#!/usr/bin/env python3
"""Regression tests for exact Nexus client release dependency resolution."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import resolve_nexus_client_release as resolver


COMMIT = "a" * 40


def release_evidence(version: str = "1.2.3", commit: str = COMMIT) -> dict:
    return {
        "schema_version": 1,
        "repository": "nexus-client",
        "version": version,
        "source": {
            "commit": commit,
            "ref": f"refs/tags/v{version}",
            "validation_run_id": 42,
        },
        "release_kind": "formal",
        "generated_at": "2026-07-31T00:00:00Z",
        "policy": {
            "repository_policy_revision": "2026-07-31.1",
            "signing_registry_revision": "2026-07-31.1",
            "exceptions": [],
        },
        "dependencies": [],
        "files": [
            {
                "name": "client.tar.gz",
                "sha256": "b" * 64,
                "size_bytes": 1,
                "platform": "linux",
                "architecture": "x64",
                "signing": {
                    "category": "platform-key",
                    "verification": "verified",
                    "verifier": "openpgp",
                    "timestamp": "not-applicable",
                    "distribution": "installable",
                    "evidence": ["client.tar.gz.asc"],
                },
                "sbom": {"name": "SBOM.spdx.json", "sha256": "c" * 64},
                "provenance": {
                    "name": "PROVENANCE.intoto.jsonl",
                    "sha256": "d" * 64,
                },
            }
        ],
        "images": [],
    }


def managed_release(
    *,
    version: str = "1.2.3",
    commit: str = COMMIT,
    complete: bool = True,
) -> dict:
    body = f"<!-- release-complete:{commit} -->" if complete else ""
    return {
        "id": 17,
        "tag_name": f"v{version}",
        "target_commitish": commit,
        "body": body,
        "draft": False,
        "prerelease": False,
        "immutable": True,
        "author": {"login": "release-app[bot]"},
        "assets": [{"id": 23, "name": "release-evidence.json"}],
    }


class ResolveNexusClientReleaseTests(unittest.TestCase):
    def args(self, root: Path):
        return resolver.parser().parse_args(
            [
                "--repository-map",
                '{"nexus-client":"desktop","nexus-management":"service"}',
                "--owner",
                "example",
                "--current-repository",
                "example/service",
                "--release-app-login",
                "release-app[bot]",
                "--output-directory",
                str(root),
            ]
        )

    def test_selects_highest_completed_release_and_writes_logical_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            releases = [[managed_release(version="1.2.2"), managed_release()]]

            def gh_json(*arguments: str):
                endpoint = arguments[-1]
                if endpoint == "repos/example/desktop":
                    return {"private": False, "full_name": "example/desktop"}
                if endpoint.endswith("releases?per_page=100"):
                    return releases
                if endpoint.endswith("git/ref/tags/v1.2.3"):
                    return {
                        "ref": "refs/tags/v1.2.3",
                        "object": {"type": "commit", "sha": COMMIT},
                    }
                raise AssertionError(arguments)

            payload = (json.dumps(release_evidence()) + "\n").encode()
            with (
                patch.object(resolver, "run_gh_json", side_effect=gh_json),
                patch.object(resolver, "run_gh_bytes", return_value=payload),
            ):
                resolved = resolver.resolve(self.args(root))
                resolver.write_outputs(self.args(root), resolved)

            dependency = json.loads((root / "dependencies.json").read_text())[0]
            metadata = json.loads((root / "nexus-client-release.json").read_text())
            self.assertEqual(dependency["commit"], COMMIT)
            self.assertEqual(dependency["repository"], "nexus-client")
            self.assertEqual(metadata["version"], "1.2.3")
            self.assertNotIn("example/desktop", json.dumps(metadata))

    def test_rejects_incomplete_release(self) -> None:
        releases = [[managed_release(complete=False)]]
        self.assertEqual(
            resolver.completed_candidates(releases, "release-app[bot]"),
            [],
        )

    def test_rejects_repository_map_identity_mismatch(self) -> None:
        with self.assertRaisesRegex(ValueError, "current repository"):
            resolver.repository_names(
                '{"nexus-client":"desktop","nexus-management":"other"}',
                "example/service",
            )


if __name__ == "__main__":
    unittest.main()
