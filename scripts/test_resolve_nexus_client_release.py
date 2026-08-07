#!/usr/bin/env python3
"""Regression tests for exact Nexus client release dependency resolution."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import resolve_nexus_client_release as resolver


COMMIT = "a" * 40


def package_checksums(version: str = "1.2.3") -> dict[str, str]:
    return {
        name: hashlib.sha256(name.encode()).hexdigest()
        for name in resolver.product_asset_names(version)
    }


def checksum_payload(
    version: str = "1.2.3", checksums: dict[str, str] | None = None
) -> bytes:
    values = checksums or package_checksums(version)
    return "".join(
        f"{values[name]}  {name}\n"
        for name in resolver.product_asset_names(version)
        if name in values
    ).encode()


def public_assets(version: str = "1.2.3", *, openpgp: bool = False) -> list[dict]:
    payload = checksum_payload(version)
    assets = [
        {
            "id": index,
            "name": name,
            "digest": f"sha256:{digest}",
        }
        for index, (name, digest) in enumerate(
            package_checksums(version).items(), start=1
        )
    ]
    assets.append(
        {
            "id": 10,
            "name": "SHA256SUMS",
            "digest": f"sha256:{hashlib.sha256(payload).hexdigest()}",
        }
    )
    if openpgp:
        for index, name in enumerate(resolver.openpgp_asset_names(version), start=11):
            digest = hashlib.sha256(f"openpgp:{name}".encode()).hexdigest()
            assets.append({"id": index, "name": name, "digest": f"sha256:{digest}"})
    return assets


def managed_release(
    *,
    version: str = "1.2.3",
    commit: str = COMMIT,
    complete: bool = True,
    assets: list[dict] | None = None,
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
        "assets": public_assets(version) if assets is None else assets,
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

    def resolve_fixture(
        self,
        root: Path,
        release: dict,
        payload: bytes | None = None,
        *,
        tag_type: str = "commit",
    ) -> dict:
        releases = [[managed_release(version="1.2.2"), release]]

        def gh_json(*arguments: str):
            endpoint = arguments[-1]
            if endpoint == "repos/example/desktop":
                return {"private": False, "full_name": "example/desktop"}
            if endpoint.endswith("releases?per_page=100"):
                return releases
            if endpoint.endswith("git/ref/tags/v1.2.3"):
                return {
                    "ref": "refs/tags/v1.2.3",
                    "object": {"type": tag_type, "sha": COMMIT},
                }
            raise AssertionError(arguments)

        checksum = checksum_payload() if payload is None else payload
        with (
            patch.object(resolver, "run_gh_json", side_effect=gh_json),
            patch.object(resolver, "run_gh_bytes", return_value=checksum) as download,
        ):
            resolved = resolver.resolve(self.args(root))
        checksum_id = next(
            asset["id"] for asset in release["assets"] if asset["name"] == "SHA256SUMS"
        )
        download.assert_called_once_with(
            "-H",
            "Accept: application/octet-stream",
            f"repos/example/desktop/releases/assets/{checksum_id}",
        )
        return resolved

    def test_selects_highest_completed_release_and_writes_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            resolved = self.resolve_fixture(root, managed_release())
            resolver.write_outputs(self.args(root), resolved)

            dependency = json.loads((root / "dependencies.json").read_text())[0]
            metadata = json.loads((root / "nexus-client-release.json").read_text())
            self.assertEqual(dependency["commit"], COMMIT)
            self.assertEqual(dependency["repository"], "nexus-client")
            self.assertEqual(metadata["schema_version"], 2)
            self.assertEqual(metadata["version"], "1.2.3")
            self.assertEqual(metadata["public_release"]["asset_count"], 10)
            self.assertEqual(len(metadata["public_release"]["packages"]), 9)
            self.assertFalse(metadata["public_release"]["openpgp"]["enabled"])
            self.assertNotIn("example/desktop", json.dumps(metadata))

    def test_accepts_only_the_complete_exact_openpgp_extension(self) -> None:
        assets = public_assets(openpgp=True)
        _, enabled = resolver.validate_public_assets(assets, "1.2.3")
        self.assertTrue(enabled)
        with self.assertRaisesRegex(ValueError, "exact public asset set"):
            resolver.validate_public_assets(assets[:-1], "1.2.3")

    def test_rejects_internal_evidence_and_unrelated_asc_assets(self) -> None:
        for name in ("release-evidence.json", "ci-evidence.asc"):
            with self.subTest(name=name):
                assets = public_assets()
                assets.append(
                    {
                        "id": 99,
                        "name": name,
                        "digest": f"sha256:{'f' * 64}",
                    }
                )
                with self.assertRaisesRegex(ValueError, "exact public asset set"):
                    resolver.validate_public_assets(assets, "1.2.3")

    def test_rejects_checksum_or_asset_api_digest_disagreement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            assets = public_assets()
            assets[0]["digest"] = f"sha256:{'e' * 64}"
            with self.assertRaisesRegex(ValueError, "differs from SHA256SUMS"):
                self.resolve_fixture(root, managed_release(assets=assets))

            assets = public_assets()
            checksum = next(asset for asset in assets if asset["name"] == "SHA256SUMS")
            checksum["digest"] = f"sha256:{'d' * 64}"
            with self.assertRaisesRegex(ValueError, "differs from its API digest"):
                self.resolve_fixture(root, managed_release(assets=assets))

    def test_rejects_noncanonical_checksum_manifest(self) -> None:
        checksums = package_checksums()
        checksums.pop(next(iter(checksums)))
        with self.assertRaisesRegex(ValueError, "exactly nine"):
            resolver.parse_sha256sums(checksum_payload(checksums=checksums), "1.2.3")
        with self.assertRaisesRegex(ValueError, "canonical text"):
            resolver.parse_sha256sums(checksum_payload().rstrip(b"\n"), "1.2.3")

    def test_rejects_non_lightweight_tag(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "lightweight exact commit"):
                self.resolve_fixture(
                    Path(temporary), managed_release(), tag_type="tag"
                )

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
