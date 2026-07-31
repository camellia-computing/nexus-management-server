#!/usr/bin/env python3
"""Regression tests for service image release evidence."""

from __future__ import annotations

import argparse
import json
import tempfile
import unittest
from pathlib import Path

import build_image_release_evidence as evidence


class ImageReleaseEvidenceTests(unittest.TestCase):
    def frozen(self, root: Path) -> dict:
        sbom = root / "image.spdx.json"
        provenance = root / "image.intoto.jsonl"
        sbom.write_text('{"spdxVersion":"SPDX-2.3"}\n', encoding="utf-8")
        provenance.write_text('{"mediaType":"fixture"}\n', encoding="utf-8")
        return evidence.freeze(
            argparse.Namespace(
                version="1.2.3",
                commit="a" * 40,
                validation_run_id=42,
                digest=f"sha256:{'b' * 64}",
                platform=[f"linux/amd64=sha256:{'c' * 64}"],
                sbom=sbom,
                provenance=provenance,
                dependencies=None,
                generated_at="2026-07-31T00:00:00Z",
                output=root / "frozen.json",
            )
        )

    def test_finalize_with_conditional_dockerhub(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            frozen = self.frozen(root)
            frozen_path = root / "frozen.json"
            frozen_path.write_text(json.dumps(frozen), encoding="utf-8")
            digest = frozen["digest"]
            registry_path = root / "registries.json"
            registry_path.write_text(
                json.dumps(
                    [
                        {
                            "name": "dockerhub",
                            "status": "skipped",
                            "reason": "not-configured",
                        },
                        {
                            "name": "ghcr",
                            "status": "published",
                            "repository": "ghcr.io/example/management",
                            "digest": digest,
                            "aliases": ["1.2.3", f"sha-{'a' * 40}"],
                            "signature": {
                                "mechanism": "keyless-cosign",
                                "verification": "verified",
                                "identity": "workflow-identity",
                                "issuer": "https://token.actions.githubusercontent.com",
                                "evidence": ["ghcr-cosign-verification.json"],
                            },
                            "readback": "verified",
                        },
                    ]
                ),
                encoding="utf-8",
            )
            value = evidence.finalize(
                argparse.Namespace(
                    frozen=frozen_path,
                    registries=registry_path,
                    output=root / "release-evidence.json",
                )
            )
            self.assertEqual(value["images"][0]["digest"], digest)
            self.assertEqual(
                value["policy"]["exceptions"][0]["id"],
                "nexus-management-amd64-clamav",
            )

    def test_no_published_registry_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            frozen = self.frozen(root)
            frozen_path = root / "frozen.json"
            frozen_path.write_text(json.dumps(frozen), encoding="utf-8")
            registry_path = root / "registries.json"
            registry_path.write_text(
                json.dumps(
                    [
                        {
                            "name": "dockerhub",
                            "status": "skipped",
                            "reason": "not-configured",
                        },
                        {
                            "name": "ghcr",
                            "status": "skipped",
                            "reason": "not-configured",
                        },
                    ]
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "no configured registry"):
                evidence.finalize(
                    argparse.Namespace(
                        frozen=frozen_path,
                        registries=registry_path,
                        output=root / "release-evidence.json",
                    )
                )


if __name__ == "__main__":
    unittest.main()
