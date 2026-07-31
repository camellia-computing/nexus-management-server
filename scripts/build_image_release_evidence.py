#!/usr/bin/env python3
"""Freeze and finalize organization release evidence for the service image."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any


POLICY_REVISION = "2026-07-31.1"
SIGNING_REGISTRY_REVISION = "2026-07-31.1"
COMMIT = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
FROZEN_KEYS = {
    "schema_version",
    "repository",
    "image",
    "version",
    "source",
    "generated_at",
    "policy",
    "dependencies",
    "digest",
    "platforms",
    "sbom",
    "provenance",
}


def load_validator() -> ModuleType:
    path = Path(__file__).with_name("validate-release-evidence.py")
    spec = importlib.util.spec_from_file_location("release_evidence_validator", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load release evidence validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path, label: str) -> Any:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"{label} must be a regular file")
    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=unique_object,
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def evidence_file(path: Path) -> dict[str, str]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size < 1:
        raise ValueError(f"evidence file must be non-empty and regular: {path}")
    return {"name": path.name, "sha256": sha256(path)}


def validate_dependencies(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError("dependencies must be an array")
    identities: list[tuple[str, str, str]] = []
    for dependency in value:
        if not isinstance(dependency, dict) or set(dependency) != {
            "repository",
            "commit",
            "version",
            "relation",
            "evidence",
        }:
            raise ValueError("dependency has unexpected fields")
        identities.append(
            (
                str(dependency.get("repository", "")),
                str(dependency.get("relation", "")),
                str(dependency.get("commit", "")),
            )
        )
    if identities != sorted(set(identities)):
        raise ValueError("dependencies must be sorted and unique")
    return value


def validate_frozen(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != FROZEN_KEYS:
        raise ValueError("frozen image evidence has unexpected fields")
    if value["schema_version"] != 1:
        raise ValueError("frozen image evidence schema version must be 1")
    if value["repository"] != "nexus-management":
        raise ValueError("frozen evidence belongs to another repository")
    if value["image"] != "nexus-management-service":
        raise ValueError("frozen evidence belongs to another image")
    if not SEMVER.fullmatch(value.get("version", "")):
        raise ValueError("frozen version must be stable SemVer")
    source = value.get("source")
    if not isinstance(source, dict) or set(source) != {
        "commit",
        "ref",
        "validation_run_id",
    }:
        raise ValueError("frozen source has unexpected fields")
    if not COMMIT.fullmatch(source.get("commit", "")):
        raise ValueError("frozen source commit is invalid")
    if source.get("ref") != f"refs/tags/v{value['version']}":
        raise ValueError("frozen source ref does not match its version")
    if (
        not isinstance(source.get("validation_run_id"), int)
        or isinstance(source["validation_run_id"], bool)
        or source["validation_run_id"] < 1
    ):
        raise ValueError("frozen validation run ID is invalid")
    if not DIGEST.fullmatch(value.get("digest", "")):
        raise ValueError("frozen image digest is invalid")
    platforms = value.get("platforms")
    if not isinstance(platforms, list) or not platforms:
        raise ValueError("frozen platforms must be a non-empty array")
    identities: list[tuple[str, str]] = []
    for platform in platforms:
        if not isinstance(platform, dict) or set(platform) != {
            "platform",
            "architecture",
            "digest",
        }:
            raise ValueError("frozen platform has unexpected fields")
        if platform["platform"] != "linux" or platform["architecture"] not in {
            "amd64",
            "arm64",
        }:
            raise ValueError("frozen platform is unsupported")
        if not DIGEST.fullmatch(platform.get("digest", "")):
            raise ValueError("frozen platform digest is invalid")
        identities.append((platform["platform"], platform["architecture"]))
    if identities != sorted(set(identities)):
        raise ValueError("frozen platforms must be sorted and unique")
    validate_dependencies(value.get("dependencies"))
    for name in ("sbom", "provenance"):
        item = value.get(name)
        if (
            not isinstance(item, dict)
            or set(item) != {"name", "sha256"}
            or not re.fullmatch(r"^[0-9a-f]{64}$", str(item.get("sha256", "")))
            or not isinstance(item.get("name"), str)
            or not item["name"]
        ):
            raise ValueError(f"frozen {name} reference is invalid")
    return value


def freeze(args: argparse.Namespace) -> dict[str, Any]:
    if not SEMVER.fullmatch(args.version):
        raise ValueError("version must be stable SemVer")
    if not COMMIT.fullmatch(args.commit):
        raise ValueError("commit must be a full lowercase SHA")
    if not DIGEST.fullmatch(args.digest):
        raise ValueError("digest must be a canonical OCI SHA-256")
    if args.validation_run_id < 1:
        raise ValueError("validation run ID must be positive")
    platforms: list[dict[str, str]] = []
    for specification in args.platform:
        try:
            name, digest = specification.split("=", 1)
            operating_system, architecture = name.split("/", 1)
        except ValueError as error:
            raise ValueError("platform must use linux/architecture=sha256:digest") from error
        platforms.append(
            {
                "platform": operating_system,
                "architecture": architecture,
                "digest": digest,
            }
        )
    platforms.sort(key=lambda item: (item["platform"], item["architecture"]))
    dependencies = (
        load_json(args.dependencies, "dependencies")
        if args.dependencies is not None
        else []
    )
    generated_at = args.generated_at or datetime.now(timezone.utc).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")
    value = {
        "schema_version": 1,
        "repository": "nexus-management",
        "image": "nexus-management-service",
        "version": args.version,
        "source": {
            "commit": args.commit,
            "ref": f"refs/tags/v{args.version}",
            "validation_run_id": args.validation_run_id,
        },
        "generated_at": generated_at,
        "policy": {
            "repository_policy_revision": POLICY_REVISION,
            "signing_registry_revision": SIGNING_REGISTRY_REVISION,
            "exceptions": [
                {
                    "id": "nexus-management-amd64-clamav",
                    "owner": "nexus-release-team",
                    "expires_on": "2026-10-31",
                    "reason": (
                        "The supported ClamAV integration and restore-tested "
                        "production topology are currently limited to amd64."
                    ),
                    "compensating_control": (
                        "CI and release acceptance execute the final amd64 image "
                        "with the pinned ClamAV service before digest publication."
                    ),
                    "evidence": [
                        "docs/releasing.md#platform-policy",
                        "release-image-metadata.json",
                    ],
                }
            ],
        },
        "dependencies": validate_dependencies(dependencies),
        "digest": args.digest,
        "platforms": platforms,
        "sbom": evidence_file(args.sbom),
        "provenance": evidence_file(args.provenance),
    }
    return validate_frozen(value)


def finalize(args: argparse.Namespace) -> dict[str, Any]:
    frozen = validate_frozen(load_json(args.frozen, "frozen evidence"))
    registries = load_json(args.registries, "registry results")
    if (
        not isinstance(registries, list)
        or len(registries) != 2
        or [item.get("name") for item in registries if isinstance(item, dict)]
        != ["dockerhub", "ghcr"]
    ):
        raise ValueError("registry results must cover Docker Hub and GHCR in order")
    value = {
        "schema_version": 1,
        "repository": frozen["repository"],
        "version": frozen["version"],
        "source": frozen["source"],
        "release_kind": "formal",
        "generated_at": frozen["generated_at"],
        "policy": frozen["policy"],
        "dependencies": frozen["dependencies"],
        "files": [],
        "images": [
            {
                "name": frozen["image"],
                "digest": frozen["digest"],
                "platforms": frozen["platforms"],
                "sbom": frozen["sbom"],
                "provenance": frozen["provenance"],
                "registries": registries,
            }
        ],
    }
    load_validator().validate_release_evidence(value)
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    if path.exists() and (not path.is_file() or path.is_symlink()):
        raise ValueError("output must be a regular file path")
    if not path.parent.is_dir() or path.parent.is_symlink():
        raise ValueError("output parent must be a real directory")
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    commands = root.add_subparsers(dest="command", required=True)
    freeze_parser = commands.add_parser("freeze")
    freeze_parser.add_argument("--version", required=True)
    freeze_parser.add_argument("--commit", required=True)
    freeze_parser.add_argument("--validation-run-id", required=True, type=int)
    freeze_parser.add_argument("--digest", required=True)
    freeze_parser.add_argument("--platform", required=True, action="append")
    freeze_parser.add_argument("--sbom", required=True, type=Path)
    freeze_parser.add_argument("--provenance", required=True, type=Path)
    freeze_parser.add_argument("--dependencies", type=Path)
    freeze_parser.add_argument("--generated-at")
    freeze_parser.add_argument("--output", required=True, type=Path)
    freeze_parser.set_defaults(handler=freeze)
    final_parser = commands.add_parser("finalize")
    final_parser.add_argument("--frozen", required=True, type=Path)
    final_parser.add_argument("--registries", required=True, type=Path)
    final_parser.add_argument("--output", required=True, type=Path)
    final_parser.set_defaults(handler=finalize)
    return root


def main() -> None:
    args = parser().parse_args()
    write_json(args.output, args.handler(args))


if __name__ == "__main__":
    main()
