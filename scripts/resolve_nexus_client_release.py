#!/usr/bin/env python3
"""Resolve the highest completed Nexus client release as an exact dependency."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
from pathlib import Path
from types import ModuleType
from typing import Any


COMMIT = re.compile(r"^[0-9a-f]{40}$")
NAME = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
SEMVER = re.compile(
    r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
LOGICAL_IDS = ("nexus-client", "nexus-management")


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def parse_json(value: str | bytes, label: str) -> Any:
    try:
        return json.loads(value, object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} is not valid JSON") from error


def load_validator() -> ModuleType:
    path = Path(__file__).with_name("validate-release-evidence.py")
    spec = importlib.util.spec_from_file_location("release_evidence_validator", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load release evidence validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_gh_json(*arguments: str) -> Any:
    process = subprocess.run(
        ["gh", "api", *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return parse_json(process.stdout, "GitHub API response")


def run_gh_bytes(*arguments: str) -> bytes:
    process = subprocess.run(
        ["gh", "api", *arguments],
        check=True,
        capture_output=True,
    )
    return process.stdout


def repository_names(value: str, current_repository: str) -> tuple[str, str]:
    parsed = parse_json(value, "NEXUS_REPOSITORY_MAP")
    if (
        not isinstance(parsed, dict)
        or tuple(sorted(parsed)) != LOGICAL_IDS
        or any(
            not isinstance(parsed[item], str)
            or not NAME.fullmatch(parsed[item])
            or parsed[item] in {".", ".."}
            for item in LOGICAL_IDS
        )
    ):
        raise ValueError(
            "NEXUS_REPOSITORY_MAP must be the complete reviewed logical map"
        )
    current_name = current_repository.split("/", 1)[-1]
    if parsed["nexus-management"].casefold() != current_name.casefold():
        raise ValueError("logical repository map does not match the current repository")
    if parsed["nexus-client"].casefold() == current_name.casefold():
        raise ValueError("Nexus client and management repository names must differ")
    return parsed["nexus-client"], parsed["nexus-management"]


def flatten_pages(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError("GitHub release response must be an array")
    if value and all(isinstance(page, list) for page in value):
        value = [item for page in value for item in page]
    if not all(isinstance(item, dict) for item in value):
        raise ValueError("GitHub release response contains an invalid item")
    return value


def completed_candidates(
    releases: Any, release_app_login: str
) -> list[tuple[tuple[int, int, int], dict[str, Any], dict[str, Any]]]:
    candidates: list[
        tuple[tuple[int, int, int], dict[str, Any], dict[str, Any]]
    ] = []
    stable_tags: set[str] = set()
    for release in flatten_pages(releases):
        tag = release.get("tag_name")
        if not isinstance(tag, str) or not (match := SEMVER.fullmatch(tag)):
            continue
        if tag in stable_tags:
            raise ValueError(f"multiple releases use stable tag {tag}")
        stable_tags.add(tag)
        commit = release.get("target_commitish")
        body = release.get("body")
        assets = release.get("assets")
        if (
            release.get("draft") is not False
            or release.get("prerelease") is not False
            or release.get("immutable") is not True
            or not isinstance(commit, str)
            or not COMMIT.fullmatch(commit)
            or not isinstance(body, str)
            or release.get("author", {}).get("login") != release_app_login
            or not isinstance(release.get("id"), int)
            or isinstance(release.get("id"), bool)
            or release["id"] < 1
            or not isinstance(assets, list)
        ):
            continue
        marker = f"<!-- release-complete:{commit} -->"
        if body.splitlines().count(marker) != 1:
            continue
        evidence_assets = [
            asset
            for asset in assets
            if isinstance(asset, dict)
            and asset.get("name") == "release-evidence.json"
            and isinstance(asset.get("id"), int)
            and not isinstance(asset.get("id"), bool)
            and asset["id"] > 0
        ]
        if len(evidence_assets) != 1:
            continue
        candidates.append(
            (
                tuple(int(match.group(index)) for index in range(1, 4)),
                release,
                evidence_assets[0],
            )
        )
    return sorted(candidates, key=lambda item: item[0])


def validate_client_evidence(
    value: Any, *, version: str, commit: str
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("Nexus client release evidence must be an object")
    load_validator().validate_release_evidence(value)
    if (
        value.get("repository") != "nexus-client"
        or value.get("version") != version
        or value.get("release_kind") != "formal"
        or value.get("source", {}).get("commit") != commit
        or value.get("source", {}).get("ref") != f"refs/tags/v{version}"
        or not value.get("files")
        or value.get("images") != []
    ):
        raise ValueError(
            "Nexus client evidence does not identify the selected formal release"
        )
    return value


def resolve(args: argparse.Namespace) -> dict[str, Any]:
    client_name, _ = repository_names(args.repository_map, args.current_repository)
    target_repository = f"{args.owner}/{client_name}"
    repository = run_gh_json(f"repos/{target_repository}")
    if (
        not isinstance(repository, dict)
        or repository.get("private") is not False
        or str(repository.get("full_name", "")).casefold()
        != target_repository.casefold()
    ):
        raise ValueError(
            "Nexus client must be publicly readable or resolved with a scoped read token"
        )
    releases = run_gh_json(
        "--paginate",
        "--slurp",
        f"repos/{target_repository}/releases?per_page=100",
    )
    candidates = completed_candidates(releases, args.release_app_login)
    if not candidates:
        raise ValueError("no completed immutable Nexus client release is available")
    _, release, evidence_asset = candidates[-1]
    tag = release["tag_name"]
    version = tag.removeprefix("v")
    commit = release["target_commitish"]
    tag_ref = run_gh_json(f"repos/{target_repository}/git/ref/tags/{tag}")
    if (
        not isinstance(tag_ref, dict)
        or tag_ref.get("ref") != f"refs/tags/{tag}"
        or tag_ref.get("object", {}).get("type") != "commit"
        or tag_ref.get("object", {}).get("sha") != commit
    ):
        raise ValueError("selected Nexus client tag is not a lightweight exact commit ref")
    evidence_bytes = run_gh_bytes(
        "-H",
        "Accept: application/octet-stream",
        f"repos/{target_repository}/releases/assets/{evidence_asset['id']}",
    )
    evidence = validate_client_evidence(
        parse_json(evidence_bytes, "Nexus client release evidence"),
        version=version,
        commit=commit,
    )
    return {
        "target_repository": target_repository,
        "release": release,
        "evidence": evidence,
        "evidence_bytes": evidence_bytes,
        "version": version,
        "tag": tag,
        "commit": commit,
    }


def write_outputs(args: argparse.Namespace, resolved: dict[str, Any]) -> None:
    output = args.output_directory
    if not output.is_dir() or output.is_symlink():
        raise ValueError("output directory must be an existing real directory")
    evidence_path = output / "nexus-client-release-evidence.json"
    metadata_path = output / "nexus-client-release.json"
    dependencies_path = output / "dependencies.json"
    evidence_path.write_bytes(resolved["evidence_bytes"])
    evidence_sha = hashlib.sha256(resolved["evidence_bytes"]).hexdigest()
    metadata = {
        "schema_version": 1,
        "repository": "nexus-client",
        "version": resolved["version"],
        "tag": resolved["tag"],
        "commit": resolved["commit"],
        "release_id": resolved["release"]["id"],
        "immutable": True,
        "complete": True,
        "release_evidence": {
            "name": evidence_path.name,
            "sha256": evidence_sha,
        },
    }
    dependency = {
        "repository": "nexus-client",
        "commit": resolved["commit"],
        "version": resolved["version"],
        "relation": "compatible-with",
        "evidence": metadata_path.name,
    }
    metadata_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    dependencies_path.write_text(
        json.dumps([dependency], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if args.github_output is not None:
        with args.github_output.open("a", encoding="utf-8") as stream:
            stream.write(f"commit={resolved['commit']}\n")
            stream.write(f"repository={resolved['target_repository']}\n")
            stream.write(f"tag={resolved['tag']}\n")
            stream.write(f"version={resolved['version']}\n")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--repository-map", required=True)
    result.add_argument("--owner", required=True)
    result.add_argument("--current-repository", required=True)
    result.add_argument("--release-app-login", required=True)
    result.add_argument("--output-directory", required=True, type=Path)
    result.add_argument("--github-output", type=Path)
    return result


def main() -> None:
    if not os.environ.get("GH_TOKEN"):
        raise ValueError("GH_TOKEN is required")
    args = parser().parse_args()
    write_outputs(args, resolve(args))


if __name__ == "__main__":
    main()
