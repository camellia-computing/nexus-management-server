#!/usr/bin/env python3
"""Resolve the highest completed Nexus client release as an exact dependency."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any


COMMIT = re.compile(r"^[0-9a-f]{40}$")
NAME = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
SEMVER = re.compile(
    r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
)
LOGICAL_IDS = ("nexus-client", "nexus-management")
ASSET_DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")
CHECKSUM_LINE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,199})$")


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
) -> list[tuple[tuple[int, int, int], dict[str, Any]]]:
    candidates: list[tuple[tuple[int, int, int], dict[str, Any]]] = []
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
        author = release.get("author")
        if (
            release.get("draft") is not False
            or release.get("prerelease") is not False
            or release.get("immutable") is not True
            or not isinstance(commit, str)
            or not COMMIT.fullmatch(commit)
            or not isinstance(body, str)
            or not isinstance(author, dict)
            or author.get("login") != release_app_login
            or not isinstance(release.get("id"), int)
            or isinstance(release.get("id"), bool)
            or release["id"] < 1
            or not isinstance(assets, list)
        ):
            continue
        marker = f"<!-- release-complete:{commit} -->"
        if body.splitlines().count(marker) != 1:
            continue
        candidates.append(
            (
                tuple(int(match.group(index)) for index in range(1, 4)),
                release,
            )
        )
    return sorted(candidates, key=lambda item: item[0])


def product_asset_names(version: str) -> tuple[str, ...]:
    prefix = f"camellia-nexus-{version}"
    return (
        f"{prefix}-linux-x64.AppImage",
        f"{prefix}-linux-x64.deb",
        f"{prefix}-linux-x64.tar.gz",
        f"{prefix}-macos-arm64.dmg",
        f"{prefix}-macos-arm64.tar.gz",
        f"{prefix}-macos-x64.dmg",
        f"{prefix}-macos-x64.tar.gz",
        f"{prefix}-windows-x64.msi",
        f"{prefix}-windows-x64-portable.zip",
    )


def openpgp_asset_names(version: str) -> tuple[str, ...]:
    prefix = f"camellia-nexus-{version}-linux-x64"
    return (
        f"{prefix}.AppImage.asc",
        f"{prefix}.deb.asc",
        f"{prefix}.tar.gz.asc",
        "RELEASE-SIGNING-KEY.asc",
    )


def validate_public_assets(
    assets: Any, version: str
) -> tuple[dict[str, dict[str, Any]], bool]:
    if not isinstance(assets, list):
        raise ValueError("Nexus client Release assets must be an array")
    by_name: dict[str, dict[str, Any]] = {}
    for asset in assets:
        if not isinstance(asset, dict) or not isinstance(asset.get("name"), str):
            raise ValueError("Nexus client Release contains invalid asset metadata")
        name = asset["name"]
        asset_id = asset.get("id")
        digest = asset.get("digest")
        if name in by_name:
            raise ValueError(f"Nexus client Release repeats asset {name}")
        if (
            not isinstance(asset_id, int)
            or isinstance(asset_id, bool)
            or asset_id < 1
            or not isinstance(digest, str)
            or not ASSET_DIGEST.fullmatch(digest)
        ):
            raise ValueError(f"Nexus client Release asset metadata is incomplete: {name}")
        by_name[name] = asset

    products = set(product_asset_names(version))
    unsigned = products | {"SHA256SUMS"}
    signed = unsigned | set(openpgp_asset_names(version))
    actual = set(by_name)
    if actual == unsigned:
        openpgp = False
    elif actual == signed:
        openpgp = True
    else:
        missing = sorted(unsigned - actual)
        unexpected = sorted(actual - signed)
        partial_openpgp = sorted((actual & set(openpgp_asset_names(version))))
        details = []
        if missing:
            details.append(f"missing={','.join(missing)}")
        if unexpected:
            details.append(f"unexpected={','.join(unexpected)}")
        if partial_openpgp and actual != signed:
            details.append(f"partial-openpgp={','.join(partial_openpgp)}")
        raise ValueError(
            "Nexus client Release does not contain an exact public asset set"
            + (f" ({'; '.join(details)})" if details else "")
        )
    return by_name, openpgp


def parse_sha256sums(payload: bytes, version: str) -> dict[str, str]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("Nexus client SHA256SUMS is not UTF-8") from error
    if not text.endswith("\n") or "\r" in text or "\x00" in text:
        raise ValueError("Nexus client SHA256SUMS is not canonical text")
    checksums: dict[str, str] = {}
    for line in text.splitlines():
        match = CHECKSUM_LINE.fullmatch(line)
        if match is None:
            raise ValueError("Nexus client SHA256SUMS contains an invalid line")
        digest, name = match.groups()
        if name in checksums:
            raise ValueError(f"Nexus client SHA256SUMS repeats {name}")
        checksums[name] = digest
    expected = set(product_asset_names(version))
    if set(checksums) != expected:
        raise ValueError("Nexus client SHA256SUMS must cover exactly nine public packages")
    return checksums


def api_sha256(asset: dict[str, Any]) -> str:
    match = ASSET_DIGEST.fullmatch(str(asset.get("digest", "")))
    if match is None:
        raise ValueError(f"Nexus client asset has no SHA-256 digest: {asset.get('name')}")
    return match.group(1)


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
    _, release = candidates[-1]
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
    assets, openpgp = validate_public_assets(release["assets"], version)
    checksum_asset = assets["SHA256SUMS"]
    checksum_bytes = run_gh_bytes(
        "-H",
        "Accept: application/octet-stream",
        f"repos/{target_repository}/releases/assets/{checksum_asset['id']}",
    )
    checksum_sha = hashlib.sha256(checksum_bytes).hexdigest()
    if checksum_sha != api_sha256(checksum_asset):
        raise ValueError("Downloaded Nexus client SHA256SUMS differs from its API digest")
    checksums = parse_sha256sums(checksum_bytes, version)
    for name, expected in checksums.items():
        if api_sha256(assets[name]) != expected:
            raise ValueError(f"Nexus client package digest differs from SHA256SUMS: {name}")
    return {
        "target_repository": target_repository,
        "release": release,
        "assets": assets,
        "checksums": checksums,
        "checksum_sha": checksum_sha,
        "openpgp": openpgp,
        "version": version,
        "tag": tag,
        "commit": commit,
    }


def write_outputs(args: argparse.Namespace, resolved: dict[str, Any]) -> None:
    output = args.output_directory
    if not output.is_dir() or output.is_symlink():
        raise ValueError("output directory must be an existing real directory")
    metadata_path = output / "nexus-client-release.json"
    dependencies_path = output / "dependencies.json"
    packages = [
        {"name": name, "sha256": resolved["checksums"][name]}
        for name in product_asset_names(resolved["version"])
    ]
    openpgp_files = [
        {"name": name, "sha256": api_sha256(resolved["assets"][name])}
        for name in openpgp_asset_names(resolved["version"])
        if resolved["openpgp"]
    ]
    metadata = {
        "schema_version": 2,
        "repository": "nexus-client",
        "version": resolved["version"],
        "tag": resolved["tag"],
        "commit": resolved["commit"],
        "release_id": resolved["release"]["id"],
        "immutable": True,
        "complete": True,
        "public_release": {
            "asset_count": len(resolved["assets"]),
            "sha256sums": {
                "name": "SHA256SUMS",
                "sha256": resolved["checksum_sha"],
            },
            "packages": packages,
            "openpgp": {
                "enabled": resolved["openpgp"],
                "files": openpgp_files,
            },
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
