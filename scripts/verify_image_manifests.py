#!/usr/bin/env python3
"""Verify published container tags resolve to one multi-architecture image."""

from __future__ import annotations

import argparse
import json
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

REQUIRED_PLATFORMS = frozenset({("linux", "amd64"), ("linux", "arm64")})


class ManifestVerificationError(RuntimeError):
    """Raised when a published image does not match the release contract."""


@dataclass(frozen=True)
class ManifestSummary:
    digest: str
    platforms: frozenset[tuple[str, str]]


def parse_manifest(payload: str, *, reference: str) -> ManifestSummary:
    try:
        manifest: dict[str, Any] = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ManifestVerificationError(f"{reference}: invalid manifest JSON: {exc}") from exc

    digest = manifest.get("digest")
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise ManifestVerificationError(f"{reference}: missing sha256 index digest")

    platforms = frozenset(
        (platform["os"], platform["architecture"])
        for item in manifest.get("manifests", [])
        if isinstance(item, dict)
        and isinstance((platform := item.get("platform")), dict)
        and isinstance(platform.get("os"), str)
        and isinstance(platform.get("architecture"), str)
    )
    missing = REQUIRED_PLATFORMS - platforms
    if missing:
        formatted = ", ".join(f"{os_name}/{architecture}" for os_name, architecture in sorted(missing))
        raise ManifestVerificationError(f"{reference}: missing required platform(s): {formatted}")

    return ManifestSummary(digest=digest, platforms=platforms)


def inspect_manifest(reference: str) -> ManifestSummary:
    command = [
        "docker",
        "buildx",
        "imagetools",
        "inspect",
        reference,
        "--format",
        "{{json .Manifest}}",
    ]
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or exc.stdout.strip() or str(exc)
        raise ManifestVerificationError(f"{reference}: manifest inspection failed: {detail}") from exc
    return parse_manifest(result.stdout, reference=reference)


def inspect_image_metadata(reference: str) -> dict[str, Any]:
    command = [
        "docker",
        "buildx",
        "imagetools",
        "inspect",
        reference,
        "--format",
        "{{json .Image}}",
    ]
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.strip() or exc.stdout.strip() or str(exc)
        raise ManifestVerificationError(f"{reference}: image metadata inspection failed: {detail}") from exc
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ManifestVerificationError(f"{reference}: invalid image metadata JSON") from exc
    if not isinstance(payload, dict):
        raise ManifestVerificationError(f"{reference}: invalid image metadata")
    return payload


def verify_published_images(
    *,
    version: str,
    images: Sequence[str],
    inspector: Callable[[str], ManifestSummary] = inspect_manifest,
    revision: str | None = None,
    metadata_inspector: Callable[[str], dict[str, Any]] = inspect_image_metadata,
    include_latest: bool = True,
) -> str:
    tags = (version, "latest") if include_latest else (version,)
    references = [f"{image}:{tag}" for image in images for tag in tags]
    summaries = {reference: inspector(reference) for reference in references}
    digests = {summary.digest for summary in summaries.values()}
    if len(digests) != 1:
        details = ", ".join(f"{reference}={summary.digest}" for reference, summary in summaries.items())
        raise ManifestVerificationError(f"published tags do not share one image digest: {details}")

    if revision is not None:
        for image in images:
            reference = f"{image}:{version}"
            metadata = metadata_inspector(reference)
            for os_name, architecture in REQUIRED_PLATFORMS:
                platform = f"{os_name}/{architecture}"
                image_data = metadata.get(platform)
                config = image_data.get("config") if isinstance(image_data, dict) else None
                labels = config.get("Labels") if isinstance(config, dict) else None
                if not isinstance(labels, dict):
                    raise ManifestVerificationError(f"{reference}: missing OCI labels for {platform}")
                if labels.get("org.opencontainers.image.version") != version:
                    raise ManifestVerificationError(f"{reference}: incorrect OCI version label for {platform}")
                if labels.get("org.opencontainers.image.revision") != revision:
                    raise ManifestVerificationError(f"{reference}: incorrect OCI revision label for {platform}")
    return digests.pop()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("version", help="Published semantic version tag")
    parser.add_argument("images", nargs="+", help="Image repositories to verify")
    parser.add_argument("--revision", help="Expected OCI source revision")
    parser.add_argument("--version-only", action="store_true", help="Verify the immutable version tag before latest is promoted")
    args = parser.parse_args()

    try:
        digest = verify_published_images(
            version=args.version,
            images=args.images,
            revision=args.revision,
            include_latest=not args.version_only,
        )
    except ManifestVerificationError as exc:
        parser.error(str(exc))
    print(f"Verified {len(args.images)} registries at {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
