from __future__ import annotations

import pytest

from scripts.verify_image_manifests import (
    REQUIRED_PLATFORMS,
    ManifestSummary,
    ManifestVerificationError,
    parse_manifest,
    verify_published_images,
)


def test_parse_manifest_accepts_required_platforms_and_attestations() -> None:
    summary = parse_manifest(
        """{
          "digest": "sha256:abc",
          "manifests": [
            {"platform": {"os": "linux", "architecture": "amd64"}},
            {"platform": {"os": "linux", "architecture": "arm64"}},
            {"platform": {"os": "unknown", "architecture": "unknown"}}
          ]
        }""",
        reference="example/image:1.0.0",
    )

    assert summary.digest == "sha256:abc"
    assert ("linux", "amd64") in summary.platforms
    assert ("linux", "arm64") in summary.platforms


def test_parse_manifest_rejects_missing_release_platform() -> None:
    with pytest.raises(ManifestVerificationError, match="linux/arm64"):
        parse_manifest(
            '{"digest":"sha256:abc","manifests":[{"platform":{"os":"linux","architecture":"amd64"}}]}',
            reference="example/image:1.0.0",
        )


def test_verify_published_images_requires_matching_version_and_latest_digests() -> None:
    def inspect(reference: str) -> ManifestSummary:
        digest = "sha256:version" if reference.endswith(":1.0.0") else "sha256:latest"
        return ManifestSummary(digest=digest, platforms=REQUIRED_PLATFORMS)

    with pytest.raises(ManifestVerificationError, match="do not share one image digest"):
        verify_published_images(
            version="1.0.0",
            images=["ghcr.io/example/image", "example/image"],
            inspector=inspect,
        )


def test_verify_published_images_returns_shared_digest() -> None:
    def inspect(_reference: str) -> ManifestSummary:
        return ManifestSummary(
            digest="sha256:shared",
            platforms=REQUIRED_PLATFORMS,
        )

    assert (
        verify_published_images(
            version="1.0.0",
            images=["ghcr.io/example/image", "example/image"],
            inspector=inspect,
        )
        == "sha256:shared"
    )


def test_version_only_verification_does_not_require_latest() -> None:
    inspected: list[str] = []

    def inspect(reference: str) -> ManifestSummary:
        inspected.append(reference)
        return ManifestSummary(digest="sha256:shared", platforms=REQUIRED_PLATFORMS)

    verify_published_images(
        version="1.0.0",
        images=["ghcr.io/example/image", "example/image"],
        inspector=inspect,
        include_latest=False,
    )

    assert inspected == ["ghcr.io/example/image:1.0.0", "example/image:1.0.0"]


def test_verify_published_images_checks_release_labels() -> None:
    def inspect(_reference: str) -> ManifestSummary:
        return ManifestSummary(digest="sha256:shared", platforms=REQUIRED_PLATFORMS)

    def metadata(_reference: str) -> dict[str, object]:
        return {
            platform: {
                "config": {
                    "Labels": {
                        "org.opencontainers.image.version": "1.0.0",
                        "org.opencontainers.image.revision": "abc123",
                    }
                }
            }
            for platform in ("linux/amd64", "linux/arm64")
        }

    assert verify_published_images(
        version="1.0.0",
        images=["ghcr.io/example/image", "example/image"],
        inspector=inspect,
        revision="abc123",
        metadata_inspector=metadata,
    ) == "sha256:shared"

    with pytest.raises(ManifestVerificationError, match="incorrect OCI revision"):
        verify_published_images(
            version="1.0.0",
            images=["ghcr.io/example/image"],
            inspector=inspect,
            revision="different",
            metadata_inspector=metadata,
        )
