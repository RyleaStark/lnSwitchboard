from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def _workflow() -> dict:
    return yaml.load(
        (ROOT / ".github" / "workflows" / "publish-rc.yml").read_text(
            encoding="utf-8"
        ),
        Loader=yaml.BaseLoader,
    )


def test_rc_publication_is_manual_only_and_serialized_by_version() -> None:
    workflow = _workflow()

    assert set(workflow["on"]) == {"workflow_dispatch"}
    assert workflow["concurrency"]["group"] == (
        "publish-rc-${{ inputs.version }}"
    )
    assert workflow["concurrency"]["cancel-in-progress"] == "false"


def test_rc_publication_requires_successful_exact_sha_ci_before_write_access() -> None:
    workflow = _workflow()
    gate = workflow["jobs"]["verify-ci"]
    publish = workflow["jobs"]["publish"]
    gate_script = "\n".join(
        step.get("run", "") for step in gate["steps"]
    )

    assert gate["permissions"] == {"actions": "read", "contents": "read"}
    assert "packages" not in gate["permissions"]
    assert "head_sha=$GITHUB_SHA" in gate_script
    assert 'conclusion == "success"' in gate_script
    assert "refs/heads/main" in gate_script
    assert publish["needs"] == "verify-ci"
    assert publish["permissions"]["packages"] == "write"


def test_rc_registry_vacancy_probe_authenticates_with_the_fetched_token() -> None:
    workflow = _workflow()
    publish_script = "\n".join(
        step.get("run", "") for step in workflow["jobs"]["publish"]["steps"]
    )

    assert re.search(
        r'-H "Authorization: Bearer \$\{?TOKEN\}?"', publish_script
    )


def test_compose_application_image_matches_version_file() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()

    assert compose["services"]["lnswitchboard"]["image"] == (
        f"ghcr.io/ryleastark/lnswitchboard:${{LNSWITCHBOARD_VERSION:-{version}}}"
    )
