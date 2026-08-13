from __future__ import annotations

import pytest

from backend.app.deployment import normalize_deployment_env, public_connector_origin


@pytest.mark.parametrize(
    ("value", "normalized", "origin"),
    [
        (None, "DOCKER", "http://lnswitchboard-public:21212"),
        ("docker", "DOCKER", "http://lnswitchboard-public:21212"),
        ("UMBREL", "UMBREL", "http://lnswitchboard_public:21212"),
        (
            "umbrel_dev",
            "UMBREL_DEV",
            "http://extended-umbrella-lnswitchboard_public:21212",
        ),
    ],
)
def test_deployment_environment_owns_public_connector_origin(
    value: str | None, normalized: str, origin: str
) -> None:
    assert normalize_deployment_env(value) == normalized
    assert public_connector_origin(value) == origin


@pytest.mark.parametrize("value", ["UMBREL-DEV", "START9", "UNKNOWN"])
def test_unsupported_deployment_environment_fails_closed(value: str) -> None:
    with pytest.raises(ValueError, match="DEP_ENV"):
        normalize_deployment_env(value)
