"""Canonical deployment-environment routing for public connectors."""

from __future__ import annotations

_DEPLOYMENT_PUBLIC_HOSTS = {
    "DOCKER": "lnswitchboard-public",
    "UMBREL": "lnswitchboard-public",
    "UMBREL_DEV": "lnswitchboard-public",
}


def normalize_deployment_env(value: str | None) -> str:
    """Normalize only casing/whitespace; deployment names use underscores."""
    normalized = str(value or "DOCKER").strip().upper()
    if normalized not in _DEPLOYMENT_PUBLIC_HOSTS:
        allowed = ", ".join(_DEPLOYMENT_PUBLIC_HOSTS)
        raise ValueError(f"DEP_ENV must be one of {allowed}")
    return normalized


def public_connector_origin(value: str | None) -> str:
    """Return the deployment-owned secretless public listener origin."""
    deployment = normalize_deployment_env(value)
    return f"http://{_DEPLOYMENT_PUBLIC_HOSTS[deployment]}:21212"
