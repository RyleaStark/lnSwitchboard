from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import patch

import pytest

from backend.app.connection_store import ConnectionStore
from backend.app.zrok_service import ZrokOperationError, ZrokService, ZrokValidationError


class StubConnector:
    def __init__(self, endpoint: str) -> None:
        self.endpoint = endpoint

    def configure(self, payload: dict[str, str]) -> str:
        self.payload = payload
        self.operation_id = "test-operation"
        return self.operation_id

    def read_status(self) -> dict[str, object]:
        return {
            "state": "connected",
            "operation_id": self.operation_id,
            "frontend_endpoints": [self.endpoint],
        }


def _service(tmp_path: Path, endpoint: str) -> ZrokService:
    return ZrokService(
        connector=StubConnector(endpoint),  # type: ignore[arg-type]
        store=ConnectionStore(tmp_path / "connections.db"),
        connector_enabled=True,
        operation_timeout_seconds=1,
    )


def test_setup_reports_deployment_supplied_public_origin(tmp_path: Path) -> None:
    origin = "http://extended-umbrella-lnswitchboard_public_1:21212"
    service = ZrokService(
        connector=StubConnector("https://lns.shares.zrok.io"),  # type: ignore[arg-type]
        store=ConnectionStore(tmp_path / "connections.db"),
        connector_enabled=True,
        public_origin=origin,
    )

    assert service.setup()["public_origin"] == origin


def test_share_token_is_not_persisted_as_provider_or_domain_identity(tmp_path: Path) -> None:
    service = _service(tmp_path, "https://pay-bones.share.zrok.io")
    connection = asyncio.run(service.provision(
        mode="cloud",
        account_token="account-token",
        api_endpoint="https://api-v2.zrok.io",
        namespace="public",
        name="pay-bones",
    ))
    assert connection.external_id == "public:pay-bones"
    assert connection.domains[0].external_id == "public:pay-bones"
    assert "secret-runtime-share-token" not in str(connection)


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://good.example/path",
        "https://good.example?query=1",
        "https://good.example:8443",
        "https://user:pass@good.example",
    ],
)
def test_public_frontend_must_be_a_bare_https_origin(tmp_path: Path, endpoint: str) -> None:
    service = _service(tmp_path, endpoint)
    with pytest.raises(ZrokOperationError):
        asyncio.run(service.provision(
            mode="cloud",
            account_token="account-token",
            api_endpoint="https://api-v2.zrok.io",
            namespace="public",
            name="pay-bones",
        ))


def test_self_hosted_endpoint_rejects_any_non_public_dns_answer(tmp_path: Path) -> None:
    service = _service(tmp_path, "https://pay-bones.example")
    answers = [
        (2, 1, 6, "", ("8.8.8.8", 443)),
        (2, 1, 6, "", ("127.0.0.1", 443)),
    ]
    with patch("backend.app.zrok_service.socket.getaddrinfo", return_value=answers):
        with pytest.raises(ZrokValidationError, match="public addresses"):
            asyncio.run(service.provision(
                mode="self_hosted",
                account_token="account-token",
                api_endpoint="https://zrok.example.com",
                namespace="public",
                name="pay-bones",
            ))
