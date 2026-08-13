from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from backend.app.connection_store import ConnectionStore
from backend.app.tailscale_connector import TailscaleProtocolError
from backend.app.tailscale_service import (
    TailscaleNotFoundError,
    TailscaleOperationError,
    TailscaleService,
    TailscaleValidationError,
    normalize_device_name,
    prerequisite_failures,
    validate_tailscale_hostname,
    funnel_status_matches,
)


def _status(**overrides):
    status = {
        "BackendState": "Running",
        "CurrentTailnet": {
            "MagicDNSEnabled": True,
            "MagicDNSSuffix": "example.ts.net",
        },
        "CertDomains": ["lns.example.ts.net"],
        "Self": {
            "ID": "node-123",
            "HostName": "lns",
            "DNSName": "lns.example.ts.net.",
            "CapMap": {
                "https": None,
                "funnel": None,
                "https://tailscale.com/cap/funnel-ports?ports=443,8443,10000": None,
            },
        },
    }
    status.update(overrides)
    return status


def test_device_name_defaults_normalizes_and_rejects_untrusted_values() -> None:
    assert normalize_device_name(None) == "lns"
    assert normalize_device_name(" LNS-Node ") == "lns-node"
    assert normalize_device_name("a" * 63) == "a" * 63

    for value in (
        "",
        "-lns",
        "lns-",
        "a" * 64,
        "lns.example",
        "lns node",
        "lns;id",
        "lns\n--hostname=evil",
        "https://lns",
    ):
        with pytest.raises(TailscaleValidationError, match="device name"):
            normalize_device_name(value)


def test_authoritative_hostname_must_be_canonical_ts_net_name() -> None:
    assert validate_tailscale_hostname("LNS.Example.TS.NET.") == "lns.example.ts.net"

    for value in (
        "example.ts.net",
        "lns.example.com",
        "https://lns.example.ts.net",
        "lns.example.ts.net:443",
        "lns.example.ts.net/path",
        "*.example.ts.net",
        "lns..example.ts.net",
        "lns_example.ts.net",
        "lns.example.ts.net?token=x",
    ):
        with pytest.raises(TailscaleValidationError, match="Tailscale hostname"):
            validate_tailscale_hostname(value)


def test_prerequisites_use_pinned_status_capabilities_and_port_ranges() -> None:
    assert prerequisite_failures(_status()) == []

    status = _status()
    status["CurrentTailnet"]["MagicDNSEnabled"] = False
    status["Self"]["CapMap"].pop("https")
    status["Self"]["CapMap"].pop("funnel")
    status["Self"]["CapMap"] = {
        "https://tailscale.com/cap/funnel-ports?ports=8443,10000": None
    }
    status["CertDomains"] = []

    assert prerequisite_failures(status) == [
        "magic_dns",
        "https_certificates",
        "funnel_node_attribute",
        "funnel_port_443",
    ]


def test_prerequisites_accept_port_443_inside_capability_range() -> None:
    status = _status()
    status["Self"]["CapMap"] = {
        "https": None,
        "funnel": None,
        "https://tailscale.com/cap/funnel-ports?ports=400-500": None,
    }

    assert prerequisite_failures(status) == []


def test_funnel_status_requires_correlated_hostname_root_proxy_and_funnel() -> None:
    hostname = "lns.example.ts.net"
    host_port = f"{hostname}:443"
    valid = {
        "TCP": {"443": {"HTTPS": True}},
        "Web": {host_port: {"Handlers": {"/": {"Proxy": "http://127.0.0.1:21212"}}}},
        "AllowFunnel": {host_port: True},
    }
    assert funnel_status_matches(valid, hostname)
    assert not funnel_status_matches(
        {
            **valid,
            "Web": {
                "other.example.ts.net:443": {
                    "Handlers": {"/": {"Proxy": "http://127.0.0.1:21212"}}
                }
            },
        },
        hostname,
    )
    assert not funnel_status_matches(
        {
            **valid,
            "Web": {
                host_port: {"Handlers": {"/other": {"Proxy": "http://127.0.0.1:21212"}}}
            },
        },
        hostname,
    )
    assert not funnel_status_matches(
        {**valid, "TCP": {"443": {"HTTPS": False}}}, hostname
    )
    assert not funnel_status_matches(
        {**valid, "AllowFunnel": {host_port: False}}, hostname
    )


class FakeTailscaleConnector:
    def __init__(self) -> None:
        self.records: list[dict[str, object]] = []
        self.node_status = _status()
        self.funnel_status: dict[str, object] = {
            "TCP": {"443": {"HTTPS": True}},
            "Web": {
                "lns.example.ts.net:443": {
                    "Handlers": {"/": {"Proxy": "http://127.0.0.1:21212"}}
                }
            },
            "AllowFunnel": {"lns.example.ts.net:443": True},
        }
        self.command_status: dict[str, str] | None = None
        self.calls: list[tuple[str, str | None]] = []
        self.consumed_operation_ids: list[str] = []
        self.disconnect_error = False
        self.disable_error = False
        self.cancel_error = False
        self.node_protocol_error = False
        self.node_status_missing = False
        self.command_protocol_error = False
        self.funnel_status_error = False
        self.begin_error = False
        self.login_artifact = True

    def _operation(self, command: str, state: str = "complete", error: str | None = None) -> str:
        operation_id = f"{len(self.calls):032x}"
        self.command_status = {
            "command": command,
            "state": state,
            "operation_id": operation_id,
        }
        if error is not None:
            self.command_status["error"] = error
        return operation_id

    def begin_login(self, device_name: str) -> str:
        if self.begin_error:
            raise OSError("synthetic begin failure")
        self.calls.append(("begin_login", device_name))
        return self._operation("begin_login", "started")

    def cancel_login(self) -> str:
        self.calls.append(("cancel_login", None))
        operation_id = self._operation(
            "cancel_login",
            "error" if self.cancel_error else "complete",
            "cancel_failed" if self.cancel_error else None,
        )
        if not self.cancel_error:
            self.login_artifact = False
        return operation_id

    def clear_login(self) -> str:
        self.calls.append(("clear_login", None))
        operation_id = self._operation("clear_login")
        self.login_artifact = False
        return operation_id

    def enable_funnel(self, *, external_id: str, hostname: str) -> str:
        self.calls.append(("enable", None))
        operation_id = self._operation("enable")
        self.command_status.update({"external_id": external_id, "hostname": hostname})
        return operation_id

    def disable_funnel(self, *, external_id: str, hostname: str) -> str:
        self.calls.append(("disable", None))
        operation_id = self._operation(
            "disable",
            "error" if self.disable_error else "complete",
            "funnel_disable_failed" if self.disable_error else None,
        )
        self.command_status.update({"external_id": external_id, "hostname": hostname})
        return operation_id

    def disconnect(
        self,
        *,
        external_id: str,
        hostname: str,
        operation_id: str | None = None,
        retry: bool = False,
    ) -> str:
        self.calls.append(("disconnect", None))
        generated_id = self._operation(
            "disconnect",
            "error" if self.disconnect_error else "complete",
            "funnel_disable_failed" if self.disconnect_error else None,
        )
        if operation_id is not None:
            generated_id = operation_id
            assert self.command_status is not None
            self.command_status["operation_id"] = operation_id
        assert self.command_status is not None
        self.command_status.update({"external_id": external_id, "hostname": hostname})
        if not self.disconnect_error:
            self.login_artifact = False
        return generated_id

    def read_login_records(self):
        return self.records

    def read_node_status(self):
        if self.node_protocol_error:
            raise TailscaleProtocolError("synthetic malformed status")
        if self.node_status_missing:
            return None
        return self.node_status

    def read_funnel_status(self):
        if self.funnel_status_error:
            raise OSError("synthetic Funnel status failure")
        return self.funnel_status

    def read_command_status(self, operation_id: str):
        if self.command_protocol_error:
            raise TailscaleProtocolError("synthetic malformed command acknowledgement")
        if self.command_status is None:
            return None
        if self.command_status.get("operation_id") != operation_id:
            return None
        return self.command_status

    def consume_command_result(
        self, operation_id: str, *, terminal: bool = True
    ) -> None:
        self.consumed_operation_ids.append(operation_id)
        if self.command_status and self.command_status.get("operation_id") == operation_id:
            self.command_status = None

    def has_login_artifact(self) -> bool:
        return self.login_artifact


def _auth_url() -> str:
    return "https://" + "login.tailscale.com" + "/a/" + "TEST_ONLY_AUTHORIZATION"


def _service(tmp_path: Path, connector: FakeTailscaleConnector) -> TailscaleService:
    return TailscaleService(
        connector=connector,
        store=ConnectionStore(tmp_path / "connections.db"),
        connector_enabled=True,
        poll_interval_seconds=0,
        operation_timeout_seconds=0.1,
        login_ttl_seconds=300,
    )


def test_begin_login_defaults_to_lns_and_returns_only_valid_transient_url(
    tmp_path: Path,
) -> None:
    connector = FakeTailscaleConnector()
    connector.records = [{"AuthURL": _auth_url(), "BackendState": "NeedsLogin"}]
    service = _service(tmp_path, connector)

    flow_id, response = asyncio.run(service.begin_login(None))

    assert len(flow_id) >= 32
    assert connector.calls == [("begin_login", "lns")]
    assert response == {
        "state": "needs_login",
        "device_name": "lns",
        "auth_url": _auth_url(),
        "expires_in_seconds": 300,
    }
    assert "flow" not in str(response).lower()


def test_begin_login_rejects_and_cancels_untrusted_authorization_url(
    tmp_path: Path,
) -> None:
    for auth_url in (
        "http://attacker.invalid/not-tailscale",
        "https://login.tailscale.com:invalid/a/TEST_ONLY_AUTHORIZATION",
    ):
        connector = FakeTailscaleConnector()
        connector.records = [{"AuthURL": auth_url, "BackendState": "NeedsLogin"}]
        service = _service(tmp_path, connector)

        with pytest.raises(
            TailscaleOperationError, match="authorization response"
        ) as raised:
            asyncio.run(service.begin_login("lns"))

        assert "attacker" not in str(raised.value)
        assert "login.tailscale.com:invalid" not in str(raised.value)
        assert ("cancel_login", None) in connector.calls


def test_begin_rejects_parallel_flow_for_single_sidecar(tmp_path: Path) -> None:
    connector = FakeTailscaleConnector()
    connector.records = [{"AuthURL": _auth_url(), "BackendState": "NeedsLogin"}]
    service = _service(tmp_path, connector)

    async def scenario() -> None:
        flow_id, _ = await service.begin_login("first")
        with pytest.raises(TailscaleOperationError, match="already in progress"):
            await service.begin_login("second")
        await service.cancel_login(flow_id)

    asyncio.run(scenario())
    assert connector.calls.count(("begin_login", "first")) == 1
    assert ("begin_login", "second") not in connector.calls


def test_failed_begin_does_not_leak_flow_or_expiry_task(tmp_path: Path) -> None:
    connector = FakeTailscaleConnector()
    connector.begin_error = True
    service = _service(tmp_path, connector)

    with pytest.raises(TailscaleOperationError, match="start Tailscale login"):
        asyncio.run(service.begin_login("lns"))

    assert service._flows == {}
    assert service._expiry_tasks == {}


def test_provider_invalid_hostname_disconnects_and_forgets_flow(tmp_path: Path) -> None:
    connector = FakeTailscaleConnector()
    connector.records = [{"AuthURL": _auth_url(), "BackendState": "NeedsLogin"}]
    service = _service(tmp_path, connector)
    flow_id, _ = asyncio.run(service.begin_login("lns"))
    connector.records.append({"BackendState": "Running"})
    connector.node_status["Self"]["DNSName"] = "attacker.invalid"

    with pytest.raises(TailscaleOperationError, match="hostname"):
        asyncio.run(service.poll_login(flow_id))

    assert flow_id not in service._flows
    assert ("disconnect", None) in connector.calls
    assert connector.login_artifact is False


def test_poll_login_registers_only_authoritative_hostname_after_prerequisites(
    tmp_path: Path,
) -> None:
    connector = FakeTailscaleConnector()
    connector.records = [{"AuthURL": _auth_url(), "BackendState": "NeedsLogin"}]
    service = _service(tmp_path, connector)
    flow_id, _ = asyncio.run(service.begin_login("LNS"))
    connector.records.append({"BackendState": "Running"})

    response = asyncio.run(service.poll_login(flow_id))

    assert response["state"] == "connected"
    connection = response["connection"]
    assert connection["provider"] == "tailscale"
    assert connection["external_id"] == "node-123"
    assert connection["public_metadata"] == {
        "device_name": "lns",
        "origin": "http://127.0.0.1:21212",
        "key_expiry_enabled": False,
    }
    assert connection["domains"][0]["hostname"] == "lns.example.ts.net"
    assert ("enable", None) in connector.calls
    assert ("clear_login", None) in connector.calls
    assert connector.calls.index(("enable", None)) < connector.calls.index(
        ("clear_login", None)
    )
    assert "AuthURL" not in str(connection)


def test_poll_login_reports_prerequisites_without_enabling_or_policy_changes(
    tmp_path: Path,
) -> None:
    connector = FakeTailscaleConnector()
    connector.records = [
        {"AuthURL": _auth_url(), "BackendState": "NeedsLogin"},
        {"BackendState": "Running"},
    ]
    connector.node_status["CurrentTailnet"]["MagicDNSEnabled"] = False
    connector.node_status["Self"]["CapMap"] = {}
    connector.node_status["CertDomains"] = []
    service = _service(tmp_path, connector)
    flow_id, _ = asyncio.run(service.begin_login("lns"))

    response = asyncio.run(service.poll_login(flow_id))

    assert response == {
        "state": "prerequisites_required",
        "device_name": "lns",
        "hostname": "lns.example.ts.net",
        "missing_prerequisites": [
            "magic_dns",
            "https_certificates",
            "funnel_node_attribute",
            "funnel_port_443",
        ],
    }
    assert ("enable", None) not in connector.calls
    assert ("disable", None) in connector.calls
    assert ("clear_login", None) in connector.calls
    persisted = service.store.list_connections()
    assert len(persisted) == 1
    assert persisted[0].status == "error"
    assert "magic_dns" in (persisted[0].last_error or "")

    connector.node_status = _status()
    connector.records = []
    connector.login_artifact = False
    completed = asyncio.run(service.poll_login(flow_id))
    assert completed["state"] == "connected"
    assert ("enable", None) in connector.calls


def test_post_enable_status_failure_disconnects_before_clearing_marker(
    tmp_path: Path,
) -> None:
    connector = FakeTailscaleConnector()
    connector.records = [{"AuthURL": _auth_url(), "BackendState": "NeedsLogin"}]
    service = _service(tmp_path, connector)
    flow_id, _ = asyncio.run(service.begin_login("lns"))
    connector.records.append({"BackendState": "Running"})
    connector.funnel_status_error = True

    with pytest.raises(TailscaleOperationError, match="read Tailscale Funnel status"):
        asyncio.run(service.poll_login(flow_id))

    assert ("enable", None) in connector.calls
    assert ("clear_login", None) not in connector.calls
    assert ("disconnect", None) in connector.calls
    assert service.store.list_connections() == []


def test_registry_failure_disconnects_before_clearing_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    connector = FakeTailscaleConnector()
    connector.records = [{"AuthURL": _auth_url(), "BackendState": "NeedsLogin"}]
    service = _service(tmp_path, connector)
    flow_id, _ = asyncio.run(service.begin_login("lns"))
    connector.records.append({"BackendState": "Running"})

    def fail_registration(*_args, **_kwargs):
        raise OSError("synthetic registry failure")

    monkeypatch.setattr(service, "_register_connection", fail_registration)

    with pytest.raises(TailscaleOperationError, match="persist Tailscale connection"):
        asyncio.run(service.poll_login(flow_id))

    assert ("enable", None) in connector.calls
    assert ("clear_login", None) not in connector.calls
    assert ("disconnect", None) in connector.calls
    assert service.store.list_connections() == []


def test_failed_prerequisite_funnel_reset_disconnects_fail_closed(
    tmp_path: Path,
) -> None:
    connector = FakeTailscaleConnector()
    connector.records = [
        {"AuthURL": _auth_url(), "BackendState": "NeedsLogin"},
    ]
    connector.node_status["Self"]["CapMap"] = {}
    connector.node_status["CertDomains"] = []
    service = _service(tmp_path, connector)
    flow_id, _ = asyncio.run(service.begin_login("lns"))
    connector.records.append({"BackendState": "Running"})
    connector.disable_error = True

    with pytest.raises(TailscaleOperationError, match="reset Tailscale Funnel"):
        asyncio.run(service.poll_login(flow_id))

    assert ("disable", None) in connector.calls
    assert ("disconnect", None) in connector.calls
    assert flow_id not in service._flows
    assert service.store.list_connections() == []


def test_cancel_prerequisite_flow_removes_persisted_error_connection(
    tmp_path: Path,
) -> None:
    connector = FakeTailscaleConnector()
    connector.records = [
        {"AuthURL": _auth_url(), "BackendState": "NeedsLogin"},
        {"BackendState": "Running"},
    ]
    connector.node_status["Self"]["CapMap"] = {}
    connector.node_status["CertDomains"] = []
    service = _service(tmp_path, connector)
    flow_id, _ = asyncio.run(service.begin_login("lns"))
    asyncio.run(service.poll_login(flow_id))
    assert len(service.store.list_connections()) == 1

    asyncio.run(service.cancel_login(flow_id))

    assert service.store.list_connections() == []
    assert ("disconnect", None) in connector.calls


def test_login_expires_and_cancels_without_client_polling(tmp_path: Path) -> None:
    connector = FakeTailscaleConnector()
    connector.records = [{"AuthURL": _auth_url(), "BackendState": "NeedsLogin"}]
    service = TailscaleService(
        connector=connector,
        store=ConnectionStore(tmp_path / "connections.db"),
        connector_enabled=True,
        poll_interval_seconds=0,
        operation_timeout_seconds=0.1,
        login_ttl_seconds=0.01,
    )

    async def scenario() -> None:
        flow_id, _ = await service.begin_login("lns")
        await asyncio.sleep(0.03)
        with pytest.raises(TailscaleNotFoundError):
            await service.poll_login(flow_id)

    asyncio.run(scenario())
    assert ("cancel_login", None) in connector.calls


def test_expiry_retries_malformed_command_acknowledgement(tmp_path: Path) -> None:
    connector = FakeTailscaleConnector()
    connector.records = [{"AuthURL": _auth_url(), "BackendState": "NeedsLogin"}]
    service = TailscaleService(
        connector=connector,
        store=ConnectionStore(tmp_path / "connections.db"),
        connector_enabled=True,
        poll_interval_seconds=0,
        operation_timeout_seconds=0.1,
        login_ttl_seconds=0.01,
    )

    async def scenario() -> None:
        flow_id, _ = await service.begin_login("lns")
        connector.command_protocol_error = True
        await asyncio.sleep(0.03)
        assert flow_id in service._flows
        assert not service._expiry_tasks[flow_id].done()

        connector.command_protocol_error = False
        await asyncio.sleep(0.15)
        assert flow_id not in service._flows

    asyncio.run(scenario())
    assert connector.calls.count(("cancel_login", None)) >= 2


def test_failed_pending_cancellation_retains_flow_guard(tmp_path: Path) -> None:
    connector = FakeTailscaleConnector()
    connector.records = [{"AuthURL": _auth_url(), "BackendState": "NeedsLogin"}]
    service = _service(tmp_path, connector)
    flow_id, _ = asyncio.run(service.begin_login("lns"))
    connector.cancel_error = True

    with pytest.raises(TailscaleOperationError):
        asyncio.run(service.cancel_login(flow_id))

    assert flow_id in service._flows
    assert connector.login_artifact is True
    with pytest.raises(TailscaleOperationError, match="already in progress"):
        asyncio.run(service.begin_login("second"))


def test_funnel_reconciliation_failure_disconnects_fail_closed(tmp_path: Path) -> None:
    connector = FakeTailscaleConnector()
    connector.records = [{"AuthURL": _auth_url(), "BackendState": "NeedsLogin"}]
    service = _service(tmp_path, connector)
    flow_id, _ = asyncio.run(service.begin_login("lns"))
    connector.records.append({"BackendState": "Running"})
    connector.funnel_status = {}

    with pytest.raises(TailscaleOperationError, match="reconcile"):
        asyncio.run(service.poll_login(flow_id))

    assert ("enable", None) in connector.calls
    assert ("disconnect", None) in connector.calls
    assert flow_id not in service._flows
    assert service.store.list_connections() == []


def test_failed_authenticated_cleanup_retains_flow_guard(tmp_path: Path) -> None:
    connector = FakeTailscaleConnector()
    connector.records = [{"AuthURL": _auth_url(), "BackendState": "NeedsLogin"}]
    service = _service(tmp_path, connector)
    flow_id, _ = asyncio.run(service.begin_login("lns"))
    connector.records.append({"BackendState": "Running"})
    connector.node_status["Self"]["DNSName"] = "attacker.invalid"
    connector.disconnect_error = True

    with pytest.raises(TailscaleOperationError, match="disable Funnel"):
        asyncio.run(service.poll_login(flow_id))

    assert flow_id in service._flows
    assert connector.login_artifact is True
    with pytest.raises(TailscaleOperationError, match="already in progress"):
        asyncio.run(service.begin_login("second"))


def test_malformed_recovery_status_never_queues_destructive_disconnect(
    tmp_path: Path,
) -> None:
    connector = FakeTailscaleConnector()
    connector.node_protocol_error = True
    service = _service(tmp_path, connector)

    asyncio.run(service.recover_incomplete_provisioning())

    assert ("disconnect", None) not in connector.calls
    assert connector.login_artifact is True


def test_recovery_reconciles_running_daemon_without_login_artifact(
    tmp_path: Path,
) -> None:
    connector = FakeTailscaleConnector()
    connector.login_artifact = False
    service = _service(tmp_path, connector)

    asyncio.run(service.recover_incomplete_provisioning())

    connections = service.store.list_connections()
    assert len(connections) == 1
    assert connections[0].provider == "tailscale"
    assert connections[0].domains[0].hostname == "lns.example.ts.net"
    assert ("enable", None) in connector.calls
    assert ("disconnect", None) not in connector.calls


def test_deployment_supplied_public_origin_drives_setup_and_funnel_match(
    tmp_path: Path,
) -> None:
    connector = FakeTailscaleConnector()
    origin = "http://extended-umbrella-lnswitchboard_public_1:21212"
    service = TailscaleService(
        connector=connector,
        store=ConnectionStore(tmp_path / "connections.db"),
        connector_enabled=True,
        public_origin=origin,
    )

    assert service.setup()["public_origin"] == origin
    status = connector.funnel_status
    status["Web"]["lns.example.ts.net:443"]["Handlers"]["/"]["Proxy"] = origin
    assert funnel_status_matches(status, "lns.example.ts.net", origin)
    assert not funnel_status_matches(status, "lns.example.ts.net")


def test_missing_recovery_status_never_queues_destructive_disconnect(
    tmp_path: Path,
) -> None:
    connector = FakeTailscaleConnector()
    connector.node_status_missing = True
    service = _service(tmp_path, connector)

    asyncio.run(service.recover_incomplete_provisioning())

    assert ("disconnect", None) not in connector.calls
    assert connector.login_artifact is True


def _persist_connection(service: TailscaleService):
    connection = service.store.upsert_connection(
        provider="tailscale",
        external_id="node-123",
        label="Tailscale Funnel",
        status="connected",
        public_metadata={
            "device_name": "lns",
            "origin": "http://127.0.0.1:21212",
        },
    )
    service.store.replace_domains(
        connection.id,
        [{"hostname": "lns.example.ts.net", "status": "active"}],
    )
    return service.store.get_connection(connection.id)


def test_disconnect_keeps_registry_when_runtime_cannot_disable_funnel(
    tmp_path: Path,
) -> None:
    connector = FakeTailscaleConnector()
    service = _service(tmp_path, connector)
    connection = _persist_connection(service)
    connector.disconnect_error = True

    with pytest.raises(TailscaleOperationError, match="disable Funnel"):
        asyncio.run(service.disconnect(connection.id))
    assert service.store.get_connection(connection.id) is not None
    pending = service.lifecycle.get_for_connection(connection.id)
    assert pending is not None
    assert pending.phase == "prepared"
    assert pending.last_error == "funnel_disable_failed"
    operation_id = pending.operation_id

    connector.disconnect_error = False
    assert asyncio.run(service.disconnect(connection.id)) is True
    assert operation_id in connector.consumed_operation_ids
    assert service.store.get_connection(connection.id) is None


def test_registry_cleanup_failure_is_translated_after_runtime_disconnect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    connector = FakeTailscaleConnector()
    service = _service(tmp_path, connector)
    connection = _persist_connection(service)

    def fail_delete(_connection_id: str) -> bool:
        raise OSError("synthetic registry failure")

    monkeypatch.setattr(service.store, "delete_connection", fail_delete)

    with pytest.raises(TailscaleOperationError, match="registry cleanup failed"):
        asyncio.run(
            service._disconnect_authenticated_runtime(
                external_id="node-123", hostname="lns.example.ts.net"
            )
        )
    assert ("disconnect", None) in connector.calls
    assert service.store.get_connection(connection.id) is not None


def test_explicit_disconnect_translates_registry_cleanup_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    connector = FakeTailscaleConnector()
    service = _service(tmp_path, connector)
    connection = _persist_connection(service)

    def fail_delete(_connection_id: str) -> bool:
        raise OSError("synthetic registry failure")

    monkeypatch.setattr(service.store, "delete_connection", fail_delete)

    with pytest.raises(TailscaleOperationError, match="registry cleanup failed"):
        asyncio.run(service.disconnect(connection.id))
    assert ("disconnect", None) in connector.calls


def test_recovery_finalizes_running_node_and_cancels_incomplete_login(
    tmp_path: Path,
) -> None:
    connector = FakeTailscaleConnector()
    service = _service(tmp_path, connector)

    asyncio.run(service.recover_incomplete_provisioning())
    recovered = service.store.list_connections()
    assert len(recovered) == 1
    assert recovered[0].provider == "tailscale"
    assert ("enable", None) in connector.calls
    assert ("clear_login", None) in connector.calls

    other = FakeTailscaleConnector()
    other.node_status["BackendState"] = "NeedsLogin"
    other_service = _service(tmp_path / "other", other)
    asyncio.run(other_service.recover_incomplete_provisioning())
    assert ("cancel_login", None) in other.calls


def test_refresh_missing_prerequisites_preserves_existing_connection(
    tmp_path: Path,
) -> None:
    connector = FakeTailscaleConnector()
    service = _service(tmp_path, connector)
    connection = _persist_connection(service)
    connector.login_artifact = False
    connector.node_status["Self"]["CapMap"] = {}
    connector.node_status["CertDomains"] = []

    with pytest.raises(TailscaleOperationError, match="missing required"):
        asyncio.run(service.refresh(connection.id))

    assert ("enable", None) not in connector.calls
    assert ("disable", None) not in connector.calls
    preserved = service.store.get_connection(connection.id)
    assert preserved is not None
    assert preserved.status == "connected"
    assert preserved.last_error is None
    assert preserved.domains[0].status == "active"


def test_refresh_is_observational_without_registry_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    connector = FakeTailscaleConnector()
    service = _service(tmp_path, connector)
    connection = _persist_connection(service)

    def reject_write(*_args, **_kwargs):
        raise AssertionError("refresh attempted a registry write")

    monkeypatch.setattr(service.store, "upsert_connection", reject_write)
    monkeypatch.setattr(service.store, "replace_domains", reject_write)
    monkeypatch.setattr(service.store, "delete_connection", reject_write)

    observed = asyncio.run(service.refresh(connection.id))

    assert observed == connection


def test_refresh_status_failure_preserves_runtime_identity_and_registry(
    tmp_path: Path,
) -> None:
    connector = FakeTailscaleConnector()
    service = _service(tmp_path, connector)
    connection = _persist_connection(service)
    connector.funnel_status_error = True

    with pytest.raises(TailscaleOperationError, match="read Tailscale Funnel status"):
        asyncio.run(service.refresh(connection.id))

    assert ("disconnect", None) not in connector.calls
    preserved = service.store.get_connection(connection.id)
    assert preserved is not None
    assert preserved.external_id == "node-123"
    assert preserved.domains[0].hostname == "lns.example.ts.net"


def test_refresh_rejects_runtime_identity_mismatch_without_overwriting_registry(
    tmp_path: Path,
) -> None:
    connector = FakeTailscaleConnector()
    service = _service(tmp_path, connector)
    connection = _persist_connection(service)
    connector.node_status["Self"]["ID"] = "different-node"
    connector.node_status["Self"]["DNSName"] = "other.example.ts.net."

    with pytest.raises(TailscaleOperationError, match="does not match"):
        asyncio.run(service.refresh(connection.id))

    assert ("enable", None) not in connector.calls
    assert ("disconnect", None) not in connector.calls
    preserved = service.store.get_connection(connection.id)
    assert preserved is not None
    assert preserved.external_id == "node-123"
    assert preserved.domains[0].hostname == "lns.example.ts.net"


def test_stale_disconnect_ack_does_not_delete_registry(tmp_path: Path) -> None:
    connector = FakeTailscaleConnector()
    service = _service(tmp_path, connector)
    connection = _persist_connection(service)
    original_disconnect = connector.disconnect

    def stale_disconnect(
        *,
        external_id: str,
        hostname: str,
        operation_id: str | None = None,
        retry: bool = False,
    ) -> str:
        generated_id = original_disconnect(
            external_id=external_id,
            hostname=hostname,
            operation_id=operation_id,
        )
        assert connector.command_status is not None
        connector.command_status["operation_id"] = "f" * 32
        return generated_id

    connector.disconnect = stale_disconnect

    with pytest.raises(TailscaleOperationError, match="disable Funnel"):
        asyncio.run(service.disconnect(connection.id))

    assert service.store.get_connection(connection.id) is not None


def test_recovery_completes_registry_cleanup_from_durable_disconnect_result(
    tmp_path: Path,
) -> None:
    connector = FakeTailscaleConnector()
    service = _service(tmp_path, connector)
    connection = _persist_connection(service)
    operation_id = "d" * 32
    service.lifecycle.create_disconnect(
        operation_id=operation_id,
        connection_id=connection.id,
        external_id="node-123",
        hostname="lns.example.ts.net",
    )
    service.lifecycle.update(operation_id, phase="command_published")
    connector.command_status = {
        "command": "disconnect",
        "state": "complete",
        "operation_id": operation_id,
        "external_id": "node-123",
        "hostname": "lns.example.ts.net",
    }
    connector.node_status["BackendState"] = "NeedsLogin"

    asyncio.run(service.recover_incomplete_provisioning())

    assert service.store.get_connection(connection.id) is None
    assert service.lifecycle.get(operation_id) is None
