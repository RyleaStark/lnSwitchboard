from __future__ import annotations

import asyncio

import grpc
import pytest

from backend.app.ln_client import LNClient
from backend.app.macaroon_store import MacaroonStore
from backend.app.lnrpc import GetInfoResponse


class FakeInvoiceResponse:
    def __init__(self, payment_hash_bytes):
        self.settled = True
        self.payment_request = "lnbc1test"
        self.r_preimage = b"\x02" * 32
        self.r_hash = payment_hash_bytes


class FakeLightningStub:
    def __init__(self, payment_hash_bytes):
        self.payment_hash_bytes = payment_hash_bytes
        self.requests = []

    async def LookupInvoice(self, request, metadata=None):
        self.requests.append(request)
        return FakeInvoiceResponse(self.payment_hash_bytes)


class FakeRpcError(grpc.RpcError):
    def __init__(self, status):
        self._status = status

    def code(self):
        return self._status

    def details(self):
        return self._status.name


class ConnectivityStub:
    def __init__(self, *, get_info_response=None, lookup_error=None):
        self.get_info_response = get_info_response
        self.lookup_error = lookup_error
        self.lookup_requests = 0
        self.last_lookup_request = None

    async def GetInfo(self, request, metadata=None):
        if isinstance(self.get_info_response, Exception):
            raise self.get_info_response
        return self.get_info_response

    async def LookupInvoice(self, request, metadata=None):
        self.lookup_requests += 1
        self.last_lookup_request = request
        if self.lookup_error:
            raise self.lookup_error
        return FakeInvoiceResponse(request.r_hash)


def test_lookup_invoice_uses_binary_payment_hash(tmp_path):
    tls_path = tmp_path / "tls.cert"
    tls_path.write_text("CERT", encoding="utf-8")

    macaroon_path = tmp_path / "macaroon.hex"
    payment_hash_hex = "11" * 32
    payment_hash_bytes = bytes.fromhex(payment_hash_hex)

    async def _exercise() -> tuple[dict[str, bytes | bool | str], FakeLightningStub]:
        store = MacaroonStore(macaroon_path)
        await store.set("00")
        client = LNClient(
            host="127.0.0.1",
            port=10009,
            macaroon_store=store,
            tls_path=tls_path,
        )
        fake_stub = FakeLightningStub(payment_hash_bytes)
        client._stub = fake_stub
        result = await client.lookup_invoice(payment_hash_hex)
        return result, fake_stub

    result, fake_stub = asyncio.run(_exercise())

    assert len(fake_stub.requests) == 1
    request = fake_stub.requests[0]
    assert request.r_hash == payment_hash_bytes
    assert request.r_hash_str == ""
    assert result["settled"] is True
    assert result["payment_request"] == "lnbc1test"
    assert result["r_preimage"] == b"\x02" * 32
    assert result["r_hash"] == payment_hash_bytes


def test_lookup_invoice_rejects_non_32_byte_hash(tmp_path):
    tls_path = tmp_path / "tls.cert"
    tls_path.write_text("CERT", encoding="utf-8")

    macaroon_path = tmp_path / "macaroon.hex"

    async def _exercise() -> None:
        store = MacaroonStore(macaroon_path)
        await store.set("00")
        client = LNClient(
            host="127.0.0.1",
            port=10009,
            macaroon_store=store,
            tls_path=tls_path,
        )
        client._stub = FakeLightningStub(b"\x00" * 32)
        await client.lookup_invoice("11")

    with pytest.raises(ValueError, match="exactly 32 bytes"):
        asyncio.run(_exercise())


def test_check_connection_get_info_success(tmp_path):
    tls_path = tmp_path / "tls.cert"
    tls_path.write_text("CERT", encoding="utf-8")

    macaroon_path = tmp_path / "macaroon.hex"

    async def _exercise():
        store = MacaroonStore(macaroon_path)
        await store.set("00")
        client = LNClient(
            host="127.0.0.1",
            port=10009,
            macaroon_store=store,
            tls_path=tls_path,
        )
        response = GetInfoResponse()
        response.alias = "foo"
        client._stub = ConnectivityStub(get_info_response=response)
        return await client.check_connection(), client._stub

    result, stub = asyncio.run(_exercise())

    assert result["info_permission"] is True
    assert result["invoice_permissions"] is True
    assert result["info"] == {"alias": "foo"}
    assert stub.lookup_requests == 0


def test_check_connection_falls_back_when_info_denied(tmp_path):
    tls_path = tmp_path / "tls.cert"
    tls_path.write_text("CERT", encoding="utf-8")

    macaroon_path = tmp_path / "macaroon.hex"

    async def _exercise():
        store = MacaroonStore(macaroon_path)
        await store.set("00")
        client = LNClient(
            host="127.0.0.1",
            port=10009,
            macaroon_store=store,
            tls_path=tls_path,
        )
        stub = ConnectivityStub(
            get_info_response=FakeRpcError(grpc.StatusCode.PERMISSION_DENIED),
            lookup_error=FakeRpcError(grpc.StatusCode.NOT_FOUND),
        )
        client._stub = stub
        return await client.check_connection(), stub

    result, stub = asyncio.run(_exercise())

    assert result["info_permission"] is False
    assert result["invoice_permissions"] is True
    assert "info" not in result
    assert stub.lookup_requests == 1
    assert bytes(stub.last_lookup_request.r_hash) == b"\x00" * 32


def test_check_connection_raises_when_lookup_forbidden(tmp_path):
    tls_path = tmp_path / "tls.cert"
    tls_path.write_text("CERT", encoding="utf-8")

    macaroon_path = tmp_path / "macaroon.hex"

    async def _exercise():
        store = MacaroonStore(macaroon_path)
        await store.set("00")
        client = LNClient(
            host="127.0.0.1",
            port=10009,
            macaroon_store=store,
            tls_path=tls_path,
        )
        stub = ConnectivityStub(
            get_info_response=FakeRpcError(grpc.StatusCode.PERMISSION_DENIED),
            lookup_error=FakeRpcError(grpc.StatusCode.PERMISSION_DENIED),
        )
        client._stub = stub
        await client.check_connection()

    with pytest.raises(FakeRpcError):
        asyncio.run(_exercise())
