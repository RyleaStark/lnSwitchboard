from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

import grpc
import pytest

from backend.app.ln_client import LNClient
from backend.app.macaroon_store import MacaroonStore
from backend.app.lnrpc import Channel, GetInfoResponse, Invoice, ListChannelsResponse


class FakeLightningStub:
    def __init__(self, payment_hash_bytes, invoice_response: Invoice | None = None):
        self.payment_hash_bytes = payment_hash_bytes
        self.requests = []
        self._response = invoice_response or self._default_response()

    def _default_response(self) -> Invoice:
        invoice = Invoice()
        invoice.settled = True
        invoice.payment_request = "lnbc1test"
        invoice.r_preimage = b"\x02" * 32
        invoice.r_hash = self.payment_hash_bytes
        invoice.creation_date = int(datetime.now(timezone.utc).timestamp())
        invoice.expiry = 3600
        invoice.state = 1
        return invoice

    async def LookupInvoice(self, request, metadata=None):
        self.requests.append(request)
        return self._response


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


class ListChannelsStub:
    def __init__(self, response):
        self.response = response
        self.requests = []

    async def ListChannels(self, request, metadata=None):
        self.requests.append(request)
        return self.response


def test_lookup_invoice_uses_binary_payment_hash(tmp_path):
    tls_path = tmp_path / "tls.cert"
    tls_path.write_text("CERT", encoding="utf-8")

    macaroon_path = tmp_path / "macaroon.hex"
    payment_hash_hex = "11" * 32
    payment_hash_bytes = bytes.fromhex(payment_hash_hex)

    async def _exercise() -> tuple[dict[str, bytes | bool | str], FakeLightningStub, Invoice]:
        store = MacaroonStore(macaroon_path)
        await store.set("00")
        client = LNClient(
            host="127.0.0.1",
            port=10009,
            macaroon_store=store,
            tls_path=tls_path,
        )
        invoice = Invoice()
        invoice.settled = True
        invoice.payment_request = "lnbc1test"
        invoice.r_preimage = b"\x02" * 32
        invoice.r_hash = payment_hash_bytes
        invoice.creation_date = int(datetime.now(timezone.utc).timestamp())
        invoice.expiry = 3600
        invoice.state = 1
        fake_stub = FakeLightningStub(payment_hash_bytes, invoice_response=invoice)
        client._stub = fake_stub
        result = await client.lookup_invoice(payment_hash_hex)
        return result, fake_stub, invoice

    result, fake_stub, invoice = asyncio.run(_exercise())

    assert len(fake_stub.requests) == 1
    request = fake_stub.requests[0]
    assert request.r_hash == payment_hash_bytes
    assert request.r_hash_str == ""
    assert result["settled"] is True
    assert result["payment_request"] == "lnbc1test"
    assert result["r_preimage"] == b"\x02" * 32
    assert result["r_hash"] == payment_hash_bytes
    assert result["state"] == "SETTLED"
    assert result["creation_date"] == invoice.creation_date
    assert result["expiry"] == invoice.expiry
    expected_expires = datetime.fromtimestamp(
        invoice.creation_date + invoice.expiry, tz=timezone.utc
    ).isoformat()
    assert result["expires_at"] == expected_expires
    assert result["is_expired"] is False


def test_lookup_invoice_detects_expired(tmp_path):
    tls_path = tmp_path / "tls.cert"
    tls_path.write_text("CERT", encoding="utf-8")

    macaroon_path = tmp_path / "macaroon.hex"
    payment_hash_hex = "22" * 32
    payment_hash_bytes = bytes.fromhex(payment_hash_hex)

    async def _exercise() -> dict[str, Any]:
        store = MacaroonStore(macaroon_path)
        await store.set("00")
        client = LNClient(
            host="127.0.0.1",
            port=10009,
            macaroon_store=store,
            tls_path=tls_path,
        )
        invoice = Invoice()
        invoice.settled = False
        invoice.payment_request = "lnbc1expired"
        invoice.r_preimage = b""
        invoice.r_hash = payment_hash_bytes
        invoice.creation_date = int(datetime.now(timezone.utc).timestamp()) - 7200
        invoice.expiry = 1800
        invoice.state = 2  # CANCELED
        fake_stub = FakeLightningStub(payment_hash_bytes, invoice_response=invoice)
        client._stub = fake_stub
        return await client.lookup_invoice(payment_hash_hex)

    result = asyncio.run(_exercise())

    assert result["settled"] is False
    assert result["state"] == "CANCELED"
    assert result["is_expired"] is True
    assert "expires_at" in result


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


def test_list_channels_formats_response(tmp_path):
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
        channel = Channel()
        channel.active = True
        channel.private = False
        channel.capacity = 2000
        channel.local_balance = 750
        channel.remote_balance = 1250
        channel.remote_pubkey = "deadbeef"
        channel.channel_point = "abc:0"
        response = ListChannelsResponse()
        response.channels.extend([channel])
        stub = ListChannelsStub(response)
        client._stub = stub
        return await client.list_channels(), stub

    result, stub = asyncio.run(_exercise())

    assert len(result) == 1
    entry = result[0]
    assert entry["capacity_sat"] == 2000
    assert entry["local_balance_sat"] == 750
    assert entry["remote_balance_sat"] == 1250
    assert entry["receiving_capacity_sat"] == 1250
    assert entry["remote_pubkey"] == "deadbeef"
    assert entry["channel_point"] == "abc:0"
    assert stub.requests and stub.requests[0].public_only is False


def test_list_channels_filters_private_when_public_only(tmp_path):
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
        pub_channel = Channel()
        pub_channel.private = False
        pub_channel.remote_balance = 500
        pub_channel.channel_point = "pub:0"
        pub_channel.remote_pubkey = "cafe"
        priv_channel = Channel()
        priv_channel.private = True
        priv_channel.remote_balance = 600
        priv_channel.channel_point = "priv:0"
        priv_channel.remote_pubkey = "beef"
        response = ListChannelsResponse()
        response.channels.extend([pub_channel, priv_channel])
        stub = ListChannelsStub(response)
        client._stub = stub
        return await client.list_channels(public_only=True), stub

    result, stub = asyncio.run(_exercise())

    assert len(result) == 1
    assert result[0]["channel_point"] == "pub:0"
    assert stub.requests and stub.requests[0].public_only is True
