"""LND gRPC client utilities."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Tuple

import grpc
from google.protobuf.json_format import MessageToDict

from .lnrpc import (
    GetInfoRequest,
    Invoice,
    InvoiceSubscription,
    LightningStub,
    ListChannelsRequest,
    PaymentHash,
)
from .macaroon_store import MacaroonStore


class LNClient:
    """Async helper that communicates with the local LND gRPC interface."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        macaroon_store: MacaroonStore,
        readonly_macaroon_store: MacaroonStore | None = None,
        tls_path: Path,
        tls_server_name: str | None = None,
    ) -> None:
        self._target = f"{host}:{port}"
        self._macaroon_store = macaroon_store
        self._readonly_macaroon_store = readonly_macaroon_store or macaroon_store
        self._tls_path = tls_path
        self._tls_server_name = tls_server_name
        self._stub: LightningStub | None = None
        self._channel: grpc.aio.Channel | None = None
        self._lock = asyncio.Lock()

    async def _load_stub(self) -> LightningStub:
        if self._stub is None:
            async with self._lock:
                if self._stub is None:
                    cert = self._tls_path.read_bytes()
                    credentials = grpc.ssl_channel_credentials(root_certificates=cert)
                    options: list[tuple[str, str]] | None = None
                    if self._tls_server_name:
                        options = [
                            ("grpc.ssl_target_name_override", self._tls_server_name),
                            ("grpc.default_authority", self._tls_server_name),
                        ]
                    self._channel = grpc.aio.secure_channel(self._target, credentials, options=options)
                    self._stub = LightningStub(self._channel)
        return self._stub

    async def _metadata(self, store: MacaroonStore | None = None) -> Tuple[Tuple[str, str], ...]:
        macaroon = await (store or self._macaroon_store).get()
        return (("macaroon", macaroon),)

    async def close(self) -> None:
        if self._channel is not None:
            await self._channel.close()
            self._channel = None
            self._stub = None

    async def check_connection(self) -> Dict[str, Any]:
        stub = await self._load_stub()
        metadata = await self._metadata()
        result: Dict[str, Any] = {"status": "ok"}

        try:
            response = await stub.GetInfo(GetInfoRequest(), metadata=metadata)
        except grpc.RpcError as exc:
            if not self._is_permission_denied(exc):
                raise

            fallback_request = PaymentHash()
            fallback_request.r_hash = b"\x00" * 32

            try:
                await stub.LookupInvoice(fallback_request, metadata=metadata)
            except grpc.RpcError as lookup_exc:
                if lookup_exc.code() == grpc.StatusCode.NOT_FOUND:
                    result.update(
                        {
                            "info_permission": False,
                            "invoice_permissions": True,
                        }
                    )
                    return result
                raise

            # Unlikely success path where dummy lookup returned a record.
            result.update(
                {
                    "info_permission": False,
                    "invoice_permissions": True,
                }
            )
            return result

        result.update(
            {
                "info_permission": True,
                "invoice_permissions": True,
                "info": MessageToDict(response),
            }
        )
        return result

    @staticmethod
    def _is_permission_denied(exc: grpc.RpcError) -> bool:
        if exc.code() == grpc.StatusCode.PERMISSION_DENIED:
            return True
        try:
            details = exc.details() or ""
        except Exception:  # pragma: no cover - defensive around grpc internals
            details = ""
        return "permission denied" in details.lower()

    async def create_invoice(
        self,
        *,
        amount_msat: int,
        memo: str,
        description_hash: bytes | None = None,
        private: bool | None = None,
    ) -> Dict[str, Any]:
        stub = await self._load_stub()
        metadata = await self._metadata()
        invoice_kwargs: Dict[str, Any] = {"memo": memo}
        if amount_msat % 1000 == 0:
            invoice_kwargs["value"] = amount_msat // 1000
        else:
            invoice_kwargs["value_msat"] = amount_msat
        if description_hash is not None:
            invoice_kwargs["description_hash"] = description_hash
        if private is not None:
            invoice_kwargs["private"] = private
        invoice = Invoice(**invoice_kwargs)
        response = await stub.AddInvoice(invoice, metadata=metadata)
        result: Dict[str, Any] = {"payment_request": response.payment_request}
        r_hash = getattr(response, "r_hash", None)
        if r_hash:
            result["r_hash"] = bytes(r_hash)
        return result

    async def lookup_invoice(self, payment_hash: bytes | str) -> Dict[str, Any]:
        stub = await self._load_stub()
        metadata = await self._metadata()

        payment_hash_bytes = self._normalize_payment_hash(payment_hash)

        async def _call(request: PaymentHash) -> Invoice:
            try:
                return await stub.LookupInvoice(request, metadata=metadata)
            except grpc.aio.AioRpcError as exc:  # pragma: no cover - network errors
                if exc.code() == grpc.StatusCode.NOT_FOUND:
                    raise LookupError("invoice not found") from exc
                raise

        binary_request = PaymentHash()
        binary_request.r_hash = payment_hash_bytes
        response = await _call(binary_request)
        return self._build_invoice_snapshot(response)

    async def subscribe_invoices(
        self,
        *,
        pending_only: bool | None = None,
        add_index: int | None = None,
        settle_index: int | None = None,
    ) -> AsyncIterator[Dict[str, Any]]:
        stub = await self._load_stub()
        metadata = await self._metadata()
        request = InvoiceSubscription()
        if pending_only is not None:
            request.pending_only = bool(pending_only)
        if add_index is not None:
            request.add_index = max(0, int(add_index))
        if settle_index is not None:
            request.settle_index = max(0, int(settle_index))
        call = stub.SubscribeInvoices(request, metadata=metadata)
        try:
            async for invoice in call:
                yield self._build_invoice_snapshot(invoice)
        finally:
            call.cancel()

    async def list_channels(self, public_only: bool = False) -> List[Dict[str, Any]]:
        stub = await self._load_stub()
        metadata = await self._metadata(self._readonly_macaroon_store)
        request = ListChannelsRequest()
        if public_only:
            request.public_only = True
        request.peer_alias_lookup = True
        response = await stub.ListChannels(request, metadata=metadata)
        channels: List[Dict[str, Any]] = []
        for chan in getattr(response, "channels", []):
            chan_id_raw = getattr(chan, "chan_id", 0)
            chan_id_str = ""
            if chan_id_raw:
                try:
                    chan_id_str = str(int(chan_id_raw))
                except (TypeError, ValueError):
                    chan_id_str = ""
            local_balance = int(getattr(chan, "local_balance", 0))
            remote_balance = int(getattr(chan, "remote_balance", 0))
            local_reserve = int(getattr(chan, "local_chan_reserve_sat", 0))
            remote_reserve = int(getattr(chan, "remote_chan_reserve_sat", 0))
            entry = {
                "active": bool(getattr(chan, "active", False)),
                "private": bool(getattr(chan, "private", False)),
                "capacity_sat": int(getattr(chan, "capacity", 0)),
                "local_balance_sat": local_balance,
                "remote_balance_sat": remote_balance,
                "local_chan_reserve_sat": local_reserve,
                "remote_chan_reserve_sat": remote_reserve,
                "channel_point": getattr(chan, "channel_point", ""),
                "remote_pubkey": getattr(chan, "remote_pubkey", ""),
                "peer_alias": getattr(chan, "peer_alias", "") or "",
                "channel_id": chan_id_str,
            }
            if public_only and entry["private"]:
                continue
            entry["receiving_capacity_sat"] = max(remote_balance - remote_reserve, 0)
            entry["sendable_balance_sat"] = max(local_balance - local_reserve, 0)
            channels.append(entry)
        return channels

    def _build_invoice_snapshot(self, response: Invoice) -> Dict[str, Any]:
        response_dict = MessageToDict(response, preserving_proto_field_name=True)

        def _int_or_none(value: Any) -> int | None:
            try:
                if value is None:
                    return None
                return int(value)
            except (TypeError, ValueError):
                return None

        settled = bool(getattr(response, "settled", False))
        state_name = response_dict.get("state")
        creation_date = _int_or_none(response_dict.get("creation_date"))
        expiry = _int_or_none(response_dict.get("expiry"))
        expires_at_ts: int | None = None
        if creation_date is not None and expiry is not None:
            expires_at_ts = creation_date + expiry
        expires_at_iso: str | None = None
        is_expired: bool | None = None
        if expires_at_ts is not None:
            expires_at_iso = datetime.fromtimestamp(expires_at_ts, tz=timezone.utc).isoformat()
            now_ts = int(datetime.now(tz=timezone.utc).timestamp())
            is_expired = expires_at_ts <= now_ts
        payment_request = getattr(response, "payment_request", "")
        r_preimage = getattr(response, "r_preimage", b"")
        r_hash = getattr(response, "r_hash", b"")
        result: Dict[str, Any] = {
            "settled": settled,
            "payment_request": payment_request,
            "r_preimage": bytes(r_preimage) if r_preimage else b"",
            "r_hash": bytes(r_hash) if r_hash else b"",
        }
        if state_name is not None:
            result["state"] = state_name
        if creation_date is not None:
            result["creation_date"] = creation_date
        if expiry is not None:
            result["expiry"] = expiry
        if expires_at_iso is not None:
            result["expires_at"] = expires_at_iso
        if is_expired is not None:
            result["is_expired"] = is_expired

        add_index = _int_or_none(response_dict.get("add_index"))
        if add_index is not None:
            result["add_index"] = add_index
        settle_index = _int_or_none(response_dict.get("settle_index"))
        if settle_index is not None:
            result["settle_index"] = settle_index
        settle_date = _int_or_none(response_dict.get("settle_date"))
        if settle_date is not None:
            result["settle_date"] = settle_date
        amt_paid_sat = _int_or_none(response_dict.get("amt_paid_sat"))
        if amt_paid_sat is not None:
            result["amt_paid_sat"] = amt_paid_sat
        amt_paid_msat = _int_or_none(response_dict.get("amt_paid_msat"))
        if amt_paid_msat is not None:
            result["amt_paid_msat"] = amt_paid_msat
        htlcs = response_dict.get("htlcs")
        if isinstance(htlcs, list):
            normalized_htlcs: list[dict[str, Any]] = []
            for htlc in htlcs:
                if not isinstance(htlc, dict):
                    continue
                entry: dict[str, Any] = {}
                for source, target in (
                    ("chan_id", "chan_id"),
                    ("htlc_index", "htlc_index"),
                    ("amt_msat", "amt_msat"),
                    ("accept_time", "accept_time"),
                    ("resolve_time", "resolve_time"),
                    ("state", "state"),
                ):
                    value = htlc.get(source)
                    if value is not None:
                        entry[target] = value
                if entry:
                    normalized_htlcs.append(entry)
            if normalized_htlcs:
                result["htlcs"] = normalized_htlcs
        return result

    @staticmethod
    def _normalize_payment_hash(payment_hash: bytes | str) -> bytes:
        if isinstance(payment_hash, bytes):
            payment_hash_bytes = payment_hash
        else:
            payment_hash_str = payment_hash.strip().lower()
            try:
                payment_hash_bytes = bytes.fromhex(payment_hash_str)
            except ValueError as exc:  # pragma: no cover - validation guard
                raise ValueError("Payment hash must be valid hexadecimal") from exc
        if len(payment_hash_bytes) != 32:
            raise ValueError("Payment hash must be exactly 32 bytes")
        return payment_hash_bytes
