"""LND gRPC client utilities."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Dict, Tuple

import grpc
from google.protobuf.json_format import MessageToDict

from .lnrpc import GetInfoRequest, Invoice, LightningStub, PaymentHash
from .macaroon_store import MacaroonStore


class LNClient:
    """Async helper that communicates with the local LND gRPC interface."""

    def __init__(
        self, *, host: str, port: int, macaroon_store: MacaroonStore, tls_path: Path
    ) -> None:
        self._target = f"{host}:{port}"
        self._macaroon_store = macaroon_store
        self._tls_path = tls_path
        self._stub: LightningStub | None = None
        self._channel: grpc.aio.Channel | None = None
        self._lock = asyncio.Lock()

    async def _load_stub(self) -> LightningStub:
        if self._stub is None:
            async with self._lock:
                if self._stub is None:
                    cert = self._tls_path.read_bytes()
                    credentials = grpc.ssl_channel_credentials(root_certificates=cert)
                    self._channel = grpc.aio.secure_channel(self._target, credentials)
                    self._stub = LightningStub(self._channel)
        return self._stub

    async def _metadata(self) -> Tuple[Tuple[str, str], ...]:
        macaroon = await self._macaroon_store.get()
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
            if exc.code() != grpc.StatusCode.PERMISSION_DENIED:
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
        sats, _remainder = divmod(amount_msat, 1000)
        invoice_kwargs: Dict[str, Any] = {"memo": memo, "value_msat": amount_msat}
        if sats > 0:
            invoice_kwargs["value"] = sats
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

        settled = bool(getattr(response, "settled", False))
        payment_request = getattr(response, "payment_request", "")
        r_preimage = getattr(response, "r_preimage", b"")
        r_hash = getattr(response, "r_hash", b"")
        result: Dict[str, Any] = {
            "settled": settled,
            "payment_request": payment_request,
            "r_preimage": bytes(r_preimage) if r_preimage else b"",
            "r_hash": bytes(r_hash) if r_hash else b"",
        }
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
