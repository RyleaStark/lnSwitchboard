from __future__ import annotations

import asyncio
import json
from typing import Any, cast

import websockets
import pytest

from backend.app.nostr_signer_store import NostrSignerStore
from backend.app.nostr_zaps import NostrZapPublisher
from ..app.outbound_security import UnsafeOutboundTarget


def test_zap_publisher_uses_websockets_17_client_api() -> None:
    received: list[Any] = []

    async def exercise() -> None:
        async def relay(websocket: Any) -> None:
            payload = json.loads(await websocket.recv())
            received.append(payload)
            await websocket.send(json.dumps(["OK", payload[1]["id"], True, "accepted"]))

        async with websockets.serve(relay, "127.0.0.1", 0) as server:
            socket = next(iter(server.sockets))
            port = socket.getsockname()[1]
            publisher = NostrZapPublisher(
                signer_store=cast(NostrSignerStore, object()),
                allow_private_relays=True,
            )
            await publisher._send(f"ws://127.0.0.1:{port}", {"id": "receipt-id"})

    asyncio.run(exercise())
    assert received == [["EVENT", {"id": "receipt-id"}]]


@pytest.mark.parametrize(
    ("reply", "message"),
    [
        ('["NOTICE","blocked"]', "did not acknowledge"),
        ('["OK","different-event",true,""]', "different event"),
        ('["OK","receipt-id",false,"blocked"]', "blocked"),
        ("not-json", "invalid acknowledgement"),
    ],
)
def test_publish_rejects_invalid_or_negative_relay_responses(reply: str, message: str) -> None:
    async def run() -> None:
        async def relay(websocket: Any) -> None:
            await websocket.recv()
            await websocket.send(reply)

        async with websockets.serve(relay, "127.0.0.1", 0) as server:
            socket = next(iter(server.sockets))
            port = socket.getsockname()[1]
            publisher = NostrZapPublisher(
                signer_store=cast(NostrSignerStore, object()),
                allow_private_relays=True,
            )
            with pytest.raises(RuntimeError, match=message):
                await publisher._send(
                    f"ws://127.0.0.1:{port}",
                    {"id": "receipt-id"},
                )

    asyncio.run(run())


def test_private_relay_targets_are_blocked_by_default() -> None:
    publisher = NostrZapPublisher(
        signer_store=cast(NostrSignerStore, object()),
    )

    with pytest.raises(UnsafeOutboundTarget, match="non-public network"):
        asyncio.run(publisher._send("ws://127.0.0.1:9", {"id": "receipt-id"}))
