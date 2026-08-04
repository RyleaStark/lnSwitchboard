"""Administration API for provider-neutral external service connections."""

from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, Depends

from ..config import Settings
from ..connection_store import ConnectionStore
from ..deps import get_connection_store_dep, get_settings_dep

router = APIRouter(prefix="/api/connections", tags=["connections"])


@router.get("")
async def list_connections(
    store: ConnectionStore = Depends(get_connection_store_dep),
    settings: Settings = Depends(get_settings_dep),
) -> dict[str, object]:
    connector_available = settings.cloudflared_connector_enabled
    return {
        "providers": [
            {
                "id": "cloudflare",
                "name": "Cloudflare",
                "capability": "available" if connector_available else "unavailable",
                "reason": None if connector_available else "connector_not_installed",
            }
        ],
        "connections": [asdict(connection) for connection in store.list_connections()],
    }
