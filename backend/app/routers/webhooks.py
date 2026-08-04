"""Webhook delivery history and operator tools."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from ..deps import get_log_storage_dep, get_webhook_dispatcher_dep
from ..log_storage import RequestLogStorage
from ..webhook_dispatcher import WebhookDispatcher


router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])


class WebhookTestPayload(BaseModel):
    url: str = Field(..., description="HTTP(S) endpoint to send a sample webhook to.")
    secret: Optional[str] = Field(default=None, description="Optional HMAC secret for the test delivery.")
    payload: Optional[Dict[str, Any]] = Field(default=None, description="Optional payload override.")


@router.get("/deliveries")
async def list_deliveries(
    storage: RequestLogStorage = Depends(get_log_storage_dep),
    q: str = Query("", description="Search query for delivery records."),
    page: int = Query(1, ge=1, description="1-based page number."),
    page_size: int = Query(10, ge=1, le=100, description="Number of deliveries per page."),
) -> Dict[str, Any]:
    return await storage.list_deliveries(page=page, page_size=page_size, query=q)


@router.get("/deliveries/{delivery_id}/attempts")
async def list_delivery_attempts(
    delivery_id: int,
    storage: RequestLogStorage = Depends(get_log_storage_dep),
) -> Dict[str, Any]:
    delivery = await storage.get_delivery(delivery_id)
    if not delivery:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Delivery not found")
    return {"items": await storage.list_delivery_attempts(delivery_id)}


@router.post("/deliveries/{delivery_id}/replay")
async def replay_delivery(
    delivery_id: int,
    storage: RequestLogStorage = Depends(get_log_storage_dep),
    dispatcher: WebhookDispatcher = Depends(get_webhook_dispatcher_dep),
) -> Dict[str, Any]:
    delivery = await storage.get_delivery(delivery_id)
    if not delivery:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Delivery not found")
    if delivery.get("kind") != "http.webhook":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Only HTTP webhook deliveries can be replayed")
    delivered = await dispatcher.replay_delivery(delivery)
    return {"status": "delivered" if delivered else "failed"}


@router.post("/test")
async def test_webhook(
    payload: WebhookTestPayload,
    dispatcher: WebhookDispatcher = Depends(get_webhook_dispatcher_dep),
) -> Dict[str, Any]:
    if not payload.url.startswith(("http://", "https://")):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Webhook URL must start with http:// or https://")
    delivered = await dispatcher.dispatch_test(
        url=payload.url,
        secret=payload.secret,
        payload=payload.payload,
    )
    return {"status": "delivered" if delivered else "failed"}
