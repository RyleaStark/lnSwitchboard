"""Minimal LND gRPC stubs."""

from .lightning import (  # noqa: F401
    AddInvoiceResponse,
    Channel,
    GetInfoRequest,
    GetInfoResponse,
    Invoice,
    LightningStub,
    ListChannelsRequest,
    ListChannelsResponse,
    PaymentHash,
)
