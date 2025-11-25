"""Minimal LND gRPC stubs."""

from .lightning import (  # noqa: F401
    AddInvoiceResponse,
    Channel,
    GetInfoRequest,
    GetInfoResponse,
    Invoice,
    InvoiceSubscription,
    LightningStub,
    ListChannelsRequest,
    ListChannelsResponse,
    PaymentHash,
)
