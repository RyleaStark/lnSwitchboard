"""Dynamically generated protobuf messages and stub for a subset of LND's Lightning API."""

from __future__ import annotations

from typing import Any

import grpc
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

_file_proto = descriptor_pb2.FileDescriptorProto()
_file_proto.name = "lightning.proto"
_file_proto.package = "lnrpc"
_file_proto.syntax = "proto3"

# Invoice message
_invoice = _file_proto.message_type.add()
_invoice.name = "Invoice"
_field = _invoice.field.add()
_field.name = "memo"
_field.number = 1
_field.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
_field.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
_field = _invoice.field.add()
_field.name = "r_preimage"
_field.number = 3
_field.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
_field.type = descriptor_pb2.FieldDescriptorProto.TYPE_BYTES
_field = _invoice.field.add()
_field.name = "r_hash"
_field.number = 4
_field.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
_field.type = descriptor_pb2.FieldDescriptorProto.TYPE_BYTES
_field = _invoice.field.add()
_field.name = "value"
_field.number = 2
_field.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
_field.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT64
_field = _invoice.field.add()
_field.name = "description_hash"
_field.number = 13
_field.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
_field.type = descriptor_pb2.FieldDescriptorProto.TYPE_BYTES
_field = _invoice.field.add()
_field.name = "settled"
_field.number = 8
_field.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
_field.type = descriptor_pb2.FieldDescriptorProto.TYPE_BOOL
_field = _invoice.field.add()
_field.name = "payment_request"
_field.number = 11
_field.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
_field.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
_field = _invoice.field.add()
_field.name = "value_msat"
_field.number = 23
_field.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
_field.type = descriptor_pb2.FieldDescriptorProto.TYPE_INT64
_field = _invoice.field.add()
_field.name = "private"
_field.number = 17
_field.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
_field.type = descriptor_pb2.FieldDescriptorProto.TYPE_BOOL

# AddInvoiceResponse message
_add_invoice_resp = _file_proto.message_type.add()
_add_invoice_resp.name = "AddInvoiceResponse"
_field = _add_invoice_resp.field.add()
_field.name = "r_hash"
_field.number = 1
_field.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
_field.type = descriptor_pb2.FieldDescriptorProto.TYPE_BYTES
_field = _add_invoice_resp.field.add()
_field.name = "payment_request"
_field.number = 2
_field.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
_field.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

# GetInfoRequest message
_get_info_req = _file_proto.message_type.add()
_get_info_req.name = "GetInfoRequest"

# GetInfoResponse message
_get_info_resp = _file_proto.message_type.add()
_get_info_resp.name = "GetInfoResponse"
_field = _get_info_resp.field.add()
_field.name = "alias"
_field.number = 1
_field.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
_field.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING

# PaymentHash message
_payment_hash = _file_proto.message_type.add()
_payment_hash.name = "PaymentHash"
_field = _payment_hash.field.add()
_field.name = "r_hash_str"
_field.number = 1
_field.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
_field.type = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
_field = _payment_hash.field.add()
_field.name = "r_hash"
_field.number = 2
_field.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL
_field.type = descriptor_pb2.FieldDescriptorProto.TYPE_BYTES

# Service definition (for completeness)
_service = _file_proto.service.add()
_service.name = "Lightning"
_method = _service.method.add()
_method.name = "AddInvoice"
_method.input_type = ".lnrpc.Invoice"
_method.output_type = ".lnrpc.AddInvoiceResponse"
_method = _service.method.add()
_method.name = "GetInfo"
_method.input_type = ".lnrpc.GetInfoRequest"
_method.output_type = ".lnrpc.GetInfoResponse"
_method = _service.method.add()
_method.name = "LookupInvoice"
_method.input_type = ".lnrpc.PaymentHash"
_method.output_type = ".lnrpc.Invoice"

_pool = descriptor_pool.Default()
try:
    _pool.Add(_file_proto)
except ValueError:
    # Already registered, safe to ignore.
    pass

_descriptor = _pool.FindFileByName("lightning.proto")


def _get_message_class(name: str):
    return message_factory.GetMessageClass(_descriptor.message_types_by_name[name])


Invoice = _get_message_class("Invoice")
AddInvoiceResponse = _get_message_class("AddInvoiceResponse")
GetInfoRequest = _get_message_class("GetInfoRequest")
GetInfoResponse = _get_message_class("GetInfoResponse")
PaymentHash = _get_message_class("PaymentHash")


class LightningStub:
    """Minimal async stub for the Lightning service."""

    def __init__(self, channel: grpc.aio.Channel) -> None:
        self._channel = channel
        self._add_invoice = channel.unary_unary(
            "/lnrpc.Lightning/AddInvoice",
            request_serializer=lambda msg: msg.SerializeToString(),
            response_deserializer=AddInvoiceResponse.FromString,
        )
        self._get_info = channel.unary_unary(
            "/lnrpc.Lightning/GetInfo",
            request_serializer=lambda msg: msg.SerializeToString(),
            response_deserializer=GetInfoResponse.FromString,
        )
        self._lookup_invoice = channel.unary_unary(
            "/lnrpc.Lightning/LookupInvoice",
            request_serializer=lambda msg: msg.SerializeToString(),
            response_deserializer=Invoice.FromString,
        )

    async def AddInvoice(self, request: Invoice, *, metadata: Any | None = None) -> AddInvoiceResponse:
        return await self._add_invoice(request, metadata=metadata)

    async def GetInfo(self, request: GetInfoRequest, *, metadata: Any | None = None) -> GetInfoResponse:
        return await self._get_info(request, metadata=metadata)

    async def LookupInvoice(self, request: PaymentHash, *, metadata: Any | None = None) -> Invoice:
        return await self._lookup_invoice(request, metadata=metadata)
