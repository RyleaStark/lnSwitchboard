from __future__ import annotations

from backend.app.lnrpc import Invoice


def test_dynamic_lnd_invoice_round_trip_with_protobuf_7() -> None:
    original = Invoice(
        memo="lnSwitchboard compatibility check",
        value=42,
        expiry=3600,
        private=True,
    )

    restored = Invoice.FromString(original.SerializeToString())

    assert restored.memo == original.memo
    assert restored.value == 42
    assert restored.expiry == 3600
    assert restored.private is True
