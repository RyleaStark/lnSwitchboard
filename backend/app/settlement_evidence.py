"""Small, JSON-safe evidence contract for local LND settlement snapshots."""
from typing import Any

MAX_PAID_MSAT = 9_007_199_254_740_991
MAX_SETTLE_DATE = 253_402_300_799


def _positive_integer(value: Any, maximum: int) -> bool:
    return type(value) is int and 0 < value <= maximum


def proof_from_snapshot(snapshot: dict[str, Any]) -> dict[str, Any] | None:
    """Only trusted local LND snapshots may enter this function."""
    if snapshot.get("state") != "SETTLED" or snapshot.get("settled") is not True:
        return None
    amount = snapshot.get("amt_paid_msat")
    date = snapshot.get("settle_date")
    if not _positive_integer(amount, MAX_PAID_MSAT) or not _positive_integer(date, MAX_SETTLE_DATE):
        return None
    return {
        "version": 1,
        "settlement_source": "local_lnd",
        "amount_paid_msat": amount,
        "settle_date": date,
    }
