"""Utility helpers for handling Nostr npub encodings."""

from __future__ import annotations

import re
from typing import Iterable, List, Sequence

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_CHARSET_MAP = {c: i for i, c in enumerate(BECH32_CHARSET)}


class NpubFormatError(ValueError):
    """Raised when an npub value cannot be parsed."""


def _bech32_polymod(values: Sequence[int]) -> int:
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            if (b >> i) & 1:
                chk ^= generator[i]
    return chk


def _bech32_hrp_expand(hrp: str) -> List[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _bech32_verify_checksum(hrp: str, data: Sequence[int]) -> bool:
    return _bech32_polymod(_bech32_hrp_expand(hrp) + list(data)) == 1


def _bech32_create_checksum(hrp: str, data: Sequence[int]) -> List[int]:
    values = _bech32_hrp_expand(hrp) + list(data)
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _convertbits(data: Iterable[int], from_bits: int, to_bits: int, *, pad: bool = True) -> List[int]:
    acc = 0
    bits = 0
    ret: List[int] = []
    maxv = (1 << to_bits) - 1
    max_acc = (1 << (from_bits + to_bits - 1)) - 1
    for value in data:
        if value < 0 or value >> from_bits:
            raise NpubFormatError("Invalid data range for convertbits")
        acc = ((acc << from_bits) | value) & max_acc
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (to_bits - bits)) & maxv)
    elif bits >= from_bits or ((acc << (to_bits - bits)) & maxv):
        raise NpubFormatError("Invalid padding in convertbits")
    return ret


def _bech32_decode(value: str) -> tuple[str, List[int]]:
    if not value or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise NpubFormatError("npub contains invalid characters")
    if value.lower() != value and value.upper() != value:
        raise NpubFormatError("npub cannot mix casing")
    value = value.lower()
    pos = value.rfind("1")
    if pos <= 0 or pos + 7 > len(value):
        raise NpubFormatError("npub is missing separator")
    hrp = value[:pos]
    data_part = value[pos + 1 :]
    data: List[int] = []
    for char in data_part:
        if char not in BECH32_CHARSET_MAP:
            raise NpubFormatError("npub contains characters outside bech32 set")
        data.append(BECH32_CHARSET_MAP[char])
    if not _bech32_verify_checksum(hrp, data):
        raise NpubFormatError("npub checksum failed")
    return hrp, data[:-6]


def _bech32_encode(hrp: str, data: Sequence[int]) -> str:
    combined = list(data) + _bech32_create_checksum(hrp, data)
    encoded = "".join(BECH32_CHARSET[d] for d in combined)
    return f"{hrp}1{encoded}"


def npub_to_hex(value: str) -> str:
    """Convert an npub or raw hex pubkey into a 64-character hex string."""
    if not value:
        raise NpubFormatError("npub is required")
    candidate = value.strip()
    hex_match = re.fullmatch(r"[0-9a-fA-F]{64}", candidate)
    if hex_match:
        return candidate.lower()
    hrp, data = _bech32_decode(candidate)
    if hrp != "npub":
        raise NpubFormatError("Only npub bech32 encodings are supported")
    raw_bytes = _convertbits(data, 5, 8, pad=False)
    if len(raw_bytes) != 32:
        raise NpubFormatError("npub must decode to 32 bytes")
    return bytes(raw_bytes).hex()


def hex_to_npub(value: str) -> str:
    """Encode a 32-byte hex public key into npub format."""
    if not value:
        raise NpubFormatError("pubkey hex is required")
    candidate = value.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", candidate):
        raise NpubFormatError("pubkey hex must be 64 hexadecimal characters")
    data = bytes.fromhex(candidate)
    five_bit = _convertbits(data, 8, 5, pad=True)
    return _bech32_encode("npub", five_bit)
