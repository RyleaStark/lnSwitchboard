"""Minimal Nostr event and BIP-340 Schnorr helpers."""

from __future__ import annotations

import hashlib
import json
import secrets
from typing import Any, Dict, Iterable, Optional, Tuple


P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
Point = Optional[Tuple[int, int]]


class NostrCryptoError(ValueError):
    """Raised when Nostr event keys or signatures are invalid."""


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _tagged_hash(tag: str, data: bytes) -> bytes:
    tag_hash = _sha256(tag.encode("utf-8"))
    return _sha256(tag_hash + tag_hash + data)


def _bytes_from_hex(value: str, *, size: int, label: str) -> bytes:
    try:
        data = bytes.fromhex(value)
    except ValueError as exc:
        raise NostrCryptoError(f"{label} must be hex") from exc
    if len(data) != size:
        raise NostrCryptoError(f"{label} must be {size} bytes")
    return data


def _has_even_y(point: Tuple[int, int]) -> bool:
    return point[1] % 2 == 0


def _mod_inv(value: int, modulo: int) -> int:
    return pow(value, modulo - 2, modulo)


def _point_add(first: Point, second: Point) -> Point:
    if first is None:
        return second
    if second is None:
        return first
    x1, y1 = first
    x2, y2 = second
    if x1 == x2 and y1 != y2:
        return None
    if first == second:
        slope = (3 * x1 * x1) * _mod_inv(2 * y1 % P, P)
    else:
        slope = (y2 - y1) * _mod_inv((x2 - x1) % P, P)
    slope %= P
    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return x3, y3


def _point_mul(scalar: int, point: Point = G) -> Point:
    result: Point = None
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def _lift_x(x_value: int) -> Tuple[int, int]:
    if x_value >= P:
        raise NostrCryptoError("x coordinate is out of range")
    y_sq = (pow(x_value, 3, P) + 7) % P
    y_value = pow(y_sq, (P + 1) // 4, P)
    if pow(y_value, 2, P) != y_sq:
        raise NostrCryptoError("x coordinate is not on secp256k1")
    if y_value % 2:
        y_value = P - y_value
    return x_value, y_value


def normalize_private_key_hex(value: str) -> str:
    data = _bytes_from_hex(value.strip().lower(), size=32, label="Private key")
    secret = int.from_bytes(data, "big")
    if secret <= 0 or secret >= N:
        raise NostrCryptoError("Private key is outside the secp256k1 range")
    return data.hex()


def generate_private_key_hex() -> str:
    while True:
        candidate = secrets.token_bytes(32)
        value = int.from_bytes(candidate, "big")
        if 0 < value < N:
            return candidate.hex()


def public_key_from_private_hex(private_key_hex: str) -> str:
    private_key = int.from_bytes(
        _bytes_from_hex(normalize_private_key_hex(private_key_hex), size=32, label="Private key"),
        "big",
    )
    point = _point_mul(private_key)
    if point is None:
        raise NostrCryptoError("Unable to derive public key")
    return point[0].to_bytes(32, "big").hex()


def schnorr_sign(message_hash: bytes, private_key_hex: str, aux_rand: bytes | None = None) -> str:
    if len(message_hash) != 32:
        raise NostrCryptoError("Message hash must be 32 bytes")
    private_key = int.from_bytes(
        _bytes_from_hex(normalize_private_key_hex(private_key_hex), size=32, label="Private key"),
        "big",
    )
    public_point = _point_mul(private_key)
    if public_point is None:
        raise NostrCryptoError("Unable to derive public key")
    if not _has_even_y(public_point):
        private_key = N - private_key
    aux = aux_rand if aux_rand is not None else secrets.token_bytes(32)
    if len(aux) != 32:
        raise NostrCryptoError("Auxiliary randomness must be 32 bytes")
    secret_bytes = private_key.to_bytes(32, "big")
    t_value = bytes(a ^ b for a, b in zip(secret_bytes, _tagged_hash("BIP0340/aux", aux)))
    public_key_bytes = public_point[0].to_bytes(32, "big")
    nonce = int.from_bytes(
        _tagged_hash("BIP0340/nonce", t_value + public_key_bytes + message_hash),
        "big",
    ) % N
    if nonce == 0:
        raise NostrCryptoError("Generated invalid nonce")
    nonce_point = _point_mul(nonce)
    if nonce_point is None:
        raise NostrCryptoError("Generated invalid nonce point")
    if not _has_even_y(nonce_point):
        nonce = N - nonce
    r_bytes = nonce_point[0].to_bytes(32, "big")
    challenge = int.from_bytes(
        _tagged_hash("BIP0340/challenge", r_bytes + public_key_bytes + message_hash),
        "big",
    ) % N
    s_value = (nonce + challenge * private_key) % N
    return (r_bytes + s_value.to_bytes(32, "big")).hex()


def schnorr_verify(message_hash: bytes, public_key_hex: str, signature_hex: str) -> bool:
    try:
        public_key = _bytes_from_hex(public_key_hex.strip().lower(), size=32, label="Public key")
        signature = _bytes_from_hex(signature_hex.strip().lower(), size=64, label="Signature")
        if len(message_hash) != 32:
            return False
        p_point = _lift_x(int.from_bytes(public_key, "big"))
        r_value = int.from_bytes(signature[:32], "big")
        s_value = int.from_bytes(signature[32:], "big")
        if r_value >= P or s_value >= N:
            return False
        challenge = int.from_bytes(
            _tagged_hash("BIP0340/challenge", signature[:32] + public_key + message_hash),
            "big",
        ) % N
        r_point = _point_add(_point_mul(s_value), _point_mul(N - challenge, p_point))
        if r_point is None or not _has_even_y(r_point):
            return False
        return r_point[0] == r_value
    except NostrCryptoError:
        return False


def serialize_event_for_id(event: Dict[str, Any]) -> str:
    payload = [
        0,
        event.get("pubkey", ""),
        int(event.get("created_at", 0)),
        int(event.get("kind", 0)),
        event.get("tags") or [],
        event.get("content") or "",
    ]
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


def event_id(event: Dict[str, Any]) -> str:
    return _sha256(serialize_event_for_id(event).encode("utf-8")).hex()


def sign_event(event: Dict[str, Any], private_key_hex: str) -> Dict[str, Any]:
    signed = dict(event)
    signed["pubkey"] = public_key_from_private_hex(private_key_hex)
    signed["id"] = event_id(signed)
    signed["sig"] = schnorr_sign(bytes.fromhex(signed["id"]), private_key_hex)
    return signed


def verify_event(event: Dict[str, Any]) -> bool:
    event_id_value = event.get("id")
    pubkey = event.get("pubkey")
    signature = event.get("sig")
    if not isinstance(event_id_value, str) or not isinstance(pubkey, str) or not isinstance(signature, str):
        return False
    computed_id = event_id(event)
    if computed_id != event_id_value.lower():
        return False
    return schnorr_verify(bytes.fromhex(computed_id), pubkey, signature)


def first_tag_value(tags: Iterable[Any], name: str) -> Optional[str]:
    for tag in tags:
        if not isinstance(tag, list) or len(tag) < 2:
            continue
        if tag[0] == name and isinstance(tag[1], str):
            return tag[1]
    return None
