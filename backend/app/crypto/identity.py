"""Ed25519 identity messages and verification helpers."""
from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ED25519_PUB_BYTES = 32
BUNDLE_LABEL = b"PRAHARI-KEY-BUNDLE-V1\x00"
SESSION_OFFER_LABEL = b"PRAHARI-SESSION-OFFER-V1\x00"


def verify_ed25519_signature(*, public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key) != ED25519_PUB_BYTES or len(signature) != 64:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def bundle_signing_payload(*, x25519_public_key: bytes, ml_kem_encapsulation_key: bytes) -> bytes:
    return BUNDLE_LABEL + x25519_public_key + ml_kem_encapsulation_key


def session_offer_signing_payload(
    *,
    channel_id: str,
    key_epoch: int,
    responder_id: str,
    x25519_ephemeral_public: bytes,
    ml_kem_ciphertext: bytes,
) -> bytes:
    return (
        SESSION_OFFER_LABEL
        + channel_id.encode("utf-8")
        + b"\x00"
        + str(key_epoch).encode("ascii")
        + b"\x00"
        + responder_id.encode("utf-8")
        + b"\x00"
        + x25519_ephemeral_public
        + ml_kem_ciphertext
    )
