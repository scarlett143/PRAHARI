"""Ed25519 identity messages and verification helpers."""
from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ED25519_PUB_BYTES = 32
BUNDLE_LABEL = b"PRAHARI-KEY-BUNDLE-V1\x00"
SESSION_OFFER_LABEL = b"PRAHARI-SESSION-OFFER-V1\x00"
PASSWORD_RESET_LABEL = b"PRAHARI-PASSWORD-RESET-V1\x00"


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


def password_reset_signing_payload(
    *, username: str, challenge: str, new_password_digest: bytes
) -> bytes:
    """Bytes proving the holder of an account's identity key asked for THIS reset.

    Its own label matters more here than anywhere else. Key publication signs the bare
    challenge string, so without domain separation a signature captured from that flow
    would be a valid password reset for the same account -- the two would be the same
    bytes. The label makes them disjoint message spaces.

    The new password is bound in as a digest, so a signature cannot be lifted and reused
    to set a *different* password, and the password itself never appears in a payload
    that might be logged.
    """
    return (
        PASSWORD_RESET_LABEL
        + username.encode("utf-8")
        + b"\x00"
        + challenge.encode("utf-8")
        + b"\x00"
        + new_password_digest
    )


def session_offer_signing_payload(
    *,
    channel_id: str,
    key_epoch: int,
    responder_id: str,
    x25519_ephemeral_public: bytes,
    ml_kem_ciphertext: bytes,
    wrapped_group_key: bytes | None = None,
) -> bytes:
    """Bytes the initiator signs over for one recipient's copy of an epoch's key material.

    The wrapped group key is inside the signature, not merely alongside it. Without that
    the relay could hand one member a wrapped key lifted from a different channel or
    epoch and they would accept it, since the KEM part would still verify. Appending
    nothing when it is absent keeps two-party signatures byte-identical to the ones
    already stored, so existing sessions keep verifying.
    """
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
        + (wrapped_group_key or b"")
    )
