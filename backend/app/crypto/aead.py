"""AES-256-GCM authenticated encryption with contextual AAD binding."""
from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AES_256_KEY_BYTES = 32
GCM_NONCE_BYTES = 12
GCM_TAG_BYTES = 16
WIRE_VERSION = 1


class DecryptionError(Exception):
    """Raised when an envelope cannot be authenticated."""


@dataclass(frozen=True)
class Envelope:
    version: int
    nonce: bytes
    ciphertext: bytes

    def to_wire(self) -> bytes:
        return struct.pack("!BB", self.version, len(self.nonce)) + self.nonce + self.ciphertext

    @classmethod
    def from_wire(cls, blob: bytes) -> "Envelope":
        if len(blob) < 2:
            raise DecryptionError("truncated envelope")
        version, nonce_len = struct.unpack("!BB", blob[:2])
        if nonce_len != GCM_NONCE_BYTES:
            raise DecryptionError("unexpected nonce length")
        body = blob[2:]
        if len(body) < nonce_len + GCM_TAG_BYTES:
            raise DecryptionError("truncated envelope")
        return cls(version, body[:nonce_len], body[nonce_len:])


def _require_aes256_key(key: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("key must be bytes")
    if len(key) != AES_256_KEY_BYTES:
        raise ValueError(f"AES-256 requires a {AES_256_KEY_BYTES}-byte key, got {len(key)}")


def build_aad(*, sender_id: str, channel_id: str, epoch: int) -> bytes:
    return b"|".join(
        [
            b"prahari-v%d" % WIRE_VERSION,
            sender_id.encode("utf-8"),
            channel_id.encode("utf-8"),
            str(epoch).encode("ascii"),
        ]
    )


def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> Envelope:
    _require_aes256_key(key)
    nonce = os.urandom(GCM_NONCE_BYTES)
    return Envelope(WIRE_VERSION, nonce, AESGCM(key).encrypt(nonce, plaintext, aad))


def decrypt(key: bytes, envelope: Envelope, aad: bytes) -> bytes:
    _require_aes256_key(key)
    if envelope.version != WIRE_VERSION:
        raise DecryptionError("unsupported wire version")
    try:
        return AESGCM(key).decrypt(envelope.nonce, envelope.ciphertext, aad)
    except InvalidTag:
        raise DecryptionError("authentication failed") from None
