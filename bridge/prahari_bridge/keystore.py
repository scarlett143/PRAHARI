"""On-aircraft key storage.

The private keys generated here are the aircraft's equivalent of a browser's IndexedDB
identity: they are created locally, never transmitted, and never recoverable from the
server. Losing this file means the aircraft must be re-provisioned.
"""
from __future__ import annotations

import base64
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .crypto import pqc


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(value: str) -> bytes:
    return base64.b64decode(value)


@dataclass(frozen=True)
class Identity:
    ed25519_private: bytes
    ed25519_public: bytes
    x25519_private: bytes
    x25519_public: bytes
    ml_kem_encapsulation_key: bytes
    ml_kem_decapsulation_key: bytes

    @property
    def signing_key(self) -> Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(self.ed25519_private)

    def sign(self, message: bytes) -> bytes:
        return self.signing_key.sign(message)

    def to_json(self) -> dict:
        return {
            "version": 1,
            "ed25519_private": _b64e(self.ed25519_private),
            "ed25519_public": _b64e(self.ed25519_public),
            "x25519_private": _b64e(self.x25519_private),
            "x25519_public": _b64e(self.x25519_public),
            "ml_kem_encapsulation_key": _b64e(self.ml_kem_encapsulation_key),
            "ml_kem_decapsulation_key": _b64e(self.ml_kem_decapsulation_key),
        }

    @classmethod
    def from_json(cls, payload: dict) -> "Identity":
        return cls(
            ed25519_private=_b64d(payload["ed25519_private"]),
            ed25519_public=_b64d(payload["ed25519_public"]),
            x25519_private=_b64d(payload["x25519_private"]),
            x25519_public=_b64d(payload["x25519_public"]),
            ml_kem_encapsulation_key=_b64d(payload["ml_kem_encapsulation_key"]),
            ml_kem_decapsulation_key=_b64d(payload["ml_kem_decapsulation_key"]),
        )


def generate_identity() -> Identity:
    ed_private = Ed25519PrivateKey.generate()
    x_private = X25519PrivateKey.generate()
    kem = pqc.get_backend().keygen()
    return Identity(
        ed25519_private=ed_private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ),
        ed25519_public=ed_private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ),
        x25519_private=x_private.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        ),
        x25519_public=x_private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ),
        ml_kem_encapsulation_key=kem.encapsulation_key,
        ml_kem_decapsulation_key=kem.decapsulation_key,
    )


class Keystore:
    """A single-file keystore for one aircraft."""

    def __init__(self, path: str | os.PathLike[str]):
        self.path = Path(path)

    def exists(self) -> bool:
        return self.path.exists()

    def load(self) -> tuple[Identity, dict]:
        payload = json.loads(self.path.read_text("utf-8"))
        return Identity.from_json(payload["identity"]), payload.get("meta", {})

    def save(self, identity: Identity, meta: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        document = {"identity": identity.to_json(), "meta": meta}
        # Write via a private temp file so the keys are never briefly world-readable.
        temp = self.path.with_suffix(self.path.suffix + ".tmp")
        temp.write_text(json.dumps(document, indent=2), "utf-8")
        os.chmod(temp, stat.S_IRUSR | stat.S_IWUSR)
        temp.replace(self.path)

    def update_meta(self, **changes) -> dict:
        identity, meta = self.load()
        meta.update(changes)
        self.save(identity, meta)
        return meta
