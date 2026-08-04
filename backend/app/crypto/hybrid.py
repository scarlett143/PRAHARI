"""Hybrid X25519 + ML-KEM-768 agreement -> HKDF-SHA256 -> AES-256 key."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import pqc
from .aead import AES_256_KEY_BYTES

X25519_PUB_BYTES = 32
KDF_LABEL = b"prahari/hybrid-kem/v1/aes256gcm"


@dataclass(frozen=True)
class HybridPublicBundle:
    x25519_public: bytes
    ml_kem_encapsulation_key: bytes

    def to_transcript(self) -> bytes:
        return self.x25519_public + self.ml_kem_encapsulation_key


@dataclass(frozen=True)
class HybridPrivateBundle:
    x25519_private: bytes
    ml_kem_decapsulation_key: bytes


@dataclass(frozen=True)
class HybridCiphertext:
    x25519_ephemeral_public: bytes
    ml_kem_ciphertext: bytes

    def to_transcript(self) -> bytes:
        return self.x25519_ephemeral_public + self.ml_kem_ciphertext


def generate_bundle() -> Tuple[HybridPublicBundle, HybridPrivateBundle]:
    x_priv = X25519PrivateKey.generate()
    x_pub = x_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    kem = pqc.get_backend().keygen()
    return (
        HybridPublicBundle(x_pub, kem.encapsulation_key),
        HybridPrivateBundle(
            x_priv.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            ),
            kem.decapsulation_key,
        ),
    )


def transcript_digest(responder: HybridPublicBundle, ciphertext: HybridCiphertext) -> bytes:
    """Bind the full handshake transcript into 32 bytes.

    The raw transcript is 2336 bytes because ML-KEM-768 keys and ciphertexts are large.
    OpenSSL-backed HKDF implementations (Node, Deno, Bun, and any embedded/FPGA-side
    reimplementation) reject an ``info`` longer than 1024 bytes, so hashing first keeps
    the same binding while staying portable to every runtime we need to target.
    """
    return hashlib.sha256(
        KDF_LABEL + responder.to_transcript() + ciphertext.to_transcript()
    ).digest()


def _derive(*, x25519_secret: bytes, ml_kem_secret: bytes,
            responder: HybridPublicBundle, ciphertext: HybridCiphertext) -> bytes:
    info = KDF_LABEL + transcript_digest(responder, ciphertext)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES_256_KEY_BYTES,
        salt=None,
        info=info,
    ).derive(x25519_secret + ml_kem_secret)


def initiate(responder: HybridPublicBundle) -> Tuple[HybridCiphertext, bytes]:
    if len(responder.x25519_public) != X25519_PUB_BYTES:
        raise ValueError("bad X25519 public key length")
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    x_secret = eph.exchange(X25519PublicKey.from_public_bytes(responder.x25519_public))
    kem_ct, kem_secret = pqc.get_backend().encapsulate(responder.ml_kem_encapsulation_key)
    ciphertext = HybridCiphertext(eph_pub, kem_ct)
    return ciphertext, _derive(
        x25519_secret=x_secret,
        ml_kem_secret=kem_secret,
        responder=responder,
        ciphertext=ciphertext,
    )


def respond(private: HybridPrivateBundle, public: HybridPublicBundle,
            ciphertext: HybridCiphertext) -> bytes:
    x_priv = X25519PrivateKey.from_private_bytes(private.x25519_private)
    x_secret = x_priv.exchange(
        X25519PublicKey.from_public_bytes(ciphertext.x25519_ephemeral_public)
    )
    kem_secret = pqc.get_backend().decapsulate(
        private.ml_kem_decapsulation_key, ciphertext.ml_kem_ciphertext
    )
    return _derive(
        x25519_secret=x_secret,
        ml_kem_secret=kem_secret,
        responder=public,
        ciphertext=ciphertext,
    )
