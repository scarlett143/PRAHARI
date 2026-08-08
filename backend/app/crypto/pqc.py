"""ML-KEM-768 abstraction reused from the reference implementation."""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol, Tuple

ALGORITHM = "ML-KEM-768"
EK_BYTES = 1184
DK_BYTES = 2400
CT_BYTES = 1088
SS_BYTES = 32


class PQCError(Exception):
    pass


@dataclass(frozen=True)
class KEMKeypair:
    encapsulation_key: bytes
    decapsulation_key: bytes


class KEMBackend(Protocol):
    name: str
    def keygen(self) -> KEMKeypair: ...
    def encapsulate(self, encapsulation_key: bytes) -> Tuple[bytes, bytes]: ...
    def decapsulate(self, decapsulation_key: bytes, ciphertext: bytes) -> bytes: ...


class KyberPyBackend:
    name = "kyber-py (pure Python, NOT constant-time)"

    def __init__(self) -> None:
        try:
            from kyber_py.ml_kem import ML_KEM_768
        except ImportError as exc:
            raise PQCError("kyber-py not installed: pip install kyber-py") from exc
        self._kem = ML_KEM_768

    def keygen(self) -> KEMKeypair:
        ek, dk = self._kem.keygen()
        return KEMKeypair(bytes(ek), bytes(dk))

    def encapsulate(self, encapsulation_key: bytes) -> Tuple[bytes, bytes]:
        if len(encapsulation_key) != EK_BYTES:
            raise PQCError(f"encapsulation key must be {EK_BYTES} bytes")
        shared_secret, ciphertext = self._kem.encaps(encapsulation_key)
        return bytes(ciphertext), bytes(shared_secret)

    def decapsulate(self, decapsulation_key: bytes, ciphertext: bytes) -> bytes:
        if len(decapsulation_key) != DK_BYTES:
            raise PQCError(f"decapsulation key must be {DK_BYTES} bytes")
        if len(ciphertext) != CT_BYTES:
            raise PQCError(f"ciphertext must be {CT_BYTES} bytes")
        return bytes(self._kem.decaps(decapsulation_key, ciphertext))


class LiboqsBackend:
    name = "liboqs (native, constant-time)"

    def __init__(self) -> None:
        try:
            import oqs
        except ImportError as exc:
            raise PQCError("liboqs-python is not installed") from exc
        self._oqs = oqs

    def keygen(self) -> KEMKeypair:
        with self._oqs.KeyEncapsulation("ML-KEM-768") as kem:
            ek = kem.generate_keypair()
            dk = kem.export_secret_key()
        return KEMKeypair(bytes(ek), bytes(dk))

    def encapsulate(self, encapsulation_key: bytes) -> Tuple[bytes, bytes]:
        with self._oqs.KeyEncapsulation("ML-KEM-768") as kem:
            ct, ss = kem.encap_secret(encapsulation_key)
        return bytes(ct), bytes(ss)

    def decapsulate(self, decapsulation_key: bytes, ciphertext: bytes) -> bytes:
        with self._oqs.KeyEncapsulation("ML-KEM-768", decapsulation_key) as kem:
            return bytes(kem.decap_secret(ciphertext))


_BACKENDS = {"kyber-py": KyberPyBackend, "liboqs": LiboqsBackend}
_cached: KEMBackend | None = None


def get_backend() -> KEMBackend:
    """The configured ML-KEM implementation.

    Resolved through the settings object rather than `os.getenv` alone. The environment
    variable is only populated as a side effect of `get_settings()`, so reading it
    directly made the answer depend on whether anything had loaded settings yet -- and the
    failure mode of getting that wrong is silent: a caller that arrives first receives the
    pure-Python backend, which is documented as research grade and *not constant-time*,
    with nothing logged to say so.

    Deferred import because `config` reaches into this module during validation; at module
    scope the two would form a cycle.
    """
    global _cached
    if _cached is None:
        try:
            from ..config import get_settings

            choice = get_settings().pqc_backend
        except Exception:
            # Settings themselves are broken or unavailable (a bare unit test, a tool run
            # outside the app). Fall back to the environment, then to the safe default.
            choice = os.getenv("PQC_BACKEND", "kyber-py")

        choice = (choice or "kyber-py").strip().lower()
        backend = _BACKENDS.get(choice)
        if backend is None:
            raise PQCError(f"unknown PQC_BACKEND {choice!r}")
        _cached = backend()
    return _cached
