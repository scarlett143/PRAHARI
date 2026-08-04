"""Combines the optional QRNG experiment and BB84 protocol simulation."""
from __future__ import annotations

from ..crypto.entropy import EntropySource, derive_key
from .experiment import run_bb84
from .qrng import QuantumUnavailable, run_aer_qrng


def run_security_lab(*, shots: int = 1024, bb84_rounds: int = 2048, intercept_rate: float = 0.0) -> dict:
    qrng_public: dict
    quantum_bits: str | None = None
    backend_name = "unavailable"
    try:
        qrng = run_aer_qrng(shots=shots)
        quantum_bits = qrng.bits
        backend_name = qrng.backend
        qrng_public = {"status": "ok", **qrng.public_dict()}
    except QuantumUnavailable as exc:
        qrng_public = {"status": "unavailable", "reason": str(exc)}

    _, entropy_report = derive_key(
        source=EntropySource.QUANTUM_MIXED,
        quantum_bits=quantum_bits,
        backend_name=backend_name,
    )
    bb84 = run_bb84(rounds=bb84_rounds, intercept_rate=intercept_rate)
    passed = bb84.passed and (qrng_public["status"] in {"ok", "unavailable"})
    return {
        "algorithm": "BB84 protocol simulation + QRNG entropy experiment",
        "backend": backend_name,
        "qrng": qrng_public,
        "bb84": bb84.to_dict(),
        "entropy": entropy_report.to_dict(),
        "passed": passed,
        "security_note": (
            "QRNG output is never used as the sole secret-key source. The BB84 component is a protocol simulation, "
            "not a claim of a deployed quantum network."
        ),
    }
