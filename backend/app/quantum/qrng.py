"""QRNG experiment using Qiskit Aer when the optional quantum extra is installed."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from ..crypto.entropy import estimate_min_entropy_per_bit


class QuantumUnavailable(RuntimeError):
    pass


@dataclass
class QRNGResult:
    bits: str
    backend: str
    shots: int
    zero_count: int
    one_count: int
    observed_bias: float
    min_entropy_per_bit: float

    def public_dict(self) -> dict:
        return {
            "backend": self.backend,
            "shots": self.shots,
            "zero_count": self.zero_count,
            "one_count": self.one_count,
            "observed_bias": self.observed_bias,
            "min_entropy_per_bit": self.min_entropy_per_bit,
        }


def run_aer_qrng(shots: int = 1024) -> QRNGResult:
    try:
        from qiskit import QuantumCircuit, transpile
        from qiskit_aer import AerSimulator
    except ImportError as exc:
        raise QuantumUnavailable(
            "Qiskit Aer is not installed; install backend/requirements-quantum.txt"
        ) from exc

    circuit = QuantumCircuit(1, 1)
    circuit.h(0)
    circuit.measure(0, 0)
    backend = AerSimulator()
    compiled = transpile(circuit, backend)
    result = backend.run(compiled, shots=shots, memory=True).result()
    memory = result.get_memory(compiled)
    bits = "".join(str(bit)[-1] for bit in memory)
    counts = Counter(bits)
    bias, min_entropy = estimate_min_entropy_per_bit(bits)
    return QRNGResult(
        bits=bits,
        backend="qiskit-aer/AerSimulator",
        shots=shots,
        zero_count=counts.get("0", 0),
        one_count=counts.get("1", 0),
        observed_bias=bias,
        min_entropy_per_bit=min_entropy,
    )
