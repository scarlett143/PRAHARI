"""Entropy mixing utilities. Network-fetched quantum bits are never used alone."""
from __future__ import annotations

import math
import os
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .aead import AES_256_KEY_BYTES


class EntropySource(str, Enum):
    SYSTEM = "system"
    QUANTUM_MIXED = "quantum_mixed"


@dataclass
class EntropyReport:
    source: EntropySource
    output_bytes: int
    system_entropy_bytes: int
    quantum_raw_bits: int = 0
    quantum_extracted_bits: int = 0
    quantum_zero_count: int = 0
    quantum_one_count: int = 0
    observed_bias: Optional[float] = None
    min_entropy_per_bit: Optional[float] = None
    total_quantum_min_entropy_bits: Optional[float] = None
    backend_name: Optional[str] = None
    job_id: Optional[str] = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "source": self.source.value,
            "output_bytes": self.output_bytes,
            "system_entropy_bytes": self.system_entropy_bytes,
            "quantum": {
                "raw_bits": self.quantum_raw_bits,
                "extracted_bits": self.quantum_extracted_bits,
                "zero_count": self.quantum_zero_count,
                "one_count": self.quantum_one_count,
                "observed_bias": self.observed_bias,
                "min_entropy_per_bit": self.min_entropy_per_bit,
                "total_min_entropy_bits": self.total_quantum_min_entropy_bits,
                "backend": self.backend_name,
                "job_id": self.job_id,
            },
            "notes": self.notes,
        }


def von_neumann_extract(bits: str) -> str:
    out: list[str] = []
    for index in range(0, len(bits) - 1, 2):
        a, b = bits[index], bits[index + 1]
        if a == "0" and b == "1":
            out.append("0")
        elif a == "1" and b == "0":
            out.append("1")
    return "".join(out)


def estimate_min_entropy_per_bit(bits: str) -> tuple[float, float]:
    if not bits:
        return 0.0, 0.0
    counts = Counter(bits)
    total = len(bits)
    p_max = max(counts.get("0", 0), counts.get("1", 0)) / total
    bias = p_max - 0.5
    if p_max >= 1.0:
        return bias, 0.0
    return bias, -math.log2(p_max)


def _bits_to_bytes(bits: str) -> bytes:
    usable = len(bits) - (len(bits) % 8)
    if usable == 0:
        return b""
    return int(bits[:usable], 2).to_bytes(usable // 8, "big")


def derive_key(
    *,
    source: EntropySource = EntropySource.SYSTEM,
    length: int = AES_256_KEY_BYTES,
    quantum_bits: Optional[str] = None,
    backend_name: Optional[str] = None,
    job_id: Optional[str] = None,
    info: bytes = b"prahari/entropy/v1",
) -> tuple[bytes, EntropyReport]:
    system_entropy = os.urandom(32)
    salt = os.urandom(32)
    ikm = system_entropy
    report = EntropyReport(
        source=source,
        output_bytes=length,
        system_entropy_bytes=len(system_entropy),
        backend_name=backend_name,
        job_id=job_id,
    )

    if source is EntropySource.QUANTUM_MIXED:
        if not quantum_bits:
            report.source = EntropySource.SYSTEM
            report.notes.append("Quantum bits unavailable; safely fell back to os.urandom.")
        else:
            extracted = von_neumann_extract(quantum_bits)
            bias, min_entropy = estimate_min_entropy_per_bit(quantum_bits)
            counts = Counter(quantum_bits)
            report.quantum_raw_bits = len(quantum_bits)
            report.quantum_extracted_bits = len(extracted)
            report.quantum_zero_count = counts.get("0", 0)
            report.quantum_one_count = counts.get("1", 0)
            report.observed_bias = bias
            report.min_entropy_per_bit = min_entropy
            report.total_quantum_min_entropy_bits = min_entropy * len(quantum_bits)
            quantum_material = _bits_to_bytes(extracted)
            ikm += quantum_material
            report.notes.append(
                f"Mixed {len(quantum_material)} extracted quantum bytes with 32 bytes of local system entropy."
            )
            report.notes.append(
                "Quantum bits are an entropy-diversity input only; they are not treated as secret network key material."
            )

    key = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)
    return key, report
