"""BB84 protocol simulation for teaching/demo purposes."""
from __future__ import annotations

import secrets
from dataclasses import dataclass


@dataclass
class BB84Result:
    rounds: int
    sifted_bits: int
    errors: int
    qber: float
    intercept_rate: float
    passed: bool

    def to_dict(self) -> dict:
        return {
            "rounds": self.rounds,
            "sifted_bits": self.sifted_bits,
            "errors": self.errors,
            "qber": self.qber,
            "intercept_rate": self.intercept_rate,
            "passed": self.passed,
            "pass_threshold": 0.11,
        }


def _bit() -> int:
    return secrets.randbelow(2)


def run_bb84(*, rounds: int = 2048, intercept_rate: float = 0.0) -> BB84Result:
    if not 0 <= intercept_rate <= 1:
        raise ValueError("intercept_rate must be between 0 and 1")
    sifted = 0
    errors = 0

    for _ in range(rounds):
        alice_bit = _bit()
        alice_basis = _bit()
        travelling_bit = alice_bit
        travelling_basis = alice_basis

        if secrets.randbelow(1_000_000) / 1_000_000 < intercept_rate:
            eve_basis = _bit()
            if eve_basis == travelling_basis:
                eve_bit = travelling_bit
            else:
                eve_bit = _bit()
            travelling_bit = eve_bit
            travelling_basis = eve_basis

        bob_basis = _bit()
        if bob_basis == travelling_basis:
            bob_bit = travelling_bit
        else:
            bob_bit = _bit()

        if bob_basis == alice_basis:
            sifted += 1
            if bob_bit != alice_bit:
                errors += 1

    qber = errors / sifted if sifted else 1.0
    return BB84Result(
        rounds=rounds,
        sifted_bits=sifted,
        errors=errors,
        qber=qber,
        intercept_rate=intercept_rate,
        passed=qber < 0.11,
    )
