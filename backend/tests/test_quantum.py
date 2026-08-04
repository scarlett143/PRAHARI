from app.crypto.entropy import EntropySource, derive_key, estimate_min_entropy_per_bit, von_neumann_extract
from app.quantum.experiment import run_bb84


def test_entropy_falls_back_safely_without_quantum_bits():
    first, report = derive_key(source=EntropySource.QUANTUM_MIXED, quantum_bits=None)
    second, _ = derive_key(source=EntropySource.QUANTUM_MIXED, quantum_bits=None)
    assert len(first) == 32
    assert first != second
    assert report.source is EntropySource.SYSTEM


def test_von_neumann_and_min_entropy_metrics():
    assert von_neumann_extract("01100011") == "01"
    _, entropy = estimate_min_entropy_per_bit("01" * 500)
    assert entropy > 0.99


def test_bb84_no_interceptor_has_low_qber_and_interception_raises_it():
    clean = run_bb84(rounds=6000, intercept_rate=0.0)
    attacked = run_bb84(rounds=6000, intercept_rate=1.0)
    assert clean.qber < 0.05
    assert attacked.qber > 0.15
