"""Production configuration gates and PQC backend equivalence.

The deployment note asks for a constant-time backend and a strong secret before this
faces anything real. These assert the app *enforces* that rather than printing advice to
stderr, and that switching backends does not change the wire format -- a published key
bundle must stay valid across the switch.
"""
import pytest

from app.config import MIN_JWT_SECRET_LENGTH, Settings
from app.crypto import pqc

STRONG_SECRET = "x" * 64


def settings(**overrides) -> Settings:
    base = {
        "environment": "production",
        "jwt_secret": STRONG_SECRET,
        "pqc_backend": "liboqs",
    }
    base.update(overrides)
    return Settings(**base)


def test_production_refuses_a_placeholder_secret():
    with pytest.raises(RuntimeError, match="JWT_SECRET"):
        settings(jwt_secret="changeme").validate_for_runtime()


def test_production_refuses_a_short_invented_secret():
    """The placeholder list only catches secrets copied from the docs."""
    short = "s3cr3t!"
    assert short.lower() not in {"", "secret", "changeme"}
    assert len(short) < MIN_JWT_SECRET_LENGTH
    with pytest.raises(RuntimeError, match="at least"):
        settings(jwt_secret=short).validate_for_runtime()


def test_production_refuses_the_non_constant_time_backend():
    with pytest.raises(RuntimeError, match="not constant-time"):
        settings(pqc_backend="kyber-py").validate_for_runtime()


def test_development_still_runs_on_the_pure_python_backend():
    """A demo install must stay easy; the gate is production-only."""
    config = Settings(environment="development", jwt_secret="", pqc_backend="kyber-py")
    config.validate_for_runtime()
    # An ephemeral secret is generated rather than the process refusing to start.
    assert len(config.jwt_secret) >= MIN_JWT_SECRET_LENGTH


def test_development_tolerates_a_short_secret():
    config = Settings(environment="development", jwt_secret="short", pqc_backend="kyber-py")
    config.validate_for_runtime()
    assert config.jwt_secret == "short"


@pytest.mark.parametrize("environment", ["production", "PRODUCTION", "prod"])
def test_production_is_recognised_however_it_is_spelled(environment):
    with pytest.raises(RuntimeError, match="not constant-time"):
        settings(environment=environment, pqc_backend="kyber-py").validate_for_runtime()


class TestBackendEquivalence:
    """liboqs and kyber-py must be interchangeable on the wire.

    If they were not, switching a deployment to the constant-time backend would
    invalidate every key bundle users had already published.
    """

    @staticmethod
    def backends():
        pytest.importorskip("kyber_py")
        oqs = pytest.importorskip("oqs", reason="liboqs-python not installed")  # noqa: F841
        return pqc.KyberPyBackend(), pqc.LiboqsBackend()

    def test_key_and_ciphertext_sizes_match_the_spec(self):
        kyber, liboqs = self.backends()
        for backend in (kyber, liboqs):
            pair = backend.keygen()
            assert len(pair.encapsulation_key) == pqc.EK_BYTES
            assert len(pair.decapsulation_key) == pqc.DK_BYTES
            ciphertext, secret = backend.encapsulate(pair.encapsulation_key)
            assert len(ciphertext) == pqc.CT_BYTES
            assert len(secret) == pqc.SS_BYTES

    def test_liboqs_keys_decapsulate_a_kyber_py_ciphertext(self):
        kyber, liboqs = self.backends()
        pair = liboqs.keygen()
        ciphertext, sent = kyber.encapsulate(pair.encapsulation_key)
        assert liboqs.decapsulate(pair.decapsulation_key, ciphertext) == sent

    def test_kyber_py_keys_decapsulate_a_liboqs_ciphertext(self):
        kyber, liboqs = self.backends()
        pair = kyber.keygen()
        ciphertext, sent = liboqs.encapsulate(pair.encapsulation_key)
        assert kyber.decapsulate(pair.decapsulation_key, ciphertext) == sent

    def test_a_tampered_ciphertext_does_not_yield_the_sent_secret(self):
        """ML-KEM is designed to return a wrong secret, not to raise, on tampering."""
        _, liboqs = self.backends()
        pair = liboqs.keygen()
        ciphertext, sent = liboqs.encapsulate(pair.encapsulation_key)
        flipped = bytearray(ciphertext)
        flipped[0] ^= 0x01
        assert liboqs.decapsulate(pair.decapsulation_key, bytes(flipped)) != sent
