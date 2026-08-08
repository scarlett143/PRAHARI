"""Post-quantum attestation over anchor roots.

An anchor exists to be checked years after it was made, which is precisely the window in
which a classical signature over it stops being trustworthy. These tests cover the signing
itself and the binding that stops one attestation being reused as another.
"""
import pytest

pytest.importorskip("aiosqlite")

from app.crypto import pqsign

pytestmark = pytest.mark.skipif(
    not pqsign.available(), reason="liboqs-python is not installed in this environment"
)

ROOT = bytes(range(32))
OTHER_ROOT = bytes(range(32, 64))


def test_a_root_signature_verifies():
    public_key, secret_key = pqsign.generate_keypair()
    payload = pqsign.anchor_signing_payload(merkle_root=ROOT, leaf_count=12)

    signature = pqsign.sign(secret_key, payload)
    assert pqsign.verify(public_key, payload, signature) is True


def test_another_key_does_not_verify():
    _, secret_key = pqsign.generate_keypair()
    impostor_public, _ = pqsign.generate_keypair()
    payload = pqsign.anchor_signing_payload(merkle_root=ROOT, leaf_count=12)

    signature = pqsign.sign(secret_key, payload)
    assert pqsign.verify(impostor_public, payload, signature) is False


def test_a_signature_is_bound_to_its_root():
    public_key, secret_key = pqsign.generate_keypair()
    signature = pqsign.sign(
        secret_key, pqsign.anchor_signing_payload(merkle_root=ROOT, leaf_count=12)
    )

    moved = pqsign.anchor_signing_payload(merkle_root=OTHER_ROOT, leaf_count=12)
    assert pqsign.verify(public_key, moved, signature) is False


def test_a_signature_is_bound_to_the_leaf_count():
    """A batch of one and a batch of a thousand must not be interchangeable: the leaf count
    is what tells a verifier how much a single inclusion proof is claiming."""
    public_key, secret_key = pqsign.generate_keypair()
    signature = pqsign.sign(
        secret_key, pqsign.anchor_signing_payload(merkle_root=ROOT, leaf_count=1)
    )

    restated = pqsign.anchor_signing_payload(merkle_root=ROOT, leaf_count=1000)
    assert pqsign.verify(public_key, restated, signature) is False


def test_the_payload_is_domain_separated():
    """The signed bytes must never be a bare 32-byte value that another flow also signs."""
    payload = pqsign.anchor_signing_payload(merkle_root=ROOT, leaf_count=3)
    assert payload.startswith(pqsign.ANCHOR_LABEL)
    assert payload != ROOT


def test_malformed_input_fails_closed():
    public_key, secret_key = pqsign.generate_keypair()
    payload = pqsign.anchor_signing_payload(merkle_root=ROOT, leaf_count=1)
    signature = pqsign.sign(secret_key, payload)

    # Garbage arrives here from whoever is asking for a proof; it must be a failed
    # verification, not an exception that becomes a 500.
    assert pqsign.verify(b"not-a-key", payload, signature) is False
    assert pqsign.verify(public_key, payload, b"not-a-signature") is False
    assert pqsign.verify(public_key, payload, b"") is False
