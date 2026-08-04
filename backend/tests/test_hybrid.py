import pytest
pytest.importorskip("kyber_py")

from app.crypto import hybrid


def test_100_randomized_hybrid_agreements():
    public, private = hybrid.generate_bundle()
    seen = set()
    for _ in range(100):
        ciphertext, initiator_key = hybrid.initiate(public)
        responder_key = hybrid.respond(private, public, ciphertext)
        assert initiator_key == responder_key
        assert len(initiator_key) == 32
        seen.add(initiator_key)
    assert len(seen) == 100


def test_transcript_changes_key():
    public, private = hybrid.generate_bundle()
    ciphertext, key = hybrid.initiate(public)
    other_public, _ = hybrid.generate_bundle()
    other_ciphertext, _ = hybrid.initiate(other_public)
    spliced = hybrid.HybridCiphertext(
        other_ciphertext.x25519_ephemeral_public,
        ciphertext.ml_kem_ciphertext,
    )
    assert hybrid.respond(private, public, spliced) != key
