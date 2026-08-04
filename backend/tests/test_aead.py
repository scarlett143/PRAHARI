import os

import pytest

from app.crypto import aead


def test_aes256_roundtrip_and_wire_format():
    key = os.urandom(32)
    aad = aead.build_aad(sender_id="alice", channel_id="general", epoch=0)
    envelope = aead.encrypt(key, b"hello bob", aad)
    wire = envelope.to_wire()
    assert aead.decrypt(key, aead.Envelope.from_wire(wire), aad) == b"hello bob"


def test_tamper_wrong_key_wrong_channel_and_wrong_epoch_fail_closed():
    key = os.urandom(32)
    aad = aead.build_aad(sender_id="alice", channel_id="general", epoch=4)
    envelope = aead.encrypt(key, b"secret", aad)

    tampered = aead.Envelope(
        envelope.version,
        envelope.nonce,
        envelope.ciphertext[:-1] + bytes([envelope.ciphertext[-1] ^ 1]),
    )
    cases = [
        (key, tampered, aad),
        (os.urandom(32), envelope, aad),
        (key, envelope, aead.build_aad(sender_id="alice", channel_id="other", epoch=4)),
        (key, envelope, aead.build_aad(sender_id="alice", channel_id="general", epoch=5)),
    ]
    for test_key, test_envelope, test_aad in cases:
        with pytest.raises(aead.DecryptionError):
            aead.decrypt(test_key, test_envelope, test_aad)


def test_aes_key_length_is_strict():
    with pytest.raises(ValueError):
        aead.encrypt(b"x" * 16, b"hello", b"aad")
