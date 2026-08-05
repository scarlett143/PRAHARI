"""Cross-implementation agreement between the Python and JavaScript ratchets.

The README claims one protocol across both deployments. That claim is only worth
anything if the two implementations actually agree on the wire, so this replays a
conversation recorded by the browser implementation and decrypts it here, byte for byte.

If a KDF label, chain constant, header layout or AAD framing drifts on either side, these
fail. Regenerate the vectors with:

    cd frontend && node scripts/generate-ratchet-vectors.mjs \\
        > ../backend/tests/vectors/ratchet_js_vectors.json
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from app.crypto import ratchet

VECTOR_FILE = Path(__file__).parent / "vectors" / "ratchet_js_vectors.json"


def b64d(value: str) -> bytes:
    return base64.b64decode(value)


@pytest.fixture(scope="module")
def vectors() -> dict:
    if not VECTOR_FILE.is_file():
        pytest.skip(f"interop vectors not generated: {VECTOR_FILE}")
    return json.loads(VECTOR_FILE.read_text())


def queued_keygen(secrets: list[str]):
    """Hand back the exact ephemerals the recorded session used, in order."""
    remaining = list(secrets)

    def keygen() -> ratchet.KeyPair:
        if not remaining:
            raise AssertionError("ratchet asked for more keypairs than the vector recorded")
        secret = b64d(remaining.pop(0))
        private = ratchet.X25519PrivateKey.from_private_bytes(secret)
        return ratchet.KeyPair(secret=secret, public=private.public_key().public_bytes_raw())

    return keygen


def build_pair(vectors: dict):
    shared = b64d(vectors["shared_secret"])
    bob_secret = b64d(vectors["bob_identity_secret"])
    bob_identity = ratchet.KeyPair(secret=bob_secret, public=b64d(vectors["bob_identity_public"]))

    alice = ratchet.init_sender(
        shared,
        bob_identity.public,
        keygen=queued_keygen(vectors["alice_keygen_queue"]),
    )
    bob = ratchet.init_receiver(
        shared,
        bob_identity,
        keygen=queued_keygen(vectors["bob_keygen_queue"]),
    )
    return alice, bob


def test_python_decrypts_a_conversation_recorded_by_the_browser(vectors):
    alice, bob = build_pair(vectors)
    channel_id = vectors["channel_id"]

    decrypted = []
    for message in vectors["messages"]:
        receiver = bob if message["from"] == "alice" else alice
        plaintext = ratchet.decrypt(
            receiver,
            b64d(message["envelope"]),
            sender_id=message["sender_id"],
            channel_id=channel_id,
            epoch=message["epoch"],
        )
        assert plaintext.decode() == message["plaintext"]
        decrypted.append(plaintext.decode())

    assert decrypted == [message["plaintext"] for message in vectors["messages"]]
    # The script deliberately covers a one-sided burst and two direction flips.
    assert len({message["from"] for message in vectors["messages"]}) == 2


def test_the_recorded_envelopes_carry_the_shared_wire_format(vectors):
    for message in vectors["messages"]:
        envelope = b64d(message["envelope"])
        assert envelope[0] == ratchet.ENVELOPE_VERSION
        # version + header + nonce + tag is the floor for an empty plaintext.
        assert len(envelope) >= 1 + ratchet.HEADER_BYTES + ratchet.NONCE_BYTES + ratchet.TAG_BYTES


def test_a_tampered_recorded_envelope_fails_here_too(vectors):
    alice, bob = build_pair(vectors)
    first = vectors["messages"][0]
    envelope = bytearray(b64d(first["envelope"]))
    envelope[-1] ^= 0xFF

    with pytest.raises(ratchet.RatchetError):
        ratchet.decrypt(
            bob,
            bytes(envelope),
            sender_id=first["sender_id"],
            channel_id=vectors["channel_id"],
            epoch=first["epoch"],
        )


def test_the_aad_binds_the_channel_across_implementations(vectors):
    """A browser-produced envelope must not decrypt under a different channel here."""
    alice, bob = build_pair(vectors)
    first = vectors["messages"][0]

    with pytest.raises(ratchet.RatchetError):
        ratchet.decrypt(
            bob,
            b64d(first["envelope"]),
            sender_id=first["sender_id"],
            channel_id="a-different-channel",
            epoch=first["epoch"],
        )
