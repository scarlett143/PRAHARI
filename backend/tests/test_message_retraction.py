"""Retraction removes the content and keeps the proof.

The delete endpoint sits on a fault line: a message's `content_hash` is a leaf in a
published Merkle tree, so the obvious implementation -- delete the row -- would silently
invalidate anchor proofs for every *other* message batched alongside it. These tests pin
the parts of the behaviour that are easy to regress and expensive to notice.
"""
import pytest

pytest.importorskip("aiosqlite")
pytest.importorskip("kyber_py")

import uuid

import anyio
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.database import get_session_factory
from app.main import app
from app.models import Message

from test_api_flow import b64
from test_regressions import _two_party_channel


def _send(client: TestClient, headers, channel_id: str, epoch: int, body: bytes):
    response = client.post(
        "/api/v2/messages",
        headers=headers,
        json={
            # Unique per send: the column is globally unique and the tests share a database.
            "client_message_id": uuid.uuid4().hex,
            "channel_id": channel_id,
            "key_epoch": epoch,
            "envelope_b64": b64(body),
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def _stored(message_id: str) -> Message:
    """Read the row straight from the database, past whatever the API chooses to show."""

    async def read():
        async with get_session_factory()() as session:
            return (
                await session.execute(select(Message).where(Message.id == message_id))
            ).scalar_one()

    return anyio.run(read)


def test_retraction_blanks_the_envelope_but_keeps_the_content_hash():
    with TestClient(app) as client:
        fixture = _two_party_channel(client)
        alice_headers, _, _ = fixture["alice"]
        channel_id = fixture["channel_id"]
        channel = client.get(f"/api/v2/channels/{channel_id}", headers=alice_headers).json()

        sent = _send(client, alice_headers, channel_id, channel["key_epoch"], b"x" * 48)
        hash_before = sent["content_hash"]

        deleted = client.delete(f"/api/v2/messages/{sent['id']}", headers=alice_headers)
        assert deleted.status_code == 200, deleted.text
        assert deleted.json()["deleted_at"] is not None

        stored = _stored(sent["id"])
        assert stored.envelope == b"", "the ciphertext must be gone"
        assert stored.content_hash.hex() == hash_before, (
            "the hash is a Merkle leaf; changing or dropping it breaks every anchor proof "
            "issued for the batch, including proofs about other people's messages"
        )


def test_only_the_author_can_retract_and_a_stranger_cannot_probe_for_ids():
    with TestClient(app) as client:
        fixture = _two_party_channel(client)
        alice_headers, _, _ = fixture["alice"]
        bob_headers, _, _ = fixture["bob"]
        channel_id = fixture["channel_id"]
        channel = client.get(f"/api/v2/channels/{channel_id}", headers=alice_headers).json()

        sent = _send(client, alice_headers, channel_id, channel["key_epoch"], b"y" * 48)

        # Bob is in the channel and can read this message, but it is not his to withdraw.
        refused = client.delete(f"/api/v2/messages/{sent['id']}", headers=bob_headers)
        assert refused.status_code == 404

        # And the answer is identical for an id that does not exist, so the status code
        # cannot be used to enumerate which messages are real.
        missing = client.delete("/api/v2/messages/does-not-exist", headers=bob_headers)
        assert missing.status_code == refused.status_code

        assert _stored(sent["id"]).envelope != b"", "a refused delete must not take effect"


def test_retracting_twice_is_a_retry_rather_than_an_error():
    with TestClient(app) as client:
        fixture = _two_party_channel(client)
        alice_headers, _, _ = fixture["alice"]
        channel_id = fixture["channel_id"]
        channel = client.get(f"/api/v2/channels/{channel_id}", headers=alice_headers).json()

        sent = _send(client, alice_headers, channel_id, channel["key_epoch"], b"z" * 48)

        first = client.delete(f"/api/v2/messages/{sent['id']}", headers=alice_headers)
        second = client.delete(f"/api/v2/messages/{sent['id']}", headers=alice_headers)
        assert first.status_code == second.status_code == 200
        # A retry must not move the timestamp: the first retraction is when it happened.
        assert first.json()["deleted_at"] == second.json()["deleted_at"]


def test_history_reports_the_retraction_so_clients_can_render_a_tombstone():
    with TestClient(app) as client:
        fixture = _two_party_channel(client)
        alice_headers, _, _ = fixture["alice"]
        bob_headers, _, _ = fixture["bob"]
        channel_id = fixture["channel_id"]
        channel = client.get(f"/api/v2/channels/{channel_id}", headers=alice_headers).json()

        kept = _send(client, alice_headers, channel_id, channel["key_epoch"], b"a" * 48)
        gone = _send(client, alice_headers, channel_id, channel["key_epoch"], b"b" * 48)
        client.delete(f"/api/v2/messages/{gone['id']}", headers=alice_headers)

        history = client.get(
            f"/api/v2/channels/{channel_id}/messages", headers=bob_headers
        ).json()
        rows = {row["id"]: row for row in history}

        assert rows[kept["id"]]["deleted_at"] is None
        assert rows[gone["id"]]["deleted_at"] is not None
        assert rows[gone["id"]]["envelope_b64"] == "", "the relay must stop serving the ciphertext"
        # The row survives so the transcript does not renumber itself around the gap.
        assert len(history) == 2
