import asyncio

from app.main import health


def test_health_declares_server_has_no_plaintext_access():
    body = asyncio.run(health())
    assert body["status"] == "ok"
    assert body["server_can_read_messages"] is False
    assert body["message_crypto_location"] == "client"
