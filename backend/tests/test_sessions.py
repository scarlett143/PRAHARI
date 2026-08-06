"""Active sessions and remote sign-out.

A JWT validates itself, so "this token should stop working now" is a question only a
server-side record can answer. These check that the record is actually consulted — that
revocation bites on the very next request, that it is scoped to the one session, and
that one account cannot reach into another's.
"""
import pytest

pytest.importorskip("aiosqlite")
pytest.importorskip("kyber_py")

from fastapi.testclient import TestClient

from app.main import app

from test_api_flow import register_verified

PASSWORD = "correct-horse-battery-staple"


def sign_in(client: TestClient, username: str):
    response = client.post(
        "/api/v2/auth/login", json={"username": username, "password": PASSWORD}
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_signing_in_creates_a_listed_session():
    with TestClient(app) as client:
        headers, _, _ = register_verified(client, "sess_list")

        rows = client.get("/api/v2/auth/sessions", headers=headers)
        assert rows.status_code == 200, rows.text
        body = rows.json()
        assert len(body) == 1
        assert body[0]["current"] is True
        assert body[0]["kind"] == "human"


def test_a_second_sign_in_appears_alongside_the_first():
    with TestClient(app) as client:
        first, _, _ = register_verified(client, "sess_two")
        second = sign_in(client, "sess_two")

        body = client.get("/api/v2/auth/sessions", headers=second).json()
        assert len(body) == 2
        # Exactly one of them is the caller's own.
        assert [row["current"] for row in body].count(True) == 1


def test_revoking_a_session_stops_its_token_immediately():
    with TestClient(app) as client:
        first, _, _ = register_verified(client, "sess_revoke")
        second = sign_in(client, "sess_revoke")

        # The second session ends the first.
        rows = client.get("/api/v2/auth/sessions", headers=second).json()
        victim = next(row["id"] for row in rows if not row["current"])
        revoked = client.delete(f"/api/v2/auth/sessions/{victim}", headers=second)
        assert revoked.status_code == 200, revoked.text

        # The revoked token is refused on its very next use, despite still being a
        # perfectly valid signature that has not expired.
        assert client.get("/api/v2/auth/me", headers=first).status_code == 401
        # The surviving session is untouched.
        assert client.get("/api/v2/auth/me", headers=second).status_code == 200


def test_revoke_others_keeps_the_calling_session():
    with TestClient(app) as client:
        first, _, _ = register_verified(client, "sess_others")
        second = sign_in(client, "sess_others")
        third = sign_in(client, "sess_others")

        result = client.post("/api/v2/auth/sessions/revoke-others", headers=third)
        assert result.status_code == 200, result.text
        assert result.json()["revoked"] == 2

        assert client.get("/api/v2/auth/me", headers=third).status_code == 200
        assert client.get("/api/v2/auth/me", headers=first).status_code == 401
        assert client.get("/api/v2/auth/me", headers=second).status_code == 401

        remaining = client.get("/api/v2/auth/sessions", headers=third).json()
        assert len(remaining) == 1


def test_one_account_cannot_revoke_another_accounts_session():
    with TestClient(app) as client:
        victim_headers, _, _ = register_verified(client, "sess_victim")
        attacker_headers, _, _ = register_verified(client, "sess_attacker")

        victim_session = client.get("/api/v2/auth/sessions", headers=victim_headers).json()[0]["id"]

        response = client.delete(
            f"/api/v2/auth/sessions/{victim_session}", headers=attacker_headers
        )
        assert response.status_code == 404
        # And the victim is still signed in.
        assert client.get("/api/v2/auth/me", headers=victim_headers).status_code == 200


def test_revoked_sessions_disappear_from_the_list():
    with TestClient(app) as client:
        first, _, _ = register_verified(client, "sess_gone")
        second = sign_in(client, "sess_gone")

        rows = client.get("/api/v2/auth/sessions", headers=second).json()
        victim = next(row["id"] for row in rows if not row["current"])
        client.delete(f"/api/v2/auth/sessions/{victim}", headers=second)

        remaining = client.get("/api/v2/auth/sessions", headers=second).json()
        assert [row["id"] for row in remaining] == [
            row["id"] for row in remaining if row["current"]
        ]
        assert victim not in [row["id"] for row in remaining]


def test_password_reset_signs_every_other_session_out():
    """Whoever resets may be recovering from a compromise; old tokens must not survive."""
    import hashlib

    from app.security import password_reset_signing_payload
    from test_api_flow import b64

    with TestClient(app) as client:
        old_headers, _, keys = register_verified(client, "sess_reset")

        challenge = client.post(
            "/api/v2/auth/recovery/challenge", json={"username": "sess_reset"}
        ).json()["challenge"]
        new_password = "a-brand-new-password-entirely"
        payload = password_reset_signing_payload(
            username="sess_reset",
            challenge=challenge,
            new_password_digest=hashlib.sha256(new_password.encode()).digest(),
        )
        reset = client.post(
            "/api/v2/auth/recovery/reset",
            json={
                "username": "sess_reset",
                "challenge": challenge,
                "signature": b64(keys["ed_private"].sign(payload)),
                "new_password": new_password,
            },
        )
        assert reset.status_code == 200, reset.text

        # The pre-reset token is dead, and the one just issued works.
        assert client.get("/api/v2/auth/me", headers=old_headers).status_code == 401
        fresh = {"Authorization": f"Bearer {reset.json()['access_token']}"}
        assert client.get("/api/v2/auth/me", headers=fresh).status_code == 200
