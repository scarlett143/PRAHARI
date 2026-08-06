"""Password reset proved with the account's Ed25519 identity key.

There is no email on a User and no server-side secret that could stand in for one, so the
identity key is the only thing that can authorise a reset. These check that it genuinely
has to be that key, that a proof cannot be replayed or retargeted, and that a failed
attempt does not leave a live nonce behind.
"""
import pytest

pytest.importorskip("aiosqlite")
pytest.importorskip("kyber_py")

import hashlib

from fastapi.testclient import TestClient

from app.main import app
from app.security import password_reset_signing_payload

from test_api_flow import b64, register_verified

NEW_PASSWORD = "an-entirely-different-password"


def reset_signature(keys, username: str, challenge: str, new_password: str) -> str:
    payload = password_reset_signing_payload(
        username=username,
        challenge=challenge,
        new_password_digest=hashlib.sha256(new_password.encode()).digest(),
    )
    return b64(keys["ed_private"].sign(payload))


def get_challenge(client: TestClient, username: str) -> str:
    response = client.post("/api/v2/auth/recovery/challenge", json={"username": username})
    assert response.status_code == 200, response.text
    return response.json()["challenge"]


def test_identity_key_resets_a_forgotten_password_and_signs_in():
    with TestClient(app) as client:
        _, user, keys = register_verified(client, "recover_happy")

        challenge = get_challenge(client, "recover_happy")
        reset = client.post(
            "/api/v2/auth/recovery/reset",
            json={
                "username": "recover_happy",
                "challenge": challenge,
                "signature": reset_signature(keys, "recover_happy", challenge, NEW_PASSWORD),
                "new_password": NEW_PASSWORD,
            },
        )
        assert reset.status_code == 200, reset.text
        assert reset.json()["username"] == "recover_happy"
        # The proof is stronger than the password it replaced, so a token comes back.
        assert reset.json()["access_token"]

        # The new password works and the old one does not.
        assert client.post(
            "/api/v2/auth/login",
            json={"username": "recover_happy", "password": NEW_PASSWORD},
        ).status_code == 200
        assert client.post(
            "/api/v2/auth/login",
            json={"username": "recover_happy", "password": "correct-horse-battery-staple"},
        ).status_code == 401


def test_another_users_key_cannot_reset_this_account():
    with TestClient(app) as client:
        register_verified(client, "recover_victim")
        _, _, attacker_keys = register_verified(client, "recover_attacker")

        challenge = get_challenge(client, "recover_victim")
        response = client.post(
            "/api/v2/auth/recovery/reset",
            json={
                "username": "recover_victim",
                "challenge": challenge,
                # Correctly formed, but signed by the wrong identity.
                "signature": reset_signature(attacker_keys, "recover_victim", challenge, NEW_PASSWORD),
                "new_password": NEW_PASSWORD,
            },
        )
        assert response.status_code == 400
        assert client.post(
            "/api/v2/auth/login",
            json={"username": "recover_victim", "password": "correct-horse-battery-staple"},
        ).status_code == 200


def test_signature_is_bound_to_the_password_it_authorised():
    """A captured proof must not let someone set a password of their own choosing."""
    with TestClient(app) as client:
        _, _, keys = register_verified(client, "recover_bound")

        challenge = get_challenge(client, "recover_bound")
        signature = reset_signature(keys, "recover_bound", challenge, NEW_PASSWORD)

        response = client.post(
            "/api/v2/auth/recovery/reset",
            json={
                "username": "recover_bound",
                "challenge": challenge,
                "signature": signature,
                "new_password": "some-other-password-entirely",
            },
        )
        assert response.status_code == 400


def test_key_publication_signature_cannot_be_replayed_as_a_reset():
    """The reason the reset payload carries its own label.

    Publishing keys signs the bare challenge string. Without domain separation that same
    signature would authorise a password reset on the same challenge.
    """
    with TestClient(app) as client:
        _, _, keys = register_verified(client, "recover_replay")

        challenge = get_challenge(client, "recover_replay")
        bare_challenge_signature = b64(keys["ed_private"].sign(challenge.encode()))

        response = client.post(
            "/api/v2/auth/recovery/reset",
            json={
                "username": "recover_replay",
                "challenge": challenge,
                "signature": bare_challenge_signature,
                "new_password": NEW_PASSWORD,
            },
        )
        assert response.status_code == 400


def test_failed_proof_burns_the_challenge():
    """A live nonce must not survive a bad attempt for someone to grind against."""
    with TestClient(app) as client:
        _, _, keys = register_verified(client, "recover_burn")
        _, _, other_keys = register_verified(client, "recover_burn_other")

        challenge = get_challenge(client, "recover_burn")
        bad = client.post(
            "/api/v2/auth/recovery/reset",
            json={
                "username": "recover_burn",
                "challenge": challenge,
                "signature": reset_signature(other_keys, "recover_burn", challenge, NEW_PASSWORD),
                "new_password": NEW_PASSWORD,
            },
        )
        assert bad.status_code == 400

        # The same challenge, now with a correct signature, must no longer be accepted.
        retry = client.post(
            "/api/v2/auth/recovery/reset",
            json={
                "username": "recover_burn",
                "challenge": challenge,
                "signature": reset_signature(keys, "recover_burn", challenge, NEW_PASSWORD),
                "new_password": NEW_PASSWORD,
            },
        )
        assert retry.status_code == 400


def test_challenge_is_single_use():
    with TestClient(app) as client:
        _, _, keys = register_verified(client, "recover_once")

        challenge = get_challenge(client, "recover_once")
        first = client.post(
            "/api/v2/auth/recovery/reset",
            json={
                "username": "recover_once",
                "challenge": challenge,
                "signature": reset_signature(keys, "recover_once", challenge, NEW_PASSWORD),
                "new_password": NEW_PASSWORD,
            },
        )
        assert first.status_code == 200

        second = client.post(
            "/api/v2/auth/recovery/reset",
            json={
                "username": "recover_once",
                "challenge": challenge,
                "signature": reset_signature(keys, "recover_once", challenge, NEW_PASSWORD),
                "new_password": NEW_PASSWORD,
            },
        )
        assert second.status_code == 400


def test_challenge_endpoint_does_not_reveal_whether_an_account_exists():
    with TestClient(app) as client:
        register_verified(client, "recover_real")

        known = client.post("/api/v2/auth/recovery/challenge", json={"username": "recover_real"})
        unknown = client.post(
            "/api/v2/auth/recovery/challenge", json={"username": "no_such_operator"}
        )
        assert known.status_code == unknown.status_code == 200
        assert set(known.json()) == set(unknown.json())
        # Distinct nonces, but indistinguishable shape.
        assert known.json()["challenge"] != unknown.json()["challenge"]


def test_reset_refuses_a_short_password():
    with TestClient(app) as client:
        _, _, keys = register_verified(client, "recover_short")
        challenge = get_challenge(client, "recover_short")
        response = client.post(
            "/api/v2/auth/recovery/reset",
            json={
                "username": "recover_short",
                "challenge": challenge,
                "signature": reset_signature(keys, "recover_short", challenge, "short"),
                "new_password": "short",
            },
        )
        assert response.status_code == 422
