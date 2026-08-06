"""Two-step verification.

The interesting cases are the ones where a second factor either fails to bind (it can be
skipped) or binds too hard (it locks someone out with no way back).
"""
import pytest

pytest.importorskip("aiosqlite")
pytest.importorskip("kyber_py")

import hashlib

from fastapi.testclient import TestClient

from app.crypto import totp
from app.main import app
from app.security import password_reset_signing_payload

from test_api_flow import b64, register_verified

PASSWORD = "correct-horse-battery-staple"


def enable_totp(client: TestClient, headers) -> str:
    setup = client.post("/api/v2/auth/2fa/setup", headers=headers)
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]

    enabled = client.post(
        "/api/v2/auth/2fa/enable", headers=headers, json={"code": totp.current_code(secret)}
    )
    assert enabled.status_code == 200, enabled.text
    return secret


def test_rfc6238_vectors():
    """The published test vector, so our codes are the ones an authenticator computes."""
    # RFC 6238 Appendix B uses the ASCII secret "12345678901234567890".
    import base64

    secret = base64.b32encode(b"12345678901234567890").decode().rstrip("=")
    assert totp.current_code(secret, at=59) == "287082"
    assert totp.current_code(secret, at=1111111109) == "081804"
    assert totp.current_code(secret, at=1234567890) == "005924"


def test_codes_from_a_neighbouring_step_are_accepted_but_distant_ones_are_not():
    secret = totp.generate_secret()
    now = 1_700_000_000
    assert totp.verify(secret, totp.current_code(secret, at=now), at=now)
    # One step of drift either way, for clocks that disagree slightly.
    assert totp.verify(secret, totp.current_code(secret, at=now - 30), at=now)
    assert totp.verify(secret, totp.current_code(secret, at=now + 30), at=now)
    # Ten minutes away is not drift.
    assert not totp.verify(secret, totp.current_code(secret, at=now + 600), at=now)


def test_malformed_codes_are_rejected():
    secret = totp.generate_secret()
    for bad in ("", "abcdef", "12345", "1234567", "12 34 56"):
        assert not totp.verify(secret, bad)


def test_setup_alone_does_not_start_requiring_a_code():
    """An abandoned setup must not become a factor the account is judged against."""
    with TestClient(app) as client:
        headers, _, _ = register_verified(client, "tfa_pending")
        client.post("/api/v2/auth/2fa/setup", headers=headers).raise_for_status()

        # No confirmation, so the password alone still signs in.
        response = client.post(
            "/api/v2/auth/login", json={"username": "tfa_pending", "password": PASSWORD}
        )
        assert response.status_code == 200
        assert response.json()["access_token"]


def test_enable_requires_a_correct_code():
    with TestClient(app) as client:
        headers, _, _ = register_verified(client, "tfa_badcode")
        client.post("/api/v2/auth/2fa/setup", headers=headers).raise_for_status()

        response = client.post("/api/v2/auth/2fa/enable", headers=headers, json={"code": "000000"})
        assert response.status_code == 400
        assert client.get("/api/v2/auth/me", headers=headers).json()["totp_enabled"] is False


def test_login_demands_the_second_factor_once_enabled():
    with TestClient(app) as client:
        headers, _, _ = register_verified(client, "tfa_login")
        secret = enable_totp(client, headers)
        assert client.get("/api/v2/auth/me", headers=headers).json()["totp_enabled"] is True

        # The correct password on its own is no longer enough.
        without = client.post(
            "/api/v2/auth/login", json={"username": "tfa_login", "password": PASSWORD}
        )
        assert without.status_code == 401
        assert without.json()["detail"]["code"] == "totp_required"

        wrong = client.post(
            "/api/v2/auth/login",
            json={"username": "tfa_login", "password": PASSWORD, "totp_code": "000000"},
        )
        assert wrong.status_code == 401

        good = client.post(
            "/api/v2/auth/login",
            json={
                "username": "tfa_login",
                "password": PASSWORD,
                "totp_code": totp.current_code(secret),
            },
        )
        assert good.status_code == 200, good.text


def test_a_valid_code_cannot_stand_in_for_the_password():
    with TestClient(app) as client:
        headers, _, _ = register_verified(client, "tfa_nopass")
        secret = enable_totp(client, headers)

        response = client.post(
            "/api/v2/auth/login",
            json={
                "username": "tfa_nopass",
                "password": "the-wrong-password-entirely",
                "totp_code": totp.current_code(secret),
            },
        )
        assert response.status_code == 401


def test_disabling_needs_password_and_code_together():
    with TestClient(app) as client:
        headers, _, _ = register_verified(client, "tfa_disable")
        secret = enable_totp(client, headers)

        # An open session is not on its own enough to switch protection off.
        assert client.post(
            "/api/v2/auth/2fa/disable",
            headers=headers,
            json={"password": "wrong-password-here", "code": totp.current_code(secret)},
        ).status_code == 400
        assert client.post(
            "/api/v2/auth/2fa/disable",
            headers=headers,
            json={"password": PASSWORD, "code": "000000"},
        ).status_code == 400
        assert client.get("/api/v2/auth/me", headers=headers).json()["totp_enabled"] is True

        both = client.post(
            "/api/v2/auth/2fa/disable",
            headers=headers,
            json={"password": PASSWORD, "code": totp.current_code(secret)},
        )
        assert both.status_code == 200
        assert client.get("/api/v2/auth/me", headers=headers).json()["totp_enabled"] is False


def test_identity_key_reset_clears_the_second_factor():
    """A lost authenticator has to be recoverable, and the identity key outranks it.

    The key is what decrypts the messages the second factor exists to protect, so
    requiring both would add no security and would make the loss permanent.
    """
    with TestClient(app) as client:
        headers, _, keys = register_verified(client, "tfa_reset")
        enable_totp(client, headers)

        challenge = client.post(
            "/api/v2/auth/recovery/challenge", json={"username": "tfa_reset"}
        ).json()["challenge"]
        new_password = "a-completely-new-password"
        payload = password_reset_signing_payload(
            username="tfa_reset",
            challenge=challenge,
            new_password_digest=hashlib.sha256(new_password.encode()).digest(),
        )
        reset = client.post(
            "/api/v2/auth/recovery/reset",
            json={
                "username": "tfa_reset",
                "challenge": challenge,
                "signature": b64(keys["ed_private"].sign(payload)),
                "new_password": new_password,
            },
        )
        assert reset.status_code == 200, reset.text

        # Back in with the new password and no code.
        again = client.post(
            "/api/v2/auth/login", json={"username": "tfa_reset", "password": new_password}
        )
        assert again.status_code == 200, again.text
        assert again.json()["access_token"]
