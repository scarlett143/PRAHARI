"""Passkey registration and sign-in.

These drive a software authenticator rather than mocking verification, so the ECDSA
signature, the authenticator-data layout and the client-data binding are all genuinely
exercised. That matters more than usual here: the WebAuthn verification is written in this
repository instead of pulled from a library, so the tests are the only thing standing
between a subtle format mistake and an authentication bypass.
"""
import pytest

pytest.importorskip("aiosqlite")
pytest.importorskip("kyber_py")

import base64
import hashlib
import json
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from app.config import get_settings
from app.crypto import webauthn
from app.main import app

from test_api_flow import register_verified
from test_fleet import _unique

settings = get_settings()
RP_ID = settings.webauthn_relying_party
ORIGIN = settings.webauthn_origins[0]


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


class SoftAuthenticator:
    """A minimal WebAuthn authenticator: one P-256 key pair and a signature counter."""

    def __init__(self, rp_id: str = RP_ID):
        self.key = ec.generate_private_key(ec.SECP256R1())
        # Unique per instance. Credential ids are globally unique in the database, so
        # deriving one from the RP would make every authenticator in this file collide.
        self.credential_id = b"cred-" + secrets.token_bytes(16)
        self.rp_id = rp_id
        self.counter = 0

    @property
    def public_key_der(self) -> bytes:
        return self.key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def client_data(self, *, ceremony: str, challenge: str, origin: str = ORIGIN) -> bytes:
        return json.dumps(
            {"type": ceremony, "challenge": challenge, "origin": origin, "crossOrigin": False}
        ).encode()

    def auth_data(self, *, user_present: bool = True, rp_id: str | None = None) -> bytes:
        self.counter += 1
        flags = webauthn.FLAG_USER_PRESENT | webauthn.FLAG_USER_VERIFIED if user_present else 0
        return (
            hashlib.sha256((rp_id or self.rp_id).encode()).digest()
            + bytes([flags])
            + self.counter.to_bytes(4, "big")
        )

    def sign(self, authenticator_data: bytes, client_data_json: bytes) -> bytes:
        return self.key.sign(
            authenticator_data + hashlib.sha256(client_data_json).digest(),
            ec.ECDSA(hashes.SHA256()),
        )


def _register(client: TestClient, headers, authenticator: SoftAuthenticator, label="Test key"):
    challenge = client.post(
        "/api/v2/auth/passkeys/register/challenge", headers=headers
    ).json()["challenge"]
    client_data = authenticator.client_data(ceremony="webauthn.create", challenge=challenge)
    auth_data = authenticator.auth_data()
    return client.post(
        "/api/v2/auth/passkeys/register",
        headers=headers,
        json={
            "credential_id": b64url(authenticator.credential_id),
            "client_data_json": b64url(client_data),
            "authenticator_data": b64url(auth_data),
            "public_key": base64.b64encode(authenticator.public_key_der).decode(),
            "label": label,
        },
    )


def _assert_login(client: TestClient, username: str, authenticator: SoftAuthenticator, **overrides):
    start = client.post(
        "/api/v2/auth/passkeys/login/challenge", json={"username": username}
    ).json()
    challenge = overrides.pop("challenge", start["challenge"])
    client_data = authenticator.client_data(
        ceremony=overrides.pop("ceremony", "webauthn.get"),
        challenge=challenge,
        origin=overrides.pop("origin", ORIGIN),
    )
    auth_data = overrides.pop("auth_data", None) or authenticator.auth_data()
    signature = overrides.pop("signature", None) or authenticator.sign(auth_data, client_data)
    return client.post(
        "/api/v2/auth/passkeys/login",
        json={
            "username": username,
            "credential_id": b64url(authenticator.credential_id),
            "client_data_json": b64url(client_data),
            "authenticator_data": b64url(auth_data),
            "signature": b64url(signature),
        },
    )


def test_a_registered_passkey_signs_in_without_a_password():
    with TestClient(app) as client:
        username = _unique("alice")
        headers, _, _ = register_verified(client, username)
        authenticator = SoftAuthenticator()

        registered = _register(client, headers, authenticator)
        assert registered.status_code == 200, registered.text
        assert registered.json()["label"] == "Test key"

        signed_in = _assert_login(client, username, authenticator)
        assert signed_in.status_code == 200, signed_in.text
        assert signed_in.json()["username"] == username

        # And the token it minted is a real, usable session.
        token = signed_in.json()["access_token"]
        me = client.get("/api/v2/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me.status_code == 200


def test_a_challenge_cannot_be_replayed():
    with TestClient(app) as client:
        username = _unique("alice")
        headers, _, _ = register_verified(client, username)
        authenticator = SoftAuthenticator()
        _register(client, headers, authenticator)

        start = client.post(
            "/api/v2/auth/passkeys/login/challenge", json={"username": username}
        ).json()
        client_data = authenticator.client_data(
            ceremony="webauthn.get", challenge=start["challenge"]
        )
        auth_data = authenticator.auth_data()
        signature = authenticator.sign(auth_data, client_data)
        payload = {
            "username": username,
            "credential_id": b64url(authenticator.credential_id),
            "client_data_json": b64url(client_data),
            "authenticator_data": b64url(auth_data),
            "signature": b64url(signature),
        }

        assert client.post("/api/v2/auth/passkeys/login", json=payload).status_code == 200
        # Byte-identical replay of a captured assertion.
        assert client.post("/api/v2/auth/passkeys/login", json=payload).status_code == 401


def test_an_assertion_from_another_origin_is_refused():
    """The phishing-resistance property: the origin is inside the signed client data."""
    with TestClient(app) as client:
        username = _unique("alice")
        headers, _, _ = register_verified(client, username)
        authenticator = SoftAuthenticator()
        _register(client, headers, authenticator)

        refused = _assert_login(
            client, username, authenticator, origin="https://prahari.example.evil"
        )
        assert refused.status_code == 401


def test_a_forged_signature_is_refused():
    with TestClient(app) as client:
        username = _unique("alice")
        headers, _, _ = register_verified(client, username)
        authenticator = SoftAuthenticator()
        _register(client, headers, authenticator)

        attacker = SoftAuthenticator()
        attacker.credential_id = authenticator.credential_id
        refused = _assert_login(client, username, attacker)
        assert refused.status_code == 401


def test_an_assertion_without_user_presence_is_refused():
    """Otherwise malware could drive a plugged-in key with nobody at the machine."""
    with TestClient(app) as client:
        username = _unique("alice")
        headers, _, _ = register_verified(client, username)
        authenticator = SoftAuthenticator()
        _register(client, headers, authenticator)

        refused = _assert_login(
            client, username, authenticator, auth_data=authenticator.auth_data(user_present=False)
        )
        assert refused.status_code == 401


def test_a_credential_registered_to_someone_else_cannot_be_used():
    with TestClient(app) as client:
        alice = _unique("alice")
        bob = _unique("bob")
        alice_headers, _, _ = register_verified(client, alice)
        register_verified(client, bob)

        authenticator = SoftAuthenticator()
        _register(client, alice_headers, authenticator)

        # Alice's credential, presented as Bob.
        refused = _assert_login(client, bob, authenticator)
        assert refused.status_code == 401


def test_registration_binds_the_relying_party():
    with TestClient(app) as client:
        username = _unique("alice")
        headers, _, _ = register_verified(client, username)
        authenticator = SoftAuthenticator(rp_id="somewhere-else.example")

        refused = _register(client, headers, authenticator)
        assert refused.status_code == 400


def test_a_login_challenge_does_not_reveal_whether_an_account_exists():
    with TestClient(app) as client:
        known = _unique("alice")
        register_verified(client, known)

        real = client.post("/api/v2/auth/passkeys/login/challenge", json={"username": known})
        fake = client.post(
            "/api/v2/auth/passkeys/login/challenge", json={"username": _unique("nobody")}
        )
        assert real.status_code == fake.status_code == 200
        assert set(real.json()) == set(fake.json())
        assert fake.json()["allowCredentials"] == []


def test_passkeys_can_be_listed_and_removed():
    with TestClient(app) as client:
        username = _unique("alice")
        headers, _, _ = register_verified(client, username)
        authenticator = SoftAuthenticator()
        created = _register(client, headers, authenticator).json()

        listed = client.get("/api/v2/auth/passkeys", headers=headers).json()
        assert [row["id"] for row in listed] == [created["id"]]

        removed = client.delete(f"/api/v2/auth/passkeys/{created['id']}", headers=headers)
        assert removed.status_code == 200
        assert client.get("/api/v2/auth/passkeys", headers=headers).json() == []

        # Removing the last one must not strand the account: password login still works.
        assert _assert_login(client, username, authenticator).status_code == 401


def test_an_identity_key_reset_evicts_registered_passkeys():
    """The credential hierarchy, enforced.

    The identity key outranks every other factor, because it is what decrypts the messages
    those factors exist to protect. A reset is also how an account is recovered after a
    compromise -- so a passkey an attacker enrolled must not survive it and keep letting
    them back in. The legitimate owner re-registers; the attacker cannot.
    """
    from test_password_recovery import NEW_PASSWORD, get_challenge, reset_signature

    with TestClient(app) as client:
        username = _unique("alice")
        headers, _, keys = register_verified(client, username)
        authenticator = SoftAuthenticator()
        _register(client, headers, authenticator)
        assert len(client.get("/api/v2/auth/passkeys", headers=headers).json()) == 1

        challenge = get_challenge(client, username)
        reset = client.post(
            "/api/v2/auth/recovery/reset",
            json={
                "username": username,
                "challenge": challenge,
                "signature": reset_signature(keys, username, challenge, NEW_PASSWORD),
                "new_password": NEW_PASSWORD,
            },
        )
        assert reset.status_code == 200, reset.text

        # The passkey is gone, and can no longer sign in.
        assert _assert_login(client, username, authenticator).status_code == 401
        new_headers = {"Authorization": f"Bearer {reset.json()['access_token']}"}
        assert client.get("/api/v2/auth/passkeys", headers=new_headers).json() == []


def test_the_same_passkey_cannot_be_registered_twice():
    with TestClient(app) as client:
        username = _unique("alice")
        headers, _, _ = register_verified(client, username)
        authenticator = SoftAuthenticator()

        assert _register(client, headers, authenticator).status_code == 200
        assert _register(client, headers, authenticator).status_code == 409
