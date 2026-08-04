from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import HTTPException

from app.config import get_settings
from app.security import (
    bundle_signing_payload,
    decode_access_token,
    hash_password,
    issue_access_token,
    session_offer_signing_payload,
    verify_key_ownership,
    verify_password,
    verify_signature,
)


def test_argon2id_password_hashing_and_verification():
    stored = hash_password("correct-horse-battery-staple")
    assert "argon2id" in stored
    assert verify_password(stored, "correct-horse-battery-staple")[0]
    assert not verify_password(stored, "wrong-password-value")[0]


def test_jwt_roundtrip_and_expired_rejection():
    token, _ = issue_access_token(user_id="u1", username="alice", role="member")
    assert decode_access_token(token)["sub"] == "u1"

    settings = get_settings()
    now = datetime.now(timezone.utc)
    expired = jwt.encode(
        {
            "sub": "u1",
            "username": "alice",
            "role": "member",
            "iat": int((now - timedelta(hours=2)).timestamp()),
            "exp": int((now - timedelta(hours=1)).timestamp()),
            "iss": "prahari",
            "aud": "prahari-api",
        },
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )
    with pytest.raises(HTTPException) as exc:
        decode_access_token(expired)
    assert exc.value.status_code == 401


def test_ed25519_challenge_and_bundle_signatures():
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    challenge = "challenge-value"
    assert verify_key_ownership(
        ed25519_public_key=public,
        challenge=challenge,
        signature=private.sign(challenge.encode()),
    )
    payload = bundle_signing_payload(x25519_public_key=b"x" * 32, ml_kem_encapsulation_key=b"k" * 1184)
    assert verify_signature(ed25519_public_key=public, message=payload, signature=private.sign(payload))
    assert not verify_signature(ed25519_public_key=public, message=payload + b"!", signature=private.sign(payload))

    offer_payload = session_offer_signing_payload(
        channel_id="channel-1",
        key_epoch=3,
        responder_id="user-b",
        x25519_ephemeral_public=b"e" * 32,
        ml_kem_ciphertext=b"c" * 1088,
    )
    assert verify_signature(
        ed25519_public_key=public, message=offer_payload, signature=private.sign(offer_payload)
    )
