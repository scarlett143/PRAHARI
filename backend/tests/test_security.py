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


def test_passwords_hashed_under_the_old_cost_still_verify_and_are_rehashed():
    """Lowering the Argon2 cost must not lock existing accounts out.

    Argon2 encodes its parameters inside the hash, so an old password verifies against
    the cost it was created with. What must also happen is the upgrade: the stored hash
    should be reissued at the current cost on the next successful login, or the account
    keeps paying the old price forever.
    """
    from argon2 import PasswordHasher

    legacy = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=4)
    stored = legacy.hash("correct-horse-battery-staple")

    ok, rehashed = verify_password(stored, "correct-horse-battery-staple")
    assert ok, "an account created under the previous cost must still be able to log in"
    assert rehashed is not None, "the stored hash should be upgraded to the current cost"
    # And the replacement is usable in its own right.
    assert verify_password(rehashed, "correct-horse-battery-staple")[0]
    assert not verify_password(stored, "wrong-password-value")[0]


def test_jwt_roundtrip_and_expired_rejection():
    token, _ttl, jti, expires_at = issue_access_token(user_id="u1", username="alice", role="member")
    claims = decode_access_token(token)
    assert claims["sub"] == "u1"
    # The jti is what ties a token to a revocable session row, so it has to be the one
    # handed back to the caller rather than an unrelated value.
    assert claims["jti"] == jti
    assert claims["exp"] == int(expires_at.timestamp())

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
