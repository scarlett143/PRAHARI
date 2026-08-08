"""WebAuthn verification, without a WebAuthn library.

This is normally where a dependency arrives, because the obvious implementation has to
parse an `attestationObject`: CBOR wrapping a COSE key, which is exactly the kind of
security-critical binary parsing nobody should hand-roll. `crypto/totp.py` is thirty lines
of stdlib HMAC and was worth writing; this would not have been.

It is avoided rather than written. WebAuthn Level 2 gives the browser
`AuthenticatorAttestationResponse.getPublicKey()`, which returns the credential's public
key already in SPKI DER -- the format `cryptography` loads directly. Registering a passkey
therefore never needs the attestation object at all, and verifying an assertion never did:
`authenticatorData` is a fixed binary layout, and the signature covers
`authenticatorData || SHA-256(clientDataJSON)`. Both halves reduce to stdlib plus a library
this project already depends on.

What that trades away, stated plainly because it is a real reduction in scope: attestation
statements are not verified, so the server does not learn *which* authenticator model
created a credential and cannot enforce a hardware allow-list. For a second factor
protecting an account whose messages are already encrypted with a key the server never
holds, that provenance buys very little -- and most deployments send
`attestation: "none"` regardless.

The checks that actually matter for security are all here: the challenge is server-issued
and single-use, the origin and RP ID are pinned, user presence is required, and the
signature is verified against the key registered for that credential id.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key

#: Authenticator data flag bits (WebAuthn §6.1).
FLAG_USER_PRESENT = 0x01
FLAG_USER_VERIFIED = 0x04

#: rpIdHash(32) + flags(1) + signCount(4). Anything after this is attested credential data
#: and extensions, which assertion verification does not need.
_AUTH_DATA_HEADER = 37


class WebAuthnError(ValueError):
    """Raised for every verification failure.

    One exception type, and callers turn it into one generic response. Distinguishing
    "unknown credential" from "bad signature" from "wrong origin" would let an attacker
    map which credentials exist by reading error text.
    """


def b64url_decode(value: str) -> bytes:
    """Decode base64url without padding, as WebAuthn transmits it."""
    if not isinstance(value, str):
        raise WebAuthnError("expected a base64url string")
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except Exception as exc:
        raise WebAuthnError("malformed base64url") from exc


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


@dataclass(frozen=True)
class AuthenticatorData:
    rp_id_hash: bytes
    flags: int
    sign_count: int

    @property
    def user_present(self) -> bool:
        return bool(self.flags & FLAG_USER_PRESENT)

    @property
    def user_verified(self) -> bool:
        return bool(self.flags & FLAG_USER_VERIFIED)


def parse_authenticator_data(raw: bytes) -> AuthenticatorData:
    if len(raw) < _AUTH_DATA_HEADER:
        raise WebAuthnError("authenticator data is too short")
    return AuthenticatorData(
        rp_id_hash=raw[:32],
        flags=raw[32],
        sign_count=int.from_bytes(raw[33:37], "big"),
    )


def _check_client_data(
    client_data_json: bytes, *, expected_type: str, challenge: str, origins: list[str]
) -> None:
    try:
        parsed = json.loads(client_data_json.decode("utf-8"))
    except Exception as exc:
        raise WebAuthnError("clientDataJSON is not valid JSON") from exc

    if parsed.get("type") != expected_type:
        raise WebAuthnError("wrong ceremony type")

    # Compared as the base64url text the browser echoes back, against the text we issued.
    # Constant-time because this is the anti-replay check, and a length-or-prefix timing
    # signal on a value the caller controls is worth closing.
    presented = parsed.get("challenge")
    if not isinstance(presented, str) or not _fixed_time_equal(presented, challenge):
        raise WebAuthnError("challenge does not match")

    # An exact origin match, never a suffix test: "evil-prahari.example" ends with the
    # same characters as "prahari.example" and must not pass.
    if parsed.get("origin") not in origins:
        raise WebAuthnError("origin is not allowed")

    if parsed.get("crossOrigin") is True:
        raise WebAuthnError("cross-origin ceremonies are refused")


def _fixed_time_equal(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def _check_authenticator_data(auth_data: AuthenticatorData, *, rp_id: str) -> None:
    if auth_data.rp_id_hash != hashlib.sha256(rp_id.encode("utf-8")).digest():
        raise WebAuthnError("relying party mismatch")
    # User presence means a human touched the authenticator for *this* ceremony. Without
    # it, malware on the host could drive a plugged-in key silently.
    if not auth_data.user_present:
        raise WebAuthnError("user presence was not asserted")


def verify_registration(
    *,
    client_data_json: bytes,
    authenticator_data: bytes,
    public_key_der: bytes,
    challenge: str,
    rp_id: str,
    origins: list[str],
) -> AuthenticatorData:
    """Check a newly created credential and return its authenticator data.

    `public_key_der` comes from the browser's `getPublicKey()`. It is loaded here rather
    than merely stored so a malformed or unsupported key is rejected at registration --
    the alternative is a credential that enrols cleanly and can never authenticate.
    """
    _check_client_data(
        client_data_json, expected_type="webauthn.create", challenge=challenge, origins=origins
    )
    parsed = parse_authenticator_data(authenticator_data)
    _check_authenticator_data(parsed, rp_id=rp_id)
    _load_key(public_key_der)
    return parsed


def verify_assertion(
    *,
    client_data_json: bytes,
    authenticator_data: bytes,
    signature: bytes,
    public_key_der: bytes,
    challenge: str,
    rp_id: str,
    origins: list[str],
    stored_sign_count: int,
) -> AuthenticatorData:
    """Check a login assertion. Raises `WebAuthnError` on any failure."""
    _check_client_data(
        client_data_json, expected_type="webauthn.get", challenge=challenge, origins=origins
    )
    parsed = parse_authenticator_data(authenticator_data)
    _check_authenticator_data(parsed, rp_id=rp_id)

    # WebAuthn §7.2: the signature covers the raw authenticator data concatenated with the
    # SHA-256 of clientDataJSON -- not the JSON itself.
    signed = authenticator_data + hashlib.sha256(client_data_json).digest()
    _verify_signature(_load_key(public_key_der), signature, signed)

    # A counter that goes backwards means two authenticators are answering for one
    # credential, which is what a cloned key looks like. Authenticators that do not
    # implement the counter report zero forever, and that is explicitly allowed.
    if parsed.sign_count != 0 and parsed.sign_count <= stored_sign_count:
        raise WebAuthnError("signature counter did not advance")

    return parsed


def _load_key(public_key_der: bytes):
    try:
        return load_der_public_key(public_key_der)
    except Exception as exc:
        raise WebAuthnError("unsupported or malformed credential public key") from exc


def _verify_signature(key, signature: bytes, message: bytes) -> None:
    try:
        if isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        elif isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, message)
        elif isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise WebAuthnError("unsupported credential key type")
    except InvalidSignature as exc:
        raise WebAuthnError("signature did not verify") from exc
