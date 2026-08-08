"""Hybrid certificates: every signature is made twice, and both must verify.

WHY DUAL RATHER THAN A CHOICE. A certificate issued today may still be load-bearing in ten
years, which is long enough that betting the chain on one signature algorithm is a bet on
which of two failures arrives first. Ed25519 falls to a quantum adversary; ML-DSA is young
enough that a classical break is not unthinkable. So every certificate here carries both,
over identical bytes, and verification requires **both** to pass.

That "both" is the entire design and the easiest thing to get wrong. Accepting either
signature would make the chain exactly as strong as the *weaker* algorithm, since an
attacker picks which one to forge -- the opposite of the intended property. Requiring both
makes it as strong as the stronger one. `verify_certificate` therefore has no early
success path, and the tests assert that a certificate with one good signature and one bad
is rejected regardless of which is which.

WHERE THE ISSUING KEYS LIVE. Not here. This service stores certificates, verifies them,
and serves them; it never mints one. A certificate arrives already signed by whoever holds
the issuer's private keys, is re-verified on the way in, and is stored only if it checks
out. A relay that could issue a certificate could impersonate anyone the chain vouches
for, which is precisely the authority this design withholds -- the same rule that keeps it
unable to read a message.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

from .crypto import pqsign
from .crypto.identity import verify_ed25519_signature

VERSION = 1
#: Domain separator. Without it a certificate body is just bytes, and a signature over one
#: could be presented as a signature over anything else this system asks a key to sign.
CERT_LABEL = b"PRAHARI-HYBRID-CERT-V1\x00"


class CertificateError(ValueError):
    pass


@dataclass(frozen=True)
class CertificateBody:
    """Everything a signature commits to. Changing any field invalidates both signatures."""

    serial: str
    issuer_serial: str
    subject_id: str
    subject_name: str
    is_ca: bool
    ed25519_public_key: bytes
    mldsa_public_key: bytes
    not_before: datetime
    not_after: datetime


def _stamp(value: datetime) -> str:
    """UTC, second precision, no offset spelling variation.

    Timestamps go into signed bytes, so two encodings of the same instant would produce
    two different signatures over what is meant to be one certificate.
    """
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def signing_payload(body: CertificateBody) -> bytes:
    """Canonical bytes both algorithms sign.

    Length-prefixed throughout. Without prefixes a subject named "ab" issued by "c" and one
    named "a" issued by "bc" concatenate identically, and one certificate's signature would
    verify against the other.
    """
    parts = [CERT_LABEL, VERSION.to_bytes(4, "big")]
    for field in (
        body.serial.encode("utf-8"),
        body.issuer_serial.encode("utf-8"),
        body.subject_id.encode("utf-8"),
        body.subject_name.encode("utf-8"),
        b"\x01" if body.is_ca else b"\x00",
        body.ed25519_public_key,
        body.mldsa_public_key,
        _stamp(body.not_before).encode("ascii"),
        _stamp(body.not_after).encode("ascii"),
    ):
        parts.append(len(field).to_bytes(4, "big"))
        parts.append(field)
    return b"".join(parts)


def fingerprint(body: CertificateBody) -> bytes:
    """SHA-256 over the signed bytes. Stable identifier for pinning and comparison."""
    return hashlib.sha256(signing_payload(body)).digest()


def verify_certificate(
    body: CertificateBody,
    *,
    ed25519_signature: bytes,
    mldsa_signature: bytes,
    issuer_ed25519_public_key: bytes,
    issuer_mldsa_public_key: bytes,
) -> None:
    """Raise unless *both* signatures verify against the issuer's keys.

    Deliberately written without an early return on the first success. The whole value of
    a hybrid certificate is that forging it requires breaking two unrelated problems, and
    a short-circuit that accepted one would silently reduce that to breaking the easier.
    """
    payload = signing_payload(body)

    classical_ok = verify_ed25519_signature(
        public_key=issuer_ed25519_public_key, message=payload, signature=ed25519_signature
    )
    post_quantum_ok = pqsign.verify(issuer_mldsa_public_key, payload, mldsa_signature)

    if not classical_ok and not post_quantum_ok:
        raise CertificateError("neither signature verifies")
    if not classical_ok:
        raise CertificateError("the Ed25519 signature does not verify")
    if not post_quantum_ok:
        # Reported distinctly from the classical failure because the operational response
        # differs: a broken ML-DSA signature on an otherwise valid certificate usually
        # means the issuer signed with a mismatched or older post-quantum key.
        raise CertificateError("the ML-DSA signature does not verify")


def check_validity(body: CertificateBody, *, at: datetime | None = None) -> None:
    moment = at or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)

    not_before = body.not_before
    not_after = body.not_after
    if not_before.tzinfo is None:
        not_before = not_before.replace(tzinfo=timezone.utc)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)

    if not_after <= not_before:
        raise CertificateError("the validity window ends before it begins")
    if moment < not_before:
        raise CertificateError("this certificate is not valid yet")
    if moment >= not_after:
        raise CertificateError("this certificate has expired")


def verify_chain(chain: list[dict], *, trusted_roots: set[str], at: datetime | None = None) -> None:
    """Walk end-entity → issuer → root.

    `chain` is ordered leaf first, each entry carrying a `body` and its two signatures.
    Every link is checked in full: both signatures, the validity window, revocation, and
    that the issuer was actually permitted to issue.
    """
    if not chain:
        raise CertificateError("empty chain")

    for depth, entry in enumerate(chain):
        body: CertificateBody = entry["body"]
        check_validity(body, at=at)
        if entry.get("revoked_at") is not None:
            raise CertificateError(f"{body.subject_name} has been revoked")

        is_root = body.issuer_serial == body.serial
        if is_root:
            if depth != len(chain) - 1:
                raise CertificateError("a self-issued certificate may only end the chain")
            if body.serial not in trusted_roots:
                # An untrusted root is the ordinary failure, not an exotic one: anyone can
                # self-sign, so a chain terminating outside the pinned set proves nothing.
                raise CertificateError("the chain ends at a root that is not trusted")
            issuer = body
        else:
            if depth + 1 >= len(chain):
                raise CertificateError("the chain stops before reaching a root")
            issuer = chain[depth + 1]["body"]
            if issuer.serial != body.issuer_serial:
                raise CertificateError("the chain is not contiguous")
            if not issuer.is_ca:
                # Without this an ordinary end-entity certificate could sign others, and
                # anyone issued a leaf could mint a chain for any name they liked.
                raise CertificateError(f"{issuer.subject_name} is not permitted to issue")

        verify_certificate(
            body,
            ed25519_signature=entry["ed25519_signature"],
            mldsa_signature=entry["mldsa_signature"],
            issuer_ed25519_public_key=issuer.ed25519_public_key,
            issuer_mldsa_public_key=issuer.mldsa_public_key,
        )
