"""Hybrid certificates.

The property everything rests on is that **both** signatures must verify. If either alone
sufficed, the chain would be exactly as strong as whichever algorithm breaks first, since
an attacker picks which to forge. Several tests below exist only to hold that line.
"""
import pytest

pytest.importorskip("aiosqlite")

from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from app import pki
from app.crypto import pqsign

pytestmark = pytest.mark.skipif(
    not pqsign.available(), reason="liboqs-python is not installed in this environment"
)

NOW = datetime(2026, 8, 8, 12, 0, tzinfo=timezone.utc)


class Authority:
    """Someone who can sign certificates: one Ed25519 key and one ML-DSA key."""

    def __init__(self, name: str):
        self.name = name
        self.ed = Ed25519PrivateKey.generate()
        self.pq_public, self._pq_secret = pqsign.generate_keypair()

    @property
    def ed_public(self) -> bytes:
        return self.ed.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def sign(self, body: pki.CertificateBody) -> tuple[bytes, bytes]:
        payload = pki.signing_payload(body)
        return self.ed.sign(payload), pqsign.sign(self._pq_secret, payload)


def body_for(
    subject: Authority,
    *,
    serial: str,
    issuer_serial: str,
    is_ca: bool = False,
    not_before: datetime = NOW - timedelta(days=1),
    not_after: datetime = NOW + timedelta(days=365),
) -> pki.CertificateBody:
    return pki.CertificateBody(
        serial=serial,
        issuer_serial=issuer_serial,
        subject_id=f"id-{serial}",
        subject_name=subject.name,
        is_ca=is_ca,
        ed25519_public_key=subject.ed_public,
        mldsa_public_key=subject.pq_public,
        not_before=not_before,
        not_after=not_after,
    )


def entry(body, issuer: Authority, revoked_at=None) -> dict:
    ed_sig, pq_sig = issuer.sign(body)
    return {
        "body": body,
        "ed25519_signature": ed_sig,
        "mldsa_signature": pq_sig,
        "revoked_at": revoked_at,
    }


def test_a_correctly_signed_certificate_verifies():
    issuer = Authority("Root")
    subject = Authority("Device")
    body = body_for(subject, serial="s1", issuer_serial="root")
    ed_sig, pq_sig = issuer.sign(body)

    pki.verify_certificate(
        body,
        ed25519_signature=ed_sig,
        mldsa_signature=pq_sig,
        issuer_ed25519_public_key=issuer.ed_public,
        issuer_mldsa_public_key=issuer.pq_public,
    )


def test_a_valid_ed25519_signature_alone_is_not_enough():
    """The point of the whole design: a quantum adversary forges the classical half."""
    issuer = Authority("Root")
    forger = Authority("Forger")
    subject = Authority("Device")
    body = body_for(subject, serial="s1", issuer_serial="root")

    real_ed, _ = issuer.sign(body)
    _, wrong_pq = forger.sign(body)

    with pytest.raises(pki.CertificateError, match="ML-DSA"):
        pki.verify_certificate(
            body,
            ed25519_signature=real_ed,
            mldsa_signature=wrong_pq,
            issuer_ed25519_public_key=issuer.ed_public,
            issuer_mldsa_public_key=issuer.pq_public,
        )


def test_a_valid_mldsa_signature_alone_is_not_enough():
    """And the mirror image: a classical break must not be enough either."""
    issuer = Authority("Root")
    forger = Authority("Forger")
    subject = Authority("Device")
    body = body_for(subject, serial="s1", issuer_serial="root")

    wrong_ed, _ = forger.sign(body)
    _, real_pq = issuer.sign(body)

    with pytest.raises(pki.CertificateError, match="Ed25519"):
        pki.verify_certificate(
            body,
            ed25519_signature=wrong_ed,
            mldsa_signature=real_pq,
            issuer_ed25519_public_key=issuer.ed_public,
            issuer_mldsa_public_key=issuer.pq_public,
        )


def test_altering_any_field_invalidates_both_signatures():
    issuer = Authority("Root")
    subject = Authority("Device")
    body = body_for(subject, serial="s1", issuer_serial="root")
    ed_sig, pq_sig = issuer.sign(body)

    # Promoting a leaf to a CA is the alteration that would matter most.
    tampered = pki.CertificateBody(**{**body.__dict__, "is_ca": True})
    with pytest.raises(pki.CertificateError):
        pki.verify_certificate(
            tampered,
            ed25519_signature=ed_sig,
            mldsa_signature=pq_sig,
            issuer_ed25519_public_key=issuer.ed_public,
            issuer_mldsa_public_key=issuer.pq_public,
        )


def test_the_payload_binds_field_boundaries():
    """Two certificates whose fields concatenate alike must not share a signature."""
    subject = Authority("x")
    left = pki.signing_payload(
        pki.CertificateBody("ab", "c", "s", "n", False, subject.ed_public, subject.pq_public, NOW, NOW)
    )
    right = pki.signing_payload(
        pki.CertificateBody("a", "bc", "s", "n", False, subject.ed_public, subject.pq_public, NOW, NOW)
    )
    assert left != right


def test_validity_windows_are_enforced():
    subject = Authority("Device")
    future = body_for(
        subject, serial="s1", issuer_serial="root",
        not_before=NOW + timedelta(days=1), not_after=NOW + timedelta(days=2),
    )
    with pytest.raises(pki.CertificateError, match="not valid yet"):
        pki.check_validity(future, at=NOW)

    expired = body_for(
        subject, serial="s2", issuer_serial="root",
        not_before=NOW - timedelta(days=10), not_after=NOW - timedelta(days=1),
    )
    with pytest.raises(pki.CertificateError, match="expired"):
        pki.check_validity(expired, at=NOW)

    backwards = body_for(
        subject, serial="s3", issuer_serial="root",
        not_before=NOW + timedelta(days=1), not_after=NOW - timedelta(days=1),
    )
    with pytest.raises(pki.CertificateError, match="ends before it begins"):
        pki.check_validity(backwards, at=NOW)


def _three_link_chain():
    root, intermediate, leaf = Authority("Root"), Authority("Issuing CA"), Authority("Device")
    root_body = body_for(root, serial="root", issuer_serial="root", is_ca=True)
    mid_body = body_for(intermediate, serial="mid", issuer_serial="root", is_ca=True)
    leaf_body = body_for(leaf, serial="leaf", issuer_serial="mid")
    chain = [entry(leaf_body, intermediate), entry(mid_body, root), entry(root_body, root)]
    return chain, {"root"}


def test_a_full_chain_verifies_to_a_trusted_root():
    chain, trusted = _three_link_chain()
    pki.verify_chain(chain, trusted_roots=trusted, at=NOW)


def test_a_chain_ending_at_an_untrusted_root_is_refused():
    """Anyone can self-sign, so terminating outside the pinned set proves nothing."""
    chain, _ = _three_link_chain()
    with pytest.raises(pki.CertificateError, match="not trusted"):
        pki.verify_chain(chain, trusted_roots=set(), at=NOW)


def test_a_leaf_cannot_act_as_an_issuer():
    root, leaf_ca, leaf = Authority("Root"), Authority("Not a CA"), Authority("Device")
    root_body = body_for(root, serial="root", issuer_serial="root", is_ca=True)
    # Issued as an ordinary end-entity certificate, then used to sign another.
    mid_body = body_for(leaf_ca, serial="mid", issuer_serial="root", is_ca=False)
    leaf_body = body_for(leaf, serial="leaf", issuer_serial="mid")
    chain = [entry(leaf_body, leaf_ca), entry(mid_body, root), entry(root_body, root)]

    with pytest.raises(pki.CertificateError, match="not permitted to issue"):
        pki.verify_chain(chain, trusted_roots={"root"}, at=NOW)


def test_revoking_a_link_breaks_the_chain_beneath_it():
    root, intermediate, leaf = Authority("Root"), Authority("Issuing CA"), Authority("Device")
    root_body = body_for(root, serial="root", issuer_serial="root", is_ca=True)
    mid_body = body_for(intermediate, serial="mid", issuer_serial="root", is_ca=True)
    leaf_body = body_for(leaf, serial="leaf", issuer_serial="mid")
    chain = [
        entry(leaf_body, intermediate),
        entry(mid_body, root, revoked_at=NOW),
        entry(root_body, root),
    ]

    with pytest.raises(pki.CertificateError, match="revoked"):
        pki.verify_chain(chain, trusted_roots={"root"}, at=NOW)


def test_a_non_contiguous_chain_is_refused():
    root, intermediate, leaf = Authority("Root"), Authority("Issuing CA"), Authority("Device")
    root_body = body_for(root, serial="root", issuer_serial="root", is_ca=True)
    mid_body = body_for(intermediate, serial="other", issuer_serial="root", is_ca=True)
    leaf_body = body_for(leaf, serial="leaf", issuer_serial="mid")  # names an absent issuer
    chain = [entry(leaf_body, intermediate), entry(mid_body, root), entry(root_body, root)]

    with pytest.raises(pki.CertificateError, match="not contiguous"):
        pki.verify_chain(chain, trusted_roots={"root"}, at=NOW)


def test_a_self_issued_certificate_may_only_end_a_chain():
    root, other = Authority("Root"), Authority("Other root")
    root_body = body_for(root, serial="root", issuer_serial="root", is_ca=True)
    other_body = body_for(other, serial="other", issuer_serial="other", is_ca=True)
    # A self-signed certificate sitting in the middle: valid on its own, meaningless here.
    chain = [entry(other_body, other), entry(root_body, root)]

    with pytest.raises(pki.CertificateError, match="may only end the chain"):
        pki.verify_chain(chain, trusted_roots={"root"}, at=NOW)


def test_an_expired_link_invalidates_the_chain():
    root, leaf = Authority("Root"), Authority("Device")
    root_body = body_for(root, serial="root", issuer_serial="root", is_ca=True)
    leaf_body = body_for(
        leaf, serial="leaf", issuer_serial="root",
        not_before=NOW - timedelta(days=10), not_after=NOW - timedelta(days=1),
    )
    chain = [entry(leaf_body, root), entry(root_body, root)]

    with pytest.raises(pki.CertificateError, match="expired"):
        pki.verify_chain(chain, trusted_roots={"root"}, at=NOW)


def test_an_empty_chain_is_refused():
    with pytest.raises(pki.CertificateError, match="empty"):
        pki.verify_chain([], trusted_roots={"root"}, at=NOW)
