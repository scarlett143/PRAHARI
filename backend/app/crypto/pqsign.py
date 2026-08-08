"""Post-quantum signatures over anchor roots (ML-DSA / FIPS 204).

WHY A SECOND SIGNATURE ALGORITHM. A Merkle root is a SHA-256 commitment, and hashes are
already fine against a quantum adversary -- Grover halves the security level, leaving 128
bits, which is not a problem. What is not fine is the *signature* saying who produced that
root and when. Anchors exist to be checked years later, which is exactly the window in
which a store-now-decrypt-later adversary becomes able to forge an ECDSA or Ed25519
signature over a root that was never anchored. A batch whose authenticity rests only on a
classical signature is a batch whose history can be rewritten in retrospect.

WHY IT IS OPTIONAL. Signing requires a key this service holds, and the deployment target
is a shared box where secret provisioning is a human step. So this follows the same shape
as the Polygon anchoring beside it: configured and it signs, unconfigured and it says so
plainly rather than pretending. An unsigned batch is still Merkle-verifiable; it simply
carries no attestation of origin.

ML-DSA-65 rather than 44 or 87: 87 is larger and slower for a margin nothing here needs,
and 44 sits at a security level below the ML-KEM-768 used everywhere else in this system.
Matching levels means the weakest link is chosen deliberately rather than by accident.
"""
from __future__ import annotations

ALGORITHM = "ML-DSA-65"


class PQSignError(RuntimeError):
    pass


def _mechanism():
    try:
        import oqs
    except ImportError as exc:  # pragma: no cover - exercised only where liboqs is absent
        raise PQSignError(
            "liboqs-python is not installed; post-quantum anchor signing is unavailable"
        ) from exc
    return oqs


def available() -> bool:
    try:
        _mechanism()
        return True
    except PQSignError:
        return False


def generate_keypair() -> tuple[bytes, bytes]:
    """Return `(public_key, secret_key)`.

    Used to provision an anchor signing key. Deliberately not called at startup: a key
    generated on boot would change every restart, and every previously signed batch would
    stop verifying against the current public key.
    """
    oqs = _mechanism()
    with oqs.Signature(ALGORITHM) as signer:
        public_key = signer.generate_keypair()
        return public_key, signer.export_secret_key()


def sign(secret_key: bytes, message: bytes) -> bytes:
    oqs = _mechanism()
    with oqs.Signature(ALGORITHM, secret_key) as signer:
        return signer.sign(message)


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        oqs = _mechanism()
    except PQSignError:
        return False
    try:
        with oqs.Signature(ALGORITHM) as verifier:
            return bool(verifier.verify(message, signature, public_key))
    except Exception:
        # A malformed key or signature is a failed verification, not a crash: this runs on
        # data supplied by whoever is asking for a proof.
        return False


#: Domain separator. Without it a signature over a Merkle root could be presented as a
#: signature over any other 32-byte value this system asks an operator to sign.
ANCHOR_LABEL = b"PRAHARI-ANCHOR-ROOT-V1\x00"


def anchor_signing_payload(*, merkle_root: bytes, leaf_count: int) -> bytes:
    """Bind the root to how many leaves it covers.

    Signing the bare root would let a batch of one message and a batch of a thousand be
    interchangeable in an attestation, which matters because the leaf count is what tells
    a verifier how much a single proof is claiming.
    """
    return ANCHOR_LABEL + leaf_count.to_bytes(8, "big") + merkle_root
