"""The key transparency log.

What this closes, precisely. A key bundle is signed by its owner's Ed25519 identity key,
so the relay has never been able to *fabricate* one -- it cannot produce the signature.
What it could do until now was quieter: serve an older bundle than the current one, or
serve a bundle belonging to a different identity, and nothing in the record would
disagree. The account row held one bundle and no history, so "this is their key" and
"this became their key an hour ago" looked identical.

Appending every publish to a per-user hash chain makes the second class of answer
checkable. Each entry commits to the one before it, so removing, reordering or editing an
entry invalidates every hash after it, and a client that has seen an earlier chain state
can prove the relay has changed its story.

Say the limit as plainly as the property. A log makes a *changed* answer detectable; it
does nothing about a *first* answer. On first contact there is no prior state to compare
against, so the safety-number comparison in crypto/verification.js remains the only thing
that establishes who you are actually talking to. Transparency turns silent substitution
into visible history -- it does not remove the need to check a fingerprint once.
"""
from __future__ import annotations

import hashlib

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import KeyBundleRecord

#: Domain separator. Without it, a digest computed here could be replayed as a Merkle leaf
#: from blockchain/anchor.py, which hashes with a `\x00` prefix over arbitrary bytes.
_DOMAIN = b"prahari-key-transparency-v1"


def entry_hash(
    *,
    prev_hash: bytes | None,
    user_id: str,
    seq: int,
    ed25519_public_key: bytes,
    x25519_public_key: bytes,
    ml_kem_encapsulation_key: bytes,
) -> bytes:
    """Commit to one bundle and to everything published before it.

    Lengths are written before the variable-length fields rather than relying on
    concatenation. Without them, two different bundles could produce identical input --
    the classic boundary ambiguity where moving bytes from the end of one field to the
    start of the next leaves the joined string unchanged.
    """
    digest = hashlib.sha256()
    digest.update(_DOMAIN)
    digest.update(prev_hash or b"\x00" * 32)
    for field in (user_id.encode("utf-8"), ed25519_public_key, x25519_public_key, ml_kem_encapsulation_key):
        digest.update(len(field).to_bytes(4, "big"))
        digest.update(field)
    digest.update(seq.to_bytes(8, "big"))
    return digest.digest()


async def latest_record(db: AsyncSession, user_id: str) -> KeyBundleRecord | None:
    return (
        await db.execute(
            select(KeyBundleRecord)
            .where(KeyBundleRecord.user_id == user_id)
            .order_by(KeyBundleRecord.seq.desc())
            .limit(1)
        )
    ).scalars().first()


async def append_bundle(
    db: AsyncSession,
    *,
    user_id: str,
    ed25519_public_key: bytes,
    x25519_public_key: bytes,
    ml_kem_encapsulation_key: bytes,
    bundle_signature: bytes,
) -> KeyBundleRecord:
    """Add one bundle to a user's chain. The caller commits.

    Republishing an identical bundle is not appended. A client that re-runs enrolment, or
    reconnects and publishes again, would otherwise fill its own history with entries that
    record no change -- and a history where most rows mean "nothing happened" is one
    nobody reads closely enough to notice the row that does.
    """
    previous = await latest_record(db, user_id)
    if (
        previous is not None
        and previous.ed25519_public_key == ed25519_public_key
        and previous.x25519_public_key == x25519_public_key
        and previous.ml_kem_encapsulation_key == ml_kem_encapsulation_key
    ):
        return previous

    seq = (previous.seq if previous else 0) + 1
    record = KeyBundleRecord(
        user_id=user_id,
        seq=seq,
        ed25519_public_key=ed25519_public_key,
        x25519_public_key=x25519_public_key,
        ml_kem_encapsulation_key=ml_kem_encapsulation_key,
        bundle_signature=bundle_signature,
        prev_hash=previous.entry_hash if previous else None,
        entry_hash=entry_hash(
            prev_hash=previous.entry_hash if previous else None,
            user_id=user_id,
            seq=seq,
            ed25519_public_key=ed25519_public_key,
            x25519_public_key=x25519_public_key,
            ml_kem_encapsulation_key=ml_kem_encapsulation_key,
        ),
    )
    db.add(record)
    return record


def verify_chain(records: list[KeyBundleRecord]) -> tuple[bool, str | None]:
    """Recompute a user's chain end to end.

    Returns `(ok, reason)`. This runs server-side for the API's own answer, but the same
    computation is repeated in the browser against the returned history -- a log the
    relay grades itself against is not evidence of anything.
    """
    expected_prev: bytes | None = None
    for index, record in enumerate(records, start=1):
        if record.seq != index:
            return False, f"sequence jumps to {record.seq} at position {index}"
        if record.prev_hash != expected_prev:
            return False, f"entry {record.seq} does not follow the previous one"
        recomputed = entry_hash(
            prev_hash=record.prev_hash,
            user_id=record.user_id,
            seq=record.seq,
            ed25519_public_key=record.ed25519_public_key,
            x25519_public_key=record.x25519_public_key,
            ml_kem_encapsulation_key=record.ml_kem_encapsulation_key,
        )
        if recomputed != record.entry_hash:
            return False, f"entry {record.seq} has been altered"
        expected_prev = record.entry_hash
    return True, None
