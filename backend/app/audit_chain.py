"""Tamper-evidence for the audit log.

WHY THE CHAIN IS NOT BUILT ON THE WRITE PATH. The obvious design gives every audit row the
hash of the row before it, computed as it is written. It does not survive contact with
concurrency: two requests auditing at the same moment both read the same tail, both claim
the next sequence, and one loses -- so a request fails *because of its own audit write*.
That is a worse outcome than the tampering it defends against, and no amount of retrying
makes an audit write a good place to put a contention point.

So writes stay exactly as cheap as they were -- an insert, no read, no hash -- and the
chain is stamped afterwards by `seal`, walking the unsealed rows in one pass. This is the
same shape as Merkle anchoring in `api/anchors.py`, which batches messages rather than
hashing each one as it arrives, and it is deliberate that the two match: one mechanism to
understand, one to review.

WHAT IT PROVES, AND WHAT IT DOES NOT. Once sealed, a row cannot be edited, reordered or
removed without every hash after it failing to recompute. Rows written since the last seal
carry no protection at all -- deleting one of those leaves no trace, which is the honest
cost of keeping the write path free. Seal often if that window matters.

Nor does the chain alone prove nothing was removed before it was ever sealed: a server
willing to rewrite its own database could reseal a shortened log from scratch and it would
verify perfectly. `AuditCheckpoint` is what closes that -- a recorded head and count, from
which a later log that is shorter or differs at the same sequence is provably not the same
log. A checkpoint is only worth as much as its distance from the machine that produced it,
so export them somewhere the server cannot reach.
"""
from __future__ import annotations

import hashlib

import anyio
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import AuditCheckpoint, AuditLog

#: Domain separator, so a digest here can never be replayed as a Merkle leaf or a key
#: transparency entry. Each chain in this system commits to what it is.
_DOMAIN = b"prahari-audit-chain-v1"

#: One sealing pass at a time. Sealing reads the unsealed rows and then stamps them, so two
#: passes running together would both claim the same rows and assign conflicting sequence
#: numbers. There is one uvicorn worker on this deployment, which makes an in-process lock
#: sufficient; a second worker would need a database-level advisory lock instead.
_SEAL_LOCK = anyio.Lock()

#: Rows are sealed and verified in bounded chunks. The audit table is the fastest-growing
#: thing here and the unit runs under MemoryMax=768M, so neither operation may load it all.
CHUNK = 500


def _field(value) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    return str(value).encode("utf-8")


def entry_hash(*, prev_hash: bytes | None, row: AuditLog, seq: int) -> bytes:
    """Commit to one audit row and to every row before it.

    Lengths precede each field. Without them "user=ab" + "c" and "user=a" + "bc" produce
    identical input, and two different histories could share a hash.
    """
    digest = hashlib.sha256()
    digest.update(_DOMAIN)
    digest.update(prev_hash or b"\x00" * 32)
    digest.update(seq.to_bytes(8, "big"))
    for value in (
        row.id,
        row.actor_id,
        row.event,
        row.severity,
        row.source_ip,
        row.detail,
        # isoformat rather than the datetime: SQLite and PostgreSQL hand back different
        # types for the same column, and the hash has to be identical on both.
        row.created_at.isoformat() if row.created_at else None,
    ):
        field = _field(value)
        digest.update(len(field).to_bytes(4, "big"))
        digest.update(field)
    return digest.digest()


async def chain_head(db: AsyncSession) -> tuple[int, bytes | None]:
    """The highest sealed sequence and its hash."""
    row = (
        await db.execute(
            select(AuditLog)
            .where(AuditLog.seq.isnot(None))
            .order_by(AuditLog.seq.desc())
            .limit(1)
        )
    ).scalars().first()
    return (row.seq, row.entry_hash) if row else (0, None)


async def seal(db: AsyncSession, *, limit: int = CHUNK) -> dict:
    """Stamp unsealed audit rows into the chain. Idempotent, and safe to call often."""
    async with _SEAL_LOCK:
        seq, prev = await chain_head(db)

        pending = (
            await db.execute(
                select(AuditLog)
                .where(AuditLog.seq.is_(None))
                # created_at alone is not unique -- SQLite's CURRENT_TIMESTAMP is
                # second-precision -- so ties would seal in one order and verify in
                # another. id breaks the tie, exactly as anchor batching does.
                .order_by(AuditLog.created_at.asc(), AuditLog.id.asc())
                .limit(min(max(limit, 1), CHUNK))
            )
        ).scalars().all()

        for row in pending:
            seq += 1
            row.seq = seq
            row.prev_hash = prev
            row.entry_hash = entry_hash(prev_hash=prev, row=row, seq=seq)
            prev = row.entry_hash

        checkpoint = None
        if pending:
            total = await db.scalar(select(func.count(AuditLog.id)).where(AuditLog.seq.isnot(None)))
            checkpoint = AuditCheckpoint(seq=seq, head_hash=prev, entry_count=int(total or 0))
            db.add(checkpoint)

        await db.commit()
        remaining = await db.scalar(
            select(func.count(AuditLog.id)).where(AuditLog.seq.is_(None))
        )
        return {
            "sealed": len(pending),
            "head_seq": seq,
            "head_hash": prev.hex() if prev else None,
            "unsealed_remaining": int(remaining or 0),
        }


async def verify(db: AsyncSession) -> dict:
    """Recompute the sealed chain end to end, in bounded chunks."""
    expected_prev: bytes | None = None
    expected_seq = 0
    checked = 0
    offset = 0

    while True:
        rows = (
            await db.execute(
                select(AuditLog)
                .where(AuditLog.seq.isnot(None))
                .order_by(AuditLog.seq.asc())
                .offset(offset)
                .limit(CHUNK)
            )
        ).scalars().all()
        if not rows:
            break

        for row in rows:
            expected_seq += 1
            if row.seq != expected_seq:
                return _broken(f"sequence jumps to {row.seq} where {expected_seq} was expected")
            if row.prev_hash != expected_prev:
                return _broken(f"entry {row.seq} does not follow the one before it")
            if entry_hash(prev_hash=row.prev_hash, row=row, seq=row.seq) != row.entry_hash:
                return _broken(f"entry {row.seq} has been altered since it was sealed")
            expected_prev = row.entry_hash
            checked += 1

        offset += len(rows)

    # A checkpoint that describes a longer log than the one in front of us means entries
    # were removed after being committed to -- the case sealing alone cannot detect.
    newest = (
        await db.execute(
            select(AuditCheckpoint).order_by(AuditCheckpoint.seq.desc()).limit(1)
        )
    ).scalars().first()
    if newest is not None and newest.seq > expected_seq:
        return _broken(
            f"a checkpoint commits to {newest.seq} entries but only {expected_seq} remain"
        )
    if newest is not None and newest.seq == expected_seq and newest.head_hash != expected_prev:
        return _broken("the chain head does not match the recorded checkpoint")

    unsealed = await db.scalar(select(func.count(AuditLog.id)).where(AuditLog.seq.is_(None)))
    return {
        "ok": True,
        "reason": None,
        "entries_checked": checked,
        "head_seq": expected_seq,
        "head_hash": expected_prev.hex() if expected_prev else None,
        # Surfaced rather than hidden: these rows are genuinely unprotected, and an
        # operator reading "ok" should see how much of the log that verdict covers.
        "unsealed_entries": int(unsealed or 0),
    }


def _broken(reason: str) -> dict:
    return {
        "ok": False,
        "reason": reason,
        "entries_checked": 0,
        "head_seq": 0,
        "head_hash": None,
        "unsealed_entries": 0,
    }
