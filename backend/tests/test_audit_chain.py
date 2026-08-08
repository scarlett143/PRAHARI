"""Tamper-evidence for the audit log.

The design decision under test is that the chain is stamped by an explicit sealing pass
rather than computed on every write. These check both halves of that bargain: that sealed
history genuinely cannot be edited, reordered or truncated without detection, and that the
unsealed window is reported honestly rather than quietly counted as protected.
"""
import pytest

pytest.importorskip("aiosqlite")

from fastapi.testclient import TestClient
from sqlalchemy import select

from app import audit_chain
from app.database import get_session_factory
from app.main import app
from app.models import AuditCheckpoint, AuditLog


@pytest.fixture(autouse=True, scope="module")
def _schema():
    """These talk to the database directly rather than over HTTP, so the schema has to be
    created some other way. Entering the app's lifespan is that way -- it is what runs
    create_all and the additive-column reconciler in every other test file too."""
    with TestClient(app):
        yield


def _session():
    return get_session_factory()()


async def _add_events(count: int, prefix: str) -> None:
    async with _session() as session:
        for index in range(count):
            session.add(
                AuditLog(
                    actor_id=f"actor-{index % 3}",
                    event=f"{prefix}.event",
                    severity="low",
                    source_ip="10.0.0.1",
                    detail=f"n={index}",
                )
            )
        await session.commit()


async def _seal() -> dict:
    async with _session() as session:
        return await audit_chain.seal(session)


async def _verify() -> dict:
    async with _session() as session:
        return await audit_chain.verify(session)


async def _sealed_rows() -> list[AuditLog]:
    async with _session() as session:
        return (
            await session.execute(
                select(AuditLog).where(AuditLog.seq.isnot(None)).order_by(AuditLog.seq.asc())
            )
        ).scalars().all()


async def test_sealing_stamps_a_verifiable_chain():
    await _add_events(5, "seal_ok")
    result = await _seal()

    assert result["sealed"] >= 5
    assert result["unsealed_remaining"] == 0

    verified = await _verify()
    assert verified["ok"] is True, verified["reason"]
    assert verified["head_hash"] == result["head_hash"]
    assert verified["unsealed_entries"] == 0


async def test_sealing_is_idempotent():
    await _add_events(3, "idem")
    first = await _seal()
    second = await _seal()

    assert second["sealed"] == 0, "a second pass has nothing left to claim"
    assert second["head_hash"] == first["head_hash"]
    assert (await _verify())["ok"] is True


async def test_writes_stay_unsealed_until_asked_and_are_reported_as_such():
    """The honest cost of keeping the write path free: a window with no protection."""
    await _add_events(2, "window")
    await _seal()
    await _add_events(4, "window_after")

    verified = await _verify()
    assert verified["ok"] is True, "already-sealed history is still intact"
    assert verified["unsealed_entries"] == 4, (
        "unprotected rows must be surfaced, not folded into an 'ok'"
    )

    await _seal()
    assert (await _verify())["unsealed_entries"] == 0


async def test_editing_a_sealed_entry_is_detected():
    await _add_events(4, "edit")
    await _seal()
    rows = await _sealed_rows()
    target = rows[len(rows) // 2]

    async with _session() as session:
        row = await session.get(AuditLog, target.id)
        row.detail = "something that never happened"
        await session.commit()

    verified = await _verify()
    assert verified["ok"] is False
    assert "altered" in verified["reason"]


async def test_deleting_a_sealed_entry_is_detected():
    await _add_events(4, "delete")
    await _seal()
    rows = await _sealed_rows()

    async with _session() as session:
        row = await session.get(AuditLog, rows[1].id)
        await session.delete(row)
        await session.commit()

    verified = await _verify()
    assert verified["ok"] is False, "a hole in the sequence must not validate"


async def test_truncating_the_log_is_caught_by_the_checkpoint():
    """The case sealing alone cannot see.

    A server willing to rewrite its own database could delete the tail *and* reseal from
    scratch, producing a chain that verifies perfectly. The checkpoint is what makes the
    shortened log provably different from the one committed to earlier.
    """
    await _add_events(6, "truncate")
    await _seal()
    rows = await _sealed_rows()
    head_seq = rows[-1].seq

    async with _session() as session:
        # Drop the last two entries and clear the chain fields on the rest, exactly as
        # someone resealing a shortened log would.
        for row in rows[-2:]:
            await session.delete(await session.get(AuditLog, row.id))
        for row in rows[:-2]:
            live = await session.get(AuditLog, row.id)
            live.seq = None
            live.prev_hash = None
            live.entry_hash = None
        await session.commit()

    await _seal()
    verified = await _verify()

    assert verified["ok"] is False
    assert "checkpoint" in verified["reason"]
    assert verified["head_seq"] == 0

    async with _session() as session:
        newest = (
            await session.execute(
                select(AuditCheckpoint).order_by(AuditCheckpoint.seq.desc()).limit(1)
            )
        ).scalars().first()
    assert newest.seq >= head_seq, "the earlier commitment survives the rewrite"


async def test_the_hash_binds_field_boundaries():
    """Two different rows must not hash alike because their fields concatenate the same."""

    class Row:
        def __init__(self, actor, event):
            self.id = "row-1"
            self.actor_id = actor
            self.event = event
            self.severity = "low"
            self.source_ip = None
            self.detail = None
            self.created_at = None

    left = audit_chain.entry_hash(prev_hash=None, row=Row("ab", "c"), seq=1)
    right = audit_chain.entry_hash(prev_hash=None, row=Row("a", "bc"), seq=1)
    assert left != right


async def test_the_chain_commits_to_position():
    """The same row at a different sequence must hash differently, or reordering is free."""

    class Row:
        id = "row-1"
        actor_id = "actor"
        event = "thing.happened"
        severity = "low"
        source_ip = None
        detail = None
        created_at = None

    assert audit_chain.entry_hash(prev_hash=None, row=Row(), seq=1) != audit_chain.entry_hash(
        prev_hash=None, row=Row(), seq=2
    )
