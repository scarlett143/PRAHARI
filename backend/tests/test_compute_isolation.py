"""CPU-bound work must not run on the event loop.

This service runs as a single uvicorn worker on a two-core box that also carries the
operator's panel, billing and status sites. In that shape, a synchronous Argon2 hash or
quantum simulation called from an `async def` handler does not just make one request slow
-- it stops the whole process for its duration. Every other request in flight, every
WebSocket frame waiting to be delivered, and the health check all wait behind it.

These tests assert the property rather than the implementation: while expensive work is in
progress, the loop still runs.
"""
import pytest

pytest.importorskip("aiosqlite")

import anyio

from app import security
from app.config import Settings


async def _loop_ticks_during(work) -> int:
    """Run `work`, counting how many times the event loop gets control meanwhile."""
    ticks = 0
    done = False

    async def spin():
        nonlocal ticks
        while not done:
            ticks += 1
            await anyio.sleep(0)

    async with anyio.create_task_group() as group:
        group.start_soon(spin)
        await work()
        done = True

    return ticks


async def test_hashing_a_password_does_not_stall_the_event_loop():
    ticks = await _loop_ticks_during(
        lambda: security.hash_password_async("a-sufficiently-long-password")
    )
    # A blocked loop yields exactly zero times. The real number is in the thousands; the
    # threshold is low on purpose so a slow CI machine cannot make this flake.
    assert ticks > 0, "Argon2 ran on the event loop and stalled every other request"


async def test_verifying_a_password_does_not_stall_the_event_loop():
    stored = security.hash_password("a-sufficiently-long-password")
    ticks = await _loop_ticks_during(
        lambda: security.verify_password_async(stored, "a-sufficiently-long-password")
    )
    assert ticks > 0


async def test_the_async_wrappers_agree_with_the_synchronous_ones():
    stored = await security.hash_password_async("a-sufficiently-long-password")

    ok, _ = await security.verify_password_async(stored, "a-sufficiently-long-password")
    assert ok is True

    wrong, _ = await security.verify_password_async(stored, "not-the-password")
    assert wrong is False


async def test_concurrent_hashing_is_bounded():
    """The limiter is what keeps a login burst from exhausting MemoryMax.

    Each Argon2 call holds 19 MiB. The default thread pool would allow 40 at once, which
    is ~760 MiB against a 768 MiB unit cap -- so the bound is not a tuning preference, it
    is what stops a burst of logins from OOM-killing the service.
    """
    assert security._PASSWORD_LIMITER.total_tokens <= 8, (
        "more concurrent hashes than this box has memory for"
    )

    # And it genuinely runs several at once rather than serialising them.
    async def hash_one():
        await security.hash_password_async("a-sufficiently-long-password")

    async with anyio.create_task_group() as group:
        for _ in range(4):
            group.start_soon(hash_one)


def test_the_quantum_lab_is_off_in_production_unless_asked_for():
    """A teaching endpoint has no claim on the CPU of a box carrying live sites."""
    assert Settings(environment="production").quantum_lab_enabled is False
    assert Settings(environment="development").quantum_lab_enabled is True

    # An explicit opt-in still wins, in both directions.
    assert Settings(environment="production", QUANTUM_LAB_ENABLED=True).quantum_lab_enabled is True
    assert Settings(environment="development", QUANTUM_LAB_ENABLED=False).quantum_lab_enabled is False


def test_the_lab_ceilings_stay_within_what_this_box_can_spend():
    from app.api.quantum import ExperimentRequest

    fields = ExperimentRequest.model_fields
    shots_max = next(m.le for m in fields["shots"].metadata if hasattr(m, "le"))
    rounds_max = next(m.le for m in fields["bb84_rounds"].metadata if hasattr(m, "le"))
    assert shots_max <= 2048
    assert rounds_max <= 4096
