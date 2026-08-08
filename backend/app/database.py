"""Async SQLAlchemy/PostgreSQL lifecycle helpers."""
from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from .config import get_settings


class Base(DeclarativeBase):
    pass


_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    global _engine, _session_factory
    if _engine is None:
        settings = get_settings()
        options: dict = {"echo": False, "pool_pre_ping": True}
        # SQLite uses a non-queue pool, so sizing arguments are invalid there.
        if not settings.database_url.startswith("sqlite"):
            options.update(
                pool_size=settings.db_pool_size,
                max_overflow=settings.db_max_overflow,
                pool_timeout=settings.db_pool_timeout_seconds,
                pool_recycle=settings.db_pool_recycle_seconds,
            )
        _engine = create_async_engine(settings.database_url, **options)
        _session_factory = async_sessionmaker(
            bind=_engine, class_=AsyncSession, expire_on_commit=False
        )
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    get_engine()
    assert _session_factory is not None
    return _session_factory


async def get_db():
    async with get_session_factory()() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


#: Columns added to existing tables after the first release.
#:
#: `Base.metadata.create_all` creates missing *tables* and nothing else -- it will never
#: add a column to a table that already exists. New tables therefore appear on upgrade
#: while new columns silently do not, and the failure surfaces as an
#: UndefinedColumnError on the first insert, well after the deploy looked successful.
#:
#: This is a deliberate stopgap, not a migration system. It only ever adds nullable
#: columns, never drops, renames or retypes anything, so it cannot destroy data. Alembic
#: is the right answer as soon as a change needs backfilling or a type change.
#: Logical types, resolved per dialect below, because "the binary one" is spelled
#: differently on PostgreSQL and SQLite and this table is created on both.
ADDITIVE_COLUMNS: tuple[tuple[str, str, str], ...] = (
    ("channels", "initiator_id", "VARCHAR"),
    ("session_offers", "wrapped_group_key", "BINARY"),
    ("users", "totp_secret", "VARCHAR"),
    ("users", "totp_enabled", "BOOLEAN"),
    ("messages", "deleted_at", "TIMESTAMP"),
    ("uav_profiles", "security_state", "VARCHAR"),
    ("uav_profiles", "security_state_at", "TIMESTAMP"),
    ("uav_profiles", "security_state_reason", "VARCHAR"),
    ("anchor_batches", "pq_signature", "BINARY"),
    ("anchor_batches", "pq_algorithm", "VARCHAR"),
    ("audit_logs", "seq", "INTEGER"),
    ("audit_logs", "prev_hash", "BINARY"),
    ("audit_logs", "entry_hash", "BINARY"),
    ("users", "webauthn_challenge", "VARCHAR"),
    ("users", "webauthn_challenge_at", "TIMESTAMP"),
    ("uav_profiles", "expected_measurement", "BINARY"),
    ("uav_profiles", "last_measurement", "BINARY"),
    ("uav_profiles", "last_measurement_at", "TIMESTAMP"),
)

_COLUMN_TYPES = {
    "VARCHAR": {"postgresql": "VARCHAR", "sqlite": "VARCHAR"},
    "BINARY": {"postgresql": "BYTEA", "sqlite": "BLOB"},
    # Added NOT NULL would fail on a table with rows, so it arrives nullable with a
    # default and the model treats NULL as "off".
    "BOOLEAN": {"postgresql": "BOOLEAN DEFAULT FALSE", "sqlite": "BOOLEAN DEFAULT 0"},
    # Nullable throughout: NULL is the meaningful "never happened" state, so no default.
    "TIMESTAMP": {"postgresql": "TIMESTAMPTZ", "sqlite": "DATETIME"},
    "INTEGER": {"postgresql": "INTEGER", "sqlite": "INTEGER"},
}


async def reconcile_additive_columns() -> None:
    engine = get_engine()
    dialect = engine.dialect.name
    async with engine.begin() as connection:

        def inspect_existing(sync_connection):
            from sqlalchemy import inspect

            inspector = inspect(sync_connection)
            tables = set(inspector.get_table_names())
            return {
                table: {column["name"] for column in inspector.get_columns(table)}
                for table in tables
            }

        existing = await connection.run_sync(inspect_existing)
        for table, column, logical_type in ADDITIVE_COLUMNS:
            if table not in existing or column in existing[table]:
                continue
            column_type = _COLUMN_TYPES[logical_type].get(dialect, "VARCHAR")
            await connection.execute(
                text(f"ALTER TABLE {table} ADD COLUMN {column} {column_type}")
            )


async def widen_session_offer_uniqueness() -> None:
    """Relax `session_offers` from one offer per epoch to one per recipient per epoch.

    This is the schema half of group messaging. The original constraint made the table
    physically incapable of holding a second recipient, so it has to be replaced rather
    than added to -- which puts it outside what `reconcile_additive_columns` will touch.

    Only PostgreSQL is altered in place. SQLite cannot drop a constraint without
    rebuilding the table, and it is only used here for local development and tests, where
    the schema is created fresh from the model and is already correct.
    """
    engine = get_engine()
    if engine.dialect.name != "postgresql":
        return
    async with engine.begin() as connection:
        await connection.execute(
            text("ALTER TABLE session_offers DROP CONSTRAINT IF EXISTS uq_channel_epoch_offer")
        )
        await connection.execute(
            text(
                "CREATE UNIQUE INDEX IF NOT EXISTS uq_channel_epoch_responder_offer "
                "ON session_offers (channel_id, key_epoch, responder_id)"
            )
        )


async def ping_database() -> None:
    async with get_engine().connect() as connection:
        await connection.execute(text("SELECT 1"))


async def close_database() -> None:
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _session_factory = None
