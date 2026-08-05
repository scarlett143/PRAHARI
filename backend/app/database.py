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
ADDITIVE_COLUMNS: tuple[tuple[str, str, str], ...] = (
    ("channels", "initiator_id", "VARCHAR"),
)


async def reconcile_additive_columns() -> None:
    engine = get_engine()
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
        for table, column, column_type in ADDITIVE_COLUMNS:
            if table not in existing or column in existing[table]:
                continue
            await connection.execute(
                text(f"ALTER TABLE {table} ADD COLUMN {column} {column_type}")
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
