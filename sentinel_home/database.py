"""SQLAlchemy engine, session factory, and Base declaration."""

from __future__ import annotations

import logging
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine, event, inspect
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


_engine = None
_SessionLocal = None


def _run_migrations(db_path: str) -> None:
    """Run Alembic migrations to bring the database schema up to date.

    If the database exists but has no Alembic version table, we stamp it
    at the revision that matches its current schema, then upgrade from there.
    This handles databases created by create_all() before migrations existed.
    """
    try:
        from alembic import command
        from alembic.config import Config

        # Find alembic.ini relative to this package
        pkg_dir = Path(__file__).resolve().parent.parent
        ini_path = pkg_dir / "alembic.ini"
        if not ini_path.exists():
            logger.debug("No alembic.ini found at %s — skipping migrations", ini_path)
            return

        alembic_cfg = Config(str(ini_path))
        alembic_cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")

        # Check if alembic_version table exists
        insp = inspect(_engine)
        has_version_table = "alembic_version" in insp.get_table_names()

        if has_version_table:
            # Already tracked — just upgrade.
            # If create_all already added columns, the migration may fail with
            # "duplicate column" — detect that and stamp head instead.
            try:
                logger.info("Running Alembic migrations (upgrade head)")
                command.upgrade(alembic_cfg, "head")
            except Exception as upgrade_exc:
                if "duplicate column" in str(upgrade_exc).lower():
                    logger.info("Columns already exist (created by create_all), stamping head")
                    command.stamp(alembic_cfg, "head")
                else:
                    raise
        else:
            # DB exists but was created by create_all() — figure out what
            # revision matches the current schema and stamp it, then upgrade.
            columns = {c["name"] for c in insp.get_columns("devices")} if "devices" in insp.get_table_names() else set()
            tables = set(insp.get_table_names())

            alert_columns = {c["name"] for c in insp.get_columns("alerts")} if "alerts" in tables else set()

            if "finding_archives" in tables:
                # Has finding_archives table — stamp at latest
                stamp_rev = "b5c8d3e6f7a9"
            elif "signal_strength" in columns and "infra_metrics" in tables:
                # Has all v1.0.3 columns — stamp at unifi/infra revision
                stamp_rev = "a3b7c1d2e4f5"
            elif "notes" in tables:
                # Has notes table (v1.0.1) but not UniFi columns
                stamp_rev = "060d94ea7c08"
            elif "devices" in tables:
                # Has base v1.0 schema
                stamp_rev = "f04c92e7eba5"
            else:
                # Empty or brand new — let create_all + stamp head handle it
                stamp_rev = None

            if stamp_rev:
                logger.info("Stamping existing database at revision %s", stamp_rev)
                command.stamp(alembic_cfg, stamp_rev)

            logger.info("Running Alembic migrations (upgrade head)")
            command.upgrade(alembic_cfg, "head")

        logger.info("Database schema is up to date")

    except Exception as exc:
        logger.warning("Alembic migration failed (will try create_all fallback): %s", exc)


def init_db(db_path: str = "sentinel.db") -> None:
    """Create engine, configure pragmas, run migrations, and create all tables."""
    global _engine, _SessionLocal

    url = f"sqlite:///{db_path}"
    _engine = create_engine(
        url,
        connect_args={"check_same_thread": False},
        echo=False,
    )

    # Enable WAL mode and foreign keys for SQLite
    @event.listens_for(_engine, "connect")
    def set_sqlite_pragma(dbapi_conn, _connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    _SessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False)

    # Import models so they're registered on Base.metadata
    from sentinel_home import models  # noqa: F401

    # Run Alembic migrations first (adds columns to existing tables)
    _run_migrations(db_path)

    # create_all as safety net — creates any missing tables (no-op for existing)
    Base.metadata.create_all(bind=_engine)


def get_engine():
    if _engine is None:
        raise RuntimeError("Database not initialised — call init_db() first")
    return _engine


def get_session() -> Session:
    """Return a new session. Caller is responsible for closing it."""
    if _SessionLocal is None:
        raise RuntimeError("Database not initialised — call init_db() first")
    return _SessionLocal()


@contextmanager
def session_scope() -> Generator[Session, None, None]:
    """Context manager that commits on success and rolls back on exception."""
    session = get_session()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
