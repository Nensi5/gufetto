"""Konekcija na bazu i sesije (SQLAlchemy 2.x)."""

from collections.abc import Iterator

from sqlalchemy import create_engine, make_url, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings


class Base(DeclarativeBase):
    pass


def _make_engine(url: str):
    kwargs = {"pool_pre_ping": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    return create_engine(url, **kwargs)


engine = _make_engine(get_settings().database_url)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def _ensure_mssql_database(url: str) -> None:
    """SQL Server kontejner ne pravi bazu sam, pa je pravimo preko master baze."""
    db_url = make_url(url)
    name = db_url.database
    if not name or not name.replace("_", "").isalnum():
        raise ValueError(f"Neispravno ime baze: {name!r}")
    master = create_engine(db_url.set(database="master"), isolation_level="AUTOCOMMIT")
    with master.connect() as conn:
        conn.execute(text(f"IF DB_ID(N'{name}') IS NULL CREATE DATABASE [{name}]"))
    master.dispose()


def init_db() -> None:
    # Za MVP pravimo tabele direktno; kasnije prelazimo na Alembic migracije.
    from app import models  # noqa: F401  (registruje modele)

    url = get_settings().database_url
    if url.startswith("mssql"):
        _ensure_mssql_database(url)
    Base.metadata.create_all(bind=engine)


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
