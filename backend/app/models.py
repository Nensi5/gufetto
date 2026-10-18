"""Modeli baze."""

from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class IocLookup(Base):
    """Keširan rezultat jednog IOC lookup-a (jedan red po IOC-u i provajderu)."""

    __tablename__ = "ioc_lookups"
    __table_args__ = (UniqueConstraint("ioc_value", "provider", name="uq_ioc_provider"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ioc_value: Mapped[str] = mapped_column(String(512), index=True)
    ioc_type: Mapped[str] = mapped_column(String(16))
    provider: Mapped[str] = mapped_column(String(32))
    # Normalizovan skor 0-100 (100 = sigurno maliciozno), None ako provajder nema podatke
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Sirov JSON odgovor kao tekst (NVARCHAR(MAX) na SQL Serveru)
    raw_json: Mapped[str] = mapped_column(Text)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
