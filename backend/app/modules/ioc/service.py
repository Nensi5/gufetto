"""Glavna logika IOC lookup-a: keš u bazi -> provajderi -> presuda."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import IocLookup
from app.modules.ioc.detect import Ioc, defang
from app.modules.ioc.providers.abuseipdb import AbuseIPDB
from app.modules.ioc.providers.base import LookupStatus, Provider, ProviderResult
from app.modules.ioc.providers.virustotal import VirusTotal
from app.modules.ioc.schemas import IocResult, ProviderOut
from app.modules.ioc.scoring import Verdict, combine

# Samo uspešne odgovore keširamo; greške i rate limit uvek probamo ponovo.
_CACHEABLE = {LookupStatus.OK, LookupStatus.NOT_FOUND}


def build_providers(settings: Settings, client: httpx.AsyncClient) -> list[Provider]:
    return [
        AbuseIPDB(settings.abuseipdb_api_key, client),
        VirusTotal(settings.virustotal_api_key, client),
    ]


def _as_utc(dt: datetime) -> datetime:
    # SQLite vraća "naive" datetime, SQL Server vraća sa zonom
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class IocService:
    def __init__(self, db: Session, providers: list[Provider], cache_ttl: timedelta):
        self.db = db
        self.providers = providers
        self.cache_ttl = cache_ttl

    def _from_cache(self, ioc: Ioc, provider: str) -> ProviderResult | None:
        row = self.db.scalar(
            select(IocLookup).where(IocLookup.ioc_value == ioc.value, IocLookup.provider == provider)
        )
        if row is None or datetime.now(timezone.utc) - _as_utc(row.fetched_at) > self.cache_ttl:
            return None
        payload = json.loads(row.raw_json)
        return ProviderResult(
            provider=provider,
            status=LookupStatus(payload["status"]),
            score=row.score,
            summary=payload.get("summary", {}),
            cached=True,
        )

    def _save(self, ioc: Ioc, result: ProviderResult) -> None:
        if result.status not in _CACHEABLE:
            return
        row = self.db.scalar(
            select(IocLookup).where(IocLookup.ioc_value == ioc.value, IocLookup.provider == result.provider)
        )
        if row is None:
            row = IocLookup(ioc_value=ioc.value, ioc_type=ioc.type.value, provider=result.provider)
            self.db.add(row)
        row.score = result.score
        row.raw_json = json.dumps(
            {"status": result.status.value, "summary": result.summary, "raw": result.raw}
        )
        row.fetched_at = datetime.now(timezone.utc)

    async def _query(self, ioc: Ioc, provider: Provider, force_refresh: bool) -> ProviderResult:
        if not force_refresh:
            cached = self._from_cache(ioc, provider.name)
            if cached:
                return cached
        return await provider.lookup(ioc)

    async def lookup(self, ioc: Ioc, force_refresh: bool = False) -> IocResult:
        if ioc.internal:
            # Interne adrese i domene ne šaljemo spoljnim servisima (curenje info o mreži)
            return IocResult(
                value=ioc.value, defanged=defang(ioc.value), type=ioc.type.value,
                score=None, verdict=Verdict.INTERNAL.value,
                reasons=["Internal/private indicator, not sent to external services"],
                providers=[],
            )

        applicable = [p for p in self.providers if p.supports(ioc)]
        results = await asyncio.gather(*(self._query(ioc, p, force_refresh) for p in applicable))

        for r in results:
            if not r.cached:
                self._save(ioc, r)
        self.db.commit()

        score, verdict, reasons = combine(list(results))
        return IocResult(
            value=ioc.value,
            defanged=defang(ioc.value),
            type=ioc.type.value,
            score=score,
            verdict=verdict.value,
            reasons=reasons,
            providers=[
                ProviderOut(provider=r.provider, status=r.status.value, score=r.score,
                            cached=r.cached, error=r.error, summary=r.summary)
                for r in results
            ],
        )
