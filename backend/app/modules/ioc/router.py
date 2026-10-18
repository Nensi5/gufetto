"""API rute IOC modula."""

from datetime import timedelta

import httpx
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.db import get_db
from app.modules.ioc.detect import defang, extract
from app.modules.ioc.schemas import ExtractResponse, LookupRequest, LookupResponse
from app.modules.ioc.service import IocService, build_providers

router = APIRouter(prefix="/api/ioc", tags=["IOC lookup"])

# Free VirusTotal dozvoljava 4 zahteva u minuti, pa ograničavamo jedan poziv
MAX_IOCS_PER_LOOKUP = 20


def get_service(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> IocService:
    client: httpx.AsyncClient = request.app.state.http
    return IocService(
        db=db,
        providers=build_providers(settings, client),
        cache_ttl=timedelta(hours=settings.ioc_cache_ttl_hours),
    )


@router.post("/extract", response_model=ExtractResponse)
def extract_iocs(body: LookupRequest) -> ExtractResponse:
    """Samo izvlači IOC-ove iz teksta, bez slanja bilo kome."""
    iocs = extract(body.input, limit=200)
    return ExtractResponse(
        count=len(iocs),
        iocs=[
            {"value": i.value, "defanged": defang(i.value), "type": i.type.value, "internal": i.internal}
            for i in iocs
        ],
    )


@router.post("/lookup", response_model=LookupResponse)
async def lookup(body: LookupRequest, service: IocService = Depends(get_service)) -> LookupResponse:
    """Izvlači IOC-ove iz unosa i proverava ih kod AbuseIPDB i VirusTotal-a."""
    iocs = extract(body.input, limit=MAX_IOCS_PER_LOOKUP + 1)
    truncated = len(iocs) > MAX_IOCS_PER_LOOKUP
    iocs = iocs[:MAX_IOCS_PER_LOOKUP]

    # Redom, ne paralelno, da ne potrošimo VT limit u jednoj sekundi
    results = [await service.lookup(ioc, body.force_refresh) for ioc in iocs]

    order = {"malicious": 0, "suspicious": 1, "unknown": 2, "clean": 3, "internal": 4}
    results.sort(key=lambda r: (order.get(r.verdict, 9), -(r.score or 0)))
    return LookupResponse(count=len(results), truncated=truncated, results=results)
