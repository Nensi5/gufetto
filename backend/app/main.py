"""Gufetto — SOC triage asistent. Ulazna tačka FastAPI aplikacije."""

from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI

from app.config import get_settings
from app.db import init_db
from app.modules.ioc.router import router as ioc_router

__version__ = "0.1.0"


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    init_db()
    # Jedan deljeni HTTP klijent za sve provajdere (connection pooling)
    app.state.http = httpx.AsyncClient(
        timeout=settings.http_timeout_seconds,
        headers={"User-Agent": f"gufetto/{__version__}"},
    )
    yield
    await app.state.http.aclose()


app = FastAPI(
    title="Gufetto",
    description="SOC triage assistant: IOC enrichment, email analysis, EDR alert triage.",
    version=__version__,
    lifespan=lifespan,
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)

app.include_router(ioc_router)


@app.get("/api/health", tags=["system"])
def health() -> dict:
    settings = get_settings()
    return {
        "status": "ok",
        "version": __version__,
        "providers": {
            "abuseipdb": bool(settings.abuseipdb_api_key),
            "virustotal": bool(settings.virustotal_api_key),
        },
    }
