"""Pydantic modeli za API zahteve i odgovore IOC modula."""

from typing import Any

from pydantic import BaseModel, Field


class LookupRequest(BaseModel):
    input: str = Field(
        ..., min_length=1, max_length=50_000,
        description="Jedan IOC ili slobodan tekst (log, mejl, alert) iz kog se izvlače IOC-ovi",
    )
    force_refresh: bool = Field(False, description="Preskoči keš i pitaj provajdere ponovo")


class ProviderOut(BaseModel):
    provider: str
    status: str
    score: int | None = None
    cached: bool = False
    error: str | None = None
    summary: dict[str, Any] = {}


class IocResult(BaseModel):
    value: str
    defanged: str
    type: str
    score: int | None
    verdict: str
    reasons: list[str]
    providers: list[ProviderOut]


class LookupResponse(BaseModel):
    count: int
    truncated: bool = False
    results: list[IocResult]


class ExtractResponse(BaseModel):
    count: int
    iocs: list[dict[str, Any]]
