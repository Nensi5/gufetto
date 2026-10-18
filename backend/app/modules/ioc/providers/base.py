"""Zajednički interfejs za threat-intel provajdere."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

import httpx

from app.modules.ioc.detect import Ioc, IocType


class LookupStatus(StrEnum):
    OK = "ok"
    NOT_FOUND = "not_found"            # provajder nema podatke o ovom IOC-u
    NOT_CONFIGURED = "not_configured"  # nedostaje API ključ
    RATE_LIMITED = "rate_limited"
    ERROR = "error"


@dataclass
class ProviderResult:
    provider: str
    status: LookupStatus
    score: int | None = None              # 0-100, None ako nema ocene
    summary: dict[str, Any] = field(default_factory=dict)  # bitna polja za UI
    raw: dict[str, Any] = field(default_factory=dict)      # ceo odgovor
    error: str | None = None
    cached: bool = False


class Provider(ABC):
    name: str
    supported_types: set[IocType]

    def __init__(self, api_key: str, client: httpx.AsyncClient):
        self.api_key = api_key
        self.client = client

    @property
    def configured(self) -> bool:
        return bool(self.api_key)

    def supports(self, ioc: Ioc) -> bool:
        return ioc.type in self.supported_types

    async def lookup(self, ioc: Ioc) -> ProviderResult:
        if not self.configured:
            return ProviderResult(self.name, LookupStatus.NOT_CONFIGURED,
                                  error=f"{self.name} API key is not configured")
        try:
            return await self._lookup(ioc)
        except httpx.HTTPStatusError as exc:
            code = exc.response.status_code
            if code == 429:
                return ProviderResult(self.name, LookupStatus.RATE_LIMITED,
                                      error="Rate limit reached, try again later")
            if code in (401, 403):
                return ProviderResult(self.name, LookupStatus.ERROR,
                                      error="API key rejected")
            return ProviderResult(self.name, LookupStatus.ERROR, error=f"HTTP {code}")
        except httpx.HTTPError as exc:
            return ProviderResult(self.name, LookupStatus.ERROR,
                                  error=f"Network error: {type(exc).__name__}")

    @abstractmethod
    async def _lookup(self, ioc: Ioc) -> ProviderResult: ...
