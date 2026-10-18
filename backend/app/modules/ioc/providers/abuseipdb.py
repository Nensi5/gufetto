"""AbuseIPDB (https://www.abuseipdb.com/api) — reputacija IP adresa."""

from app.modules.ioc.detect import IP_TYPES, Ioc
from app.modules.ioc.providers.base import LookupStatus, Provider, ProviderResult

API_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDB(Provider):
    name = "abuseipdb"
    supported_types = IP_TYPES

    async def _lookup(self, ioc: Ioc) -> ProviderResult:
        resp = await self.client.get(
            API_URL,
            params={"ipAddress": ioc.value, "maxAgeInDays": 90},
            headers={"Key": self.api_key, "Accept": "application/json"},
        )
        resp.raise_for_status()
        raw = resp.json()
        data = raw.get("data", {})

        summary = {
            "abuse_confidence": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "distinct_reporters": data.get("numDistinctUsers"),
            "last_reported": data.get("lastReportedAt"),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "usage_type": data.get("usageType"),
            "is_tor": data.get("isTor"),
            "is_whitelisted": data.get("isWhitelisted"),
        }
        # abuseConfidenceScore je već 0-100, koristimo ga direktno
        return ProviderResult(
            self.name, LookupStatus.OK,
            score=data.get("abuseConfidenceScore"), summary=summary, raw=raw,
        )
