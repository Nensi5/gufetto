"""VirusTotal API v3 (https://docs.virustotal.com/reference/overview).

Free nalog ima limit od 4 zahteva u minuti i 500 dnevno, zato je keš u
bazi bitan.
"""

import base64
from urllib.parse import quote

from app.modules.ioc.detect import HASH_TYPES, IP_TYPES, Ioc, IocType
from app.modules.ioc.providers.base import LookupStatus, Provider, ProviderResult

API_BASE = "https://www.virustotal.com/api/v3"


def vt_score(malicious: int, suspicious: int) -> int:
    """Pretvara broj detekcija u skor 0-100.

    Jedna detekcija je često false positive, pa ona daje nizak skor;
    10+ malicious detekcija je praktično sigurno loše.
    """
    if malicious == 0 and suspicious == 0:
        return 0
    return min(100, 30 + malicious * 7 + suspicious * 2)


def _endpoint(ioc: Ioc) -> str:
    if ioc.type in IP_TYPES:
        return f"{API_BASE}/ip_addresses/{ioc.value}"
    if ioc.type == IocType.DOMAIN:
        return f"{API_BASE}/domains/{ioc.value}"
    if ioc.type in HASH_TYPES:
        return f"{API_BASE}/files/{ioc.value}"
    # URL ID je base64url bez "=" na kraju
    url_id = base64.urlsafe_b64encode(ioc.value.encode()).decode().rstrip("=")
    return f"{API_BASE}/urls/{url_id}"


def _gui_link(ioc: Ioc) -> str:
    kind = {
        IocType.IPV4: "ip-address", IocType.IPV6: "ip-address",
        IocType.DOMAIN: "domain", IocType.URL: "url",
    }.get(ioc.type, "file")
    if ioc.type == IocType.URL:
        return f"https://www.virustotal.com/gui/search/{quote(ioc.value, safe='')}"
    return f"https://www.virustotal.com/gui/{kind}/{ioc.value}"


class VirusTotal(Provider):
    name = "virustotal"
    supported_types = set(IocType)

    async def _lookup(self, ioc: Ioc) -> ProviderResult:
        resp = await self.client.get(_endpoint(ioc), headers={"x-apikey": self.api_key})
        if resp.status_code == 404:
            return ProviderResult(self.name, LookupStatus.NOT_FOUND,
                                  summary={"link": _gui_link(ioc)})
        resp.raise_for_status()
        raw = resp.json()
        attrs = raw.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        engines = sum(v for v in stats.values() if isinstance(v, int))

        summary = {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "engines": engines,
            "reputation": attrs.get("reputation"),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "tags": attrs.get("tags", [])[:10],
            "link": _gui_link(ioc),
        }
        if ioc.type in HASH_TYPES:
            summary["file_name"] = attrs.get("meaningful_name")
            summary["file_type"] = attrs.get("type_description")
            threat = attrs.get("popular_threat_classification") or {}
            summary["threat_label"] = threat.get("suggested_threat_label")
        elif ioc.type in IP_TYPES:
            summary["country"] = attrs.get("country")
            summary["as_owner"] = attrs.get("as_owner")
        elif ioc.type == IocType.DOMAIN:
            summary["registrar"] = attrs.get("registrar")
            summary["creation_date"] = attrs.get("creation_date")

        return ProviderResult(self.name, LookupStatus.OK,
                              score=vt_score(malicious, suspicious),
                              summary=summary, raw=raw)
