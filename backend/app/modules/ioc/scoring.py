"""Spajanje rezultata provajdera u jednu presudu sa objašnjenjem.

Ideja je da analitičar odmah vidi ZAŠTO je nešto označeno, ne samo broj.
"""

from __future__ import annotations

from enum import StrEnum

from app.modules.ioc.providers.base import LookupStatus, ProviderResult


class Verdict(StrEnum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"
    INTERNAL = "internal"


SUSPICIOUS_THRESHOLD = 25
MALICIOUS_THRESHOLD = 60


def verdict_for(score: int | None) -> Verdict:
    if score is None:
        return Verdict.UNKNOWN
    if score >= MALICIOUS_THRESHOLD:
        return Verdict.MALICIOUS
    if score >= SUSPICIOUS_THRESHOLD:
        return Verdict.SUSPICIOUS
    return Verdict.CLEAN


def _reasons_abuseipdb(s: dict) -> list[str]:
    out = []
    conf, reports, users = s.get("abuse_confidence"), s.get("total_reports"), s.get("distinct_reporters")
    if reports:
        out.append(f"AbuseIPDB: {conf}% confidence, {reports} reports from {users} users (90 days)")
    else:
        out.append("AbuseIPDB: no abuse reports in the last 90 days")
    if s.get("is_tor"):
        out.append("Tor exit node")
    if s.get("is_whitelisted"):
        out.append("Whitelisted on AbuseIPDB")
    if s.get("usage_type"):
        out.append(f"Usage type: {s['usage_type']}" + (f" ({s['isp']})" if s.get("isp") else ""))
    return out


def _reasons_virustotal(s: dict) -> list[str]:
    out = []
    mal, sus, engines = s.get("malicious", 0), s.get("suspicious", 0), s.get("engines", 0)
    if mal or sus:
        out.append(f"VirusTotal: {mal}/{engines} engines malicious, {sus} suspicious")
    else:
        out.append(f"VirusTotal: 0/{engines} engines flag it")
    if s.get("threat_label"):
        out.append(f"Threat label: {s['threat_label']}")
    rep = s.get("reputation")
    if isinstance(rep, int) and rep < 0:
        out.append(f"Negative VirusTotal community reputation ({rep})")
    return out


_REASONERS = {"abuseipdb": _reasons_abuseipdb, "virustotal": _reasons_virustotal}


def combine(results: list[ProviderResult]) -> tuple[int | None, Verdict, list[str]]:
    """Vraća (skor, presuda, razlozi).

    Uzimamo NAJVEĆI skor od provajdera: za triage je bolje da lažno
    eskaliramo nego da propustimo nešto što jedan izvor jasno vidi.
    """
    scores = [r.score for r in results if r.status == LookupStatus.OK and r.score is not None]
    score = max(scores) if scores else None

    reasons: list[str] = []
    for r in results:
        if r.status == LookupStatus.OK and r.provider in _REASONERS:
            reasons.extend(_REASONERS[r.provider](r.summary))
        elif r.status == LookupStatus.NOT_FOUND:
            reasons.append(f"{r.provider}: no data for this indicator")
        elif r.status == LookupStatus.NOT_CONFIGURED:
            reasons.append(f"{r.provider}: API key not configured, add it to .env")
        elif r.status == LookupStatus.RATE_LIMITED:
            reasons.append(f"{r.provider}: rate limit reached, try again in a minute")
        elif r.status == LookupStatus.ERROR:
            reasons.append(f"{r.provider}: {r.error or 'lookup failed'}")

    return score, verdict_for(score), reasons
