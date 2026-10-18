import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from app.main import app
from app.modules.ioc.providers.virustotal import vt_score
from app.modules.ioc.scoring import Verdict, verdict_for

ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"
VT_BASE = "https://www.virustotal.com/api/v3"

ABUSE_BAD = {"data": {"abuseConfidenceScore": 100, "totalReports": 412, "numDistinctUsers": 98,
                      "countryCode": "DE", "isp": "Example Hosting", "usageType": "Data Center/Web Hosting/Transit",
                      "isTor": True, "isWhitelisted": False}}
VT_BAD = {"data": {"attributes": {"last_analysis_stats": {"malicious": 14, "suspicious": 2, "harmless": 60, "undetected": 18},
                                  "reputation": -35, "tags": ["tor"]}}}
VT_CLEAN = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 24},
                                    "reputation": 10}}}


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_scoring_thresholds():
    assert vt_score(0, 0) == 0
    assert verdict_for(vt_score(1, 0)) == Verdict.SUSPICIOUS
    assert verdict_for(vt_score(10, 0)) == Verdict.MALICIOUS
    assert verdict_for(None) == Verdict.UNKNOWN


def test_health(client):
    body = client.get("/api/health").json()
    assert body["status"] == "ok"
    assert body["providers"] == {"abuseipdb": True, "virustotal": True}


@respx.mock
def test_lookup_malicious_ip_then_cache(client):
    abuse = respx.get(ABUSE_URL).mock(return_value=httpx.Response(200, json=ABUSE_BAD))
    vt = respx.get(f"{VT_BASE}/ip_addresses/185.220.101.1").mock(return_value=httpx.Response(200, json=VT_BAD))

    r = client.post("/api/ioc/lookup", json={"input": "dst=185.220.101.1"}).json()
    res = r["results"][0]
    assert res["verdict"] == "malicious"
    assert res["score"] == 100
    assert res["defanged"] == "185[.]220[.]101[.]1"
    assert any("Tor exit node" in x for x in res["reasons"])
    assert abuse.call_count == 1 and vt.call_count == 1

    # Drugi put dolazi iz keša, provajderi se ne zovu
    r2 = client.post("/api/ioc/lookup", json={"input": "185.220.101.1"}).json()
    assert all(p["cached"] for p in r2["results"][0]["providers"])
    assert abuse.call_count == 1 and vt.call_count == 1


@respx.mock
def test_hash_not_found_and_domain_clean(client):
    respx.get(f"{VT_BASE}/files/44d88612fea8a8f36de82e1278abb02f").mock(return_value=httpx.Response(404))
    respx.get(f"{VT_BASE}/domains/example.org").mock(return_value=httpx.Response(200, json=VT_CLEAN))

    r = client.post("/api/ioc/lookup", json={"input": "44d88612fea8a8f36de82e1278abb02f example.org"}).json()
    by_type = {x["type"]: x for x in r["results"]}
    assert by_type["md5"]["verdict"] == "unknown"
    assert by_type["domain"]["verdict"] == "clean"
    # AbuseIPDB radi samo IP adrese, za domen se ne pita
    assert [p["provider"] for p in by_type["domain"]["providers"]] == ["virustotal"]


@respx.mock
def test_internal_ip_never_leaves(client):
    route = respx.get(url__regex=r".*").mock(return_value=httpx.Response(500))
    r = client.post("/api/ioc/lookup", json={"input": "10.0.0.5"}).json()
    assert r["results"][0]["verdict"] == "internal"
    assert route.call_count == 0


@respx.mock
def test_rate_limit_is_reported_not_cached(client):
    respx.get(ABUSE_URL).mock(return_value=httpx.Response(429))
    respx.get(f"{VT_BASE}/ip_addresses/45.155.205.233").mock(return_value=httpx.Response(429))

    r = client.post("/api/ioc/lookup", json={"input": "45.155.205.233"}).json()
    statuses = {p["provider"]: p["status"] for p in r["results"][0]["providers"]}
    assert statuses == {"abuseipdb": "rate_limited", "virustotal": "rate_limited"}
    assert r["results"][0]["verdict"] == "unknown"
    assert any("rate limit" in x for x in r["results"][0]["reasons"])


def test_extract_endpoint(client):
    r = client.post("/api/ioc/extract", json={"input": "hxxp://bad[.]site/x and 8.8.8.8"}).json()
    assert r["count"] == 2
    assert {i["type"] for i in r["iocs"]} == {"url", "ipv4"}
