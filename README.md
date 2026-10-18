<p align="center"><img src="frontend/assets/gufetto.svg" alt="Gufetto" width="180"></p>

<h1 align="center">Gufetto</h1>

**SOC triage assistant.** Paste an alert, a log line or an email, and Gufetto pulls out the indicators, checks them against threat-intel sources and tells you *why* something looks bad, not just a number.

> *Gufetto* is Italian for "little owl": the one that keeps watch through the night shift.

## Status

| Module | Status |
|---|---|
| IOC enrichment (AbuseIPDB, VirusTotal) | ✅ v0.1 |
| Email / phishing analysis | ⏳ planned |
| EDR alert triage + MITRE ATT&CK mapping | ⏳ planned |
| Network analyzer (DNS/DGA, firewall logs: Fortinet, pfSense, iptables) | ⏳ planned |

## What the IOC module does

- Extracts IPv4/IPv6, domains, URLs and MD5/SHA1/SHA256 hashes from free text
- Understands defanged input (`hxxps://evil[.]com`) and shows results defanged, so nothing is clickable by accident
- **Never sends internal indicators outside** (RFC1918, loopback, `.local`, `.corp`...)
- Queries AbuseIPDB (IPs) and VirusTotal (everything) in parallel
- Combines results into a verdict (`malicious` / `suspicious` / `clean` / `unknown`) with human-readable reasons
- Caches results in the database (24h by default) to stay inside free API limits (VirusTotal free: 4 req/min)
- Ignores file names that look like domains (`invoice.pdf`, `run.ps1`)

### Scoring

| Source | Score 0-100 |
|---|---|
| AbuseIPDB | `abuseConfidenceScore` as-is |
| VirusTotal | `0` if no detections, else `30 + 7×malicious + 2×suspicious` (capped at 100) |

The final score is the **highest** of the sources: in triage it's better to escalate a false positive than to miss something one source clearly sees.
Verdict: `≥60` malicious, `≥25` suspicious, below that clean.

## Architecture

```
browser ──▶ nginx :8080 ──┬──▶ /        static frontend
                          └──▶ /api/*   FastAPI :8000 ──▶ SQL Server 2022
                                              │
                                              └──▶ AbuseIPDB, VirusTotal
```

```
gufetto/
├── docker-compose.yml
├── nginx/nginx.conf
├── frontend/index.html
└── backend/
    ├── Dockerfile
    ├── app/
    │   ├── main.py, config.py, db.py, models.py
    │   └── modules/ioc/
    │       ├── detect.py       # extraction, refang/defang
    │       ├── providers/      # abuseipdb.py, virustotal.py
    │       ├── scoring.py      # verdict + reasons
    │       ├── service.py      # cache -> providers -> verdict
    │       └── router.py       # /api/ioc/*
    └── tests/
```

Each future module (email, EDR, network) goes into its own folder under `app/modules/`.

## Running it

### With Docker (full stack)

```bash
cp .env.example .env      # add your API keys and a strong SA password
docker compose up -d --build
```

Open http://localhost:8080. API docs are at http://localhost:8080/api/docs.

SQL Server takes ~30 s to start the first time; the backend waits for its healthcheck.
The SQL Server image is amd64 only. On an ARM machine (Apple Silicon) enable Rosetta emulation in Docker Desktop, or run locally with SQLite instead.

### From Docker Hub (no build needed)

You only need `docker-compose.yml` and a filled-in `.env` (with `DOCKERHUB_USER` set to the account that published the images):

```bash
docker compose pull
docker compose up -d --no-build
```

### Publishing images

```bash
docker login
docker compose build
docker compose push backend web
```

Pushes `<DOCKERHUB_USER>/gufetto-backend` and `<DOCKERHUB_USER>/gufetto-web`. No secrets go into the images: `.env` is excluded and keys are passed at runtime.

### Locally, without Docker (SQLite)

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install fastapi "uvicorn[standard]" sqlalchemy httpx pydantic-settings pytest respx
cp ../.env.example .env   # keep DATABASE_URL=sqlite:///./gufetto.db
uvicorn app.main:app --reload
```

The API runs on http://localhost:8000/api/docs. To use the UI locally, serve `frontend/` behind a proxy, or just use the Docker setup.

### Tests

```bash
cd backend && pytest
```

Tests mock both APIs (respx), so no keys or network are needed.

## API

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/health` | Status and which providers have keys |
| `POST` | `/api/ioc/extract` | `{"input": "..."}` → indicators found, nothing sent anywhere |
| `POST` | `/api/ioc/lookup` | `{"input": "...", "force_refresh": false}` → verdicts, max 20 indicators per call |

## Roadmap

- [ ] Alembic migrations instead of `create_all`
- [ ] Email module: header parsing (SPF/DKIM/DMARC, received chain), URL and attachment hash extraction
- [ ] EDR alert triage with MITRE ATT&CK technique mapping
- [ ] Network analyzer: firewall log parsing, DGA detection
- [ ] More sources: AlienVault OTX, URLhaus, GreyNoise
- [ ] Auth for the UI
