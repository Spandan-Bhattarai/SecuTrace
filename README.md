# SecuTrace - Threat Intelligence Platform

SecuTrace is a privacy-focused threat intelligence aggregation platform that queries multiple security services and returns a consolidated risk view for IPs, domains, URLs, hashes, CVEs, and software package indicators.

## Features

- Multi-source lookups with parallel execution
- Correlation engine (entity extraction + graph relationships)
- Confidence scoring engine (weighted source scoring + context boost)
- Quick external links and per-source full result links
- No server-side query storage

## Active Integrations

| Service | Indicator Support | API Key |
|---|---|---|
| VirusTotal | IP, domain, URL, hash | Required |
| AbuseIPDB | IP | Required |
| Shodan | IP | Required |
| AlienVault OTX | IP, domain, URL, hash | Required |
| IPInfo | IP | Required |
| URLhaus | URL, domain | Via THREATFOX_API_KEY |
| ThreatFox | IP, domain, URL, hash | Required |
| MalwareBazaar | hash | Not required |
| DShield | IP | Not required |
| NVD | CVE/software | Not required |
| OSV | CVE/software | Not required |

## Why DShield Instead of Talos

Talos public endpoints are commonly blocked by Cloudflare for automated server-side requests. DShield provides a stable free IP intelligence endpoint suitable for backend automation.

## Quick Start

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Configure environment:

```bash
cp .env.example .env
```

3. Run locally:

```bash
python app.py
```

4. Open:

```text
http://localhost:5000
```

## Configuration

Use [.env.example](.env.example) and set keys only for the services you want.

Required for full coverage:
- VIRUSTOTAL_API_KEY
- ABUSEIPDB_API_KEY
- SHODAN_API_KEY
- ALIENVAULT_OTX_API_KEY
- IPINFO_API_KEY
- THREATFOX_API_KEY

No-key connectors:
- MalwareBazaar
- DShield
- NVD
- OSV

## API Endpoints

- `GET /` - UI
- `POST /api/lookup` - lookup across all active sources
- `POST /api/lookup/<source>` - lookup a single source
- `GET /api/sources` - source status

## Deployment

Render config is included in `render.yaml`.

## Security Note

Do not commit real API keys in `.env` to git. Rotate any key that has already been committed.
