# CAmap Nordics

**Interactive map of TLS certificate authority sovereignty for Nordic municipalities**

Inspired by [mxmap.ch](https://mxmap.ch) (David Huser) — where mxmap shows email providers,
CAmap shows **which certificate authority controls HTTPS** for each municipality website and
what "kill-switch" risk that implies.

Live: **https://koldex.github.io/ca-sovereignty-map/**

---

## What it shows

A certificate authority (CA) that has issued a TLS certificate can revoke it or refuse to
renew it. If that CA is headquartered in the US it is subject to the **CLOUD Act**, meaning
a US court order could compel it to act against any municipality's certificate. This project
maps that exposure across ~1 055 municipalities in Finland, Sweden, Norway and Denmark.

### Risk levels

| Level | Colour | Description | Example CAs |
|-------|--------|-------------|-------------|
| Critical | 🔴 Red | US CLOUD Act, direct revocation risk | DigiCert, Amazon, Google |
| High | 🟠 Orange-red | US jurisdiction, nonprofit | Let's Encrypt (ISRG) |
| Medium | 🟡 Orange | Allied non-EU or multinational | GlobalSign (BE/JP) |
| Low | 🔵 Blue | EU-controlled | HARICA (GR), Certum (PL) |
| Minimal | 🟢 Green | Nordic / national | Buypass (NO), Telia (SE) |
| Unknown | ⬜ Grey | No HTTPS or unrecognised CA | — |

---

## Architecture

### Three-phase pipeline

```
Phase 1  resolve-domains
         Wikidata SPARQL + domain guessing + DNS validation
         → municipality_domains.json (884 entries)

Phase 2  scan-certs
         asyncio SSL scan + DNS CAA probe + crt.sh CT logs
         → data.json + data.min.json

Phase 3  analyze
         Statistics: CA distribution, per-country breakdown
         → stdout report
```

### Repository layout

```
ca-sovereignty-map/
├── src/cert_sovereignty/      Python pipeline package
│   ├── models.py              Pydantic data models
│   ├── signatures.py          CA fingerprint database (18 CAs)
│   ├── tls.py                 asyncio SSL scanner + www fallback
│   ├── probes.py              DNS CAA + CT log probes
│   ├── classifier.py          Evidence aggregation + confidence scoring
│   ├── resolve.py             Municipality domain resolution
│   ├── pipeline.py            Orchestration + serialization
│   ├── analyze.py             Statistics reporting
│   ├── cli.py                 CLI entry points
│   ├── constants.py           Wikidata SPARQL, country configs, CCADB URLs
│   ├── dns.py                 DNS resolver (Quad9/Cloudflare fallback)
│   └── log.py                 Loguru configuration
├── scripts/
│   ├── generate_topojson.py   Download GISCO LAU → TopoJSON conversion
│   └── bootstrap_domains.py   Build municipality_domains.json from TopoJSON
├── tests/                     pytest test suite (≥90% coverage target)
├── .github/workflows/
│   ├── ci.yml                 Lint + test on push/PR
│   ├── nightly.yml            Nightly TLS scan → commit data.json
│   └── deploy.yml             GitHub Pages deploy
├── css/  js/                  Frontend (Leaflet, CARTO basemap)
├── index.html                 Map page
├── methodology.html           Methodology documentation
├── nordic-municipalities.topojson  Municipality boundaries (537 KB)
├── data.json                  Full scan output (~1.6 MB, pretty-printed)
├── data.min.json              Minified frontend payload
├── municipality_domains.json  Phase 1 output: municipality → domain
└── overrides.json             Manual domain corrections
```

### Key design decisions

| Decision | Rationale |
|----------|-----------|
| **asyncio SSL** as primary TLS scanner | OpenSSL subprocess timed out for ~40% of servers; asyncio handles SNI/ALPN natively |
| **www fallback** in scanner | ~10% of certs are only on the www subdomain |
| **GISCO LAU 2021** for boundaries | Single authoritative source for FI+SE+NO+DK at municipality level |
| **Weighted evidence aggregation** | Same pattern as mxmap: leaf (0.35) + inter (0.25) + root (0.15) + CAA (0.10) + CT (0.08) |
| **GitHub Pages** hosting | Free, simple; data files ≤2 MB fit well |
| **Pydantic frozen models** | Immutable data throughout the pipeline prevents accidental mutation |

---

## Quick Start (Development)

### Prerequisites

- [uv](https://docs.astral.sh/uv/) (Python package manager)
- Node.js + npx (for TopoJSON generation only)
- Python 3.12+

### Install

```bash
git clone https://github.com/koldex/ca-sovereignty-map
cd ca-sovereignty-map
uv sync --group dev
```

### Run the full pipeline

```bash
# Phase 1: resolve municipality domains (~8 minutes, DNS lookups)
uv run python scripts/bootstrap_domains.py

# Phase 2: scan TLS certificates (~15 minutes, 884 domains, concurrency 30)
uv run scan-certs --skip-ct --concurrency 30

# Phase 3: statistics report
uv run analyze
```

### Regenerate municipality boundaries

Only needed when GISCO data is updated or countries change:

```bash
uv run python scripts/generate_topojson.py
# Downloads ~125 MB GISCO file to .data_cache/, outputs 537 KB TopoJSON
```

### Run tests

```bash
uv run pytest --cov --cov-report=term-missing
uv run ruff check src tests
uv run ruff format src tests
```

---

## CLI Reference

| Command | Description |
|---------|-------------|
| `uv run resolve-domains [--countries FI SE NO DK]` | Phase 1: Wikidata domain resolution |
| `uv run python scripts/bootstrap_domains.py [--country FI]` | Phase 1 fallback: TopoJSON-based domain guessing |
| `uv run scan-certs [--skip-ct] [--concurrency 30] [--country FI]` | Phase 2: TLS scan |
| `uv run analyze [--json]` | Phase 3: statistics report |
| `uv run update-ccadb` | Refresh CCADB CA jurisdiction cache |
| `uv run python scripts/generate_topojson.py` | Regenerate municipality boundaries |

---

## Self-Hosting

### Option 1 — GitHub Pages (simplest)

Fork the repository and enable Pages from `Settings → Pages → Deploy from branch → main`.
The nightly GitHub Actions workflow (`nightly.yml`) runs `scan-certs` and commits updated
`data.json` / `data.min.json` automatically.

### Option 2 — UpCloud Helsinki + Coolify (~7 €/month)

Recommended for full sovereignty — Finnish jurisdiction, no US CLOUD Act exposure.

```bash
# 1. Create UpCloud server (Helsinki, Developer Plan)
#    OS: Ubuntu 24.04 LTS

# 2. Install Coolify (open-source Vercel alternative)
ssh root@YOUR_SERVER_IP
curl -fsSL https://cdn.coollabs.io/coolify/install.sh | bash

# 3. In Coolify UI (https://YOUR_SERVER_IP:8000):
#    - New project → Connect GitHub repo
#    - Set build command: npm ci && npm run build  (or static file serving)
#    - Set domain + SSL (use Buypass ACME for Norwegian jurisdiction)
```

### Option 3 — UpCloud Object Storage (~3 €/month, static only)

```bash
# Build static site
npm run build   # or just serve the repo root

# Sync to UpCloud Object Storage (Helsinki)
aws s3 sync . s3://camap-nordics/ \
    --endpoint-url https://fi-hel2.upcloudobjects.com \
    --exclude ".git/*" --exclude ".data_cache/*"
```

### GitHub Actions secrets needed for automated hosting

| Secret | Description |
|--------|-------------|
| `UPCLOUD_S3_ACCESS` | UpCloud Object Storage access key |
| `UPCLOUD_S3_SECRET` | UpCloud Object Storage secret key |

Store these in `Settings → Secrets → Actions` in your fork. Never commit them to the repo.

### TLS certificate for self-hosted deployment

For maximum sovereignty, use **Buypass** (Norwegian CA) instead of Let's Encrypt (US):

```
ACME directory: https://api.buypass.com/acme/directory
```

Configure in Coolify: `Settings → SSL → Custom ACME → Buypass`.

---

## Data formats

### `data.json` structure

```json
{
  "generated": "2026-03-24T22:31:44Z",
  "total": 884,
  "counts": { "us-controlled": 399, "eu-controlled": 49, "nordic": 32, ... },
  "municipalities": {
    "FI-049": {
      "id": "FI-049",
      "name": "Espoo",
      "country": "FI",
      "domain": "espoo.fi",
      "primary_ca": "Let's Encrypt (ISRG)",
      "jurisdiction": "us",
      "risk_level": "high",
      "category": "us-controlled",
      "classification_confidence": 90.0,
      "cert_chain": [...],
      "caa_records": ["letsencrypt.org"],
      "classification_signals": [...]
    }
  }
}
```

Municipality IDs follow the format `{COUNTRY}-{LAU_ID}` matching the GISCO LAU 2021 dataset:
`FI-049`, `SE-0180`, `NO-0301`, `DK-101`.

### `overrides.json` format

```json
{
  "FI-091": { "domain": "hel.fi", "reason": "Helsinki uses hel.fi not helsinki.fi" }
}
```

---

## Contributing

- Pull requests welcome, especially for `overrides.json` corrections
- New CA signatures go in `src/cert_sovereignty/signatures.py`
- Test coverage must stay ≥ 90%: `uv run pytest --cov`

---

## Licence

MIT or EUPL-1.2 — to be decided.

## Attribution

- [mxmap.ch](https://github.com/dbrgn/mxmap) by David Huser — architectural inspiration
- [Eurostat GISCO LAU 2021](https://gisco-services.ec.europa.eu/) — municipality boundaries (CC BY 4.0)
- [CCADB](https://ccadb.org) (Mozilla/Linux Foundation) — CA jurisdiction data
- [crt.sh](https://crt.sh) (DigiCert) — Certificate Transparency logs
- National statistics offices (Statistics Finland, SCB, SSB, DST) — municipality data
