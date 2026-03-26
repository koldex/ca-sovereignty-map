# CAmap Nordic & Baltic — AI Agent Context

## Project summary

Interactive map of TLS certificate authority (CA) sovereignty for Nordic municipalities
(FI, SE, NO, DK, EE, LV, LT). Maps kill-switch risk: US-controlled CAs (CLOUD Act) vs EU/Nordic CAs.

**Live:** https://koldex.github.io/ca-sovereignty-map/
**Inspired by:** mxmap.ch (David Huser) → mxmap.nl (Soverin/Andre)

## Quick commands

```bash
uv sync --group dev                              # install dependencies
uv run python scripts/bootstrap_domains.py      # Phase 1: resolve domains
uv run scan-certs --skip-ct --concurrency 30    # Phase 2: TLS scan
uv run analyze                                  # Phase 3: statistics
uv run pytest --cov                             # run tests
uv run ruff check src tests && uv run ruff format src tests  # lint/format
uv run python scripts/generate_topojson.py     # regenerate TopoJSON
```

## Architecture

Pipeline: **bootstrap_domains.py → scan-certs → data.json → GitHub Pages**

Key modules:
- `tls.py` — asyncio SSL scanner (primary), www fallback, no OpenSSL subprocess
- `dns.py` — DNS lookup with Quad9/Cloudflare fallback (use `dns.resolver.NXDOMAIN`, NOT `dns.exception.NXDOMAIN`)
- `signatures.py` — CA fingerprint database (18 CAs, pattern matching)
- `classifier.py` — weighted evidence aggregation, confidence scoring
- `pipeline.py` — scan_many() with semaphore (concurrency 50), builds data.json
- `resolve.py` — domain guessing + Wikidata SPARQL (User-Agent required)

## Data sources

- **Municipality boundaries:** Eurostat GISCO LAU 2021 (CC BY 4.0), cached at `.data_cache/`
- **Municipality domains:** Wikidata SPARQL → domain guessing → DNS validation
- **CA jurisdiction:** CCADB (Mozilla/Linux Foundation)
- **CT logs:** crt.sh API (optional, `--skip-ct` disables)

## Known limitations / pending improvements

- ~45% classified as "Unknown" — HTTP-only, CDN proxy, or slow/refusing TLS connections
- Wikidata SPARQL needs proper User-Agent to avoid 403 rate limits
- Norway: many municipalities use shared hosting (Framsikt, WebCruiter etc.)
- Sweden: some use `.kommun.se` others use `.se` directly
- Domain guessing is not perfect; `overrides.json` is the correction mechanism

## Municipality ID format

`{COUNTRY}-{LAU_ID}` — exactly matching GISCO LAU 2021 GISCO_ID field with `_` → `-`
Examples: `FI-049` (Espoo), `SE-0180` (Stockholm), `NO-0301` (Oslo), `DK-101` (Copenhagen)

## Hosting recommendation

UpCloud Helsinki + Coolify (~7 €/month) — Finnish jurisdiction, no US CLOUD Act.
TLS: Telia Certificate Service (ACME, `https://acme.trust.telia.com/directory`) for Nordic sovereignty.

## Important bugs fixed

1. `dns.py`: `dns.resolver.NXDOMAIN` not `dns.exception.NXDOMAIN` (was causing 821 failures)
2. `tls.py`: replaced OpenSSL subprocess with asyncio SSL (was causing 372 timeouts)
3. `index.html`: Leaflet JS SRI hash was wrong (`...XV/XN/sp8=` → `...XV1lvTlZBo=`)
4. `data.min.json`: was in .gitignore — now committed (required by GitHub Pages)
