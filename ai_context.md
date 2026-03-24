# CAmap Nordics — AI Context

**last_verified:** 2026-03-24T19:32:00Z
**project_version:** 0.1.0 (scaffold)
**status:** Project scaffold created, ready for development

## Project summary

Interactive map showing TLS certificate authority (CA) sovereignty of Nordic municipalities.
Identifies which municipalities use US-controlled CAs (CLOUD Act kill-switch risk) vs.
EU/Nordic CAs.

**Countries:** FI (~309), SE (~290), NO (~356), DK (~98) = ~1053 municipalities total
**Data pipeline:** resolve-domains → scan-certs → analyze → frontend

## Architecture decisions

- **mxmap-inspired:** Two-phase pipeline (domain resolution + classification)
- **OpenSSL subprocess** for TLS scanning (more reliable than Python ssl for full chain)
- **CCADB** as authoritative CA jurisdiction source
- **Pydantic models** for all data structures (frozen=True for immutability)
- **Semaphore-limited concurrency** (50 for TLS, 20 for HTTP)
- **Weighted evidence aggregation** (leaf issuer 0.35, intermediate 0.25, root 0.15, CAA 0.10, CT 0.08)
- **Confidence rules** matching mxmap's _PROVIDER_RULES pattern
- **Leaflet + TopoJSON + Canvas renderer** for frontend
- **CARTO Positron** basemap (same as mxmap)

## Risk classification

| Jurisdiction | Risk | Example CAs |
|---|---|---|
| US | CRITICAL/HIGH | DigiCert, Google, Amazon, Let's Encrypt |
| EU | LOW | HARICA, Certum, D-TRUST, GlobalSign |
| NORDIC | MINIMAL | Buypass (NO) |
| ALLIED | MEDIUM | SwissSign (CH) |
| OTHER | MEDIUM | Unknown |

## Key files

- `src/cert_sovereignty/` — Python package
- `tests/` — pytest test suite (90% coverage target)
- `.github/workflows/` — CI, nightly scan, deploy
- `index.html` — Leaflet map (Finnish UI)
- `methodology.html` — methodology page (Finnish)
- `overrides.json` — manual domain corrections
- `data.json` / `data.min.json` — scan output (pipeline-generated)
- `municipality_domains.json` — phase 1 output (empty initially)

## Pending tasks

1. Generate `nordic-municipalities.topojson` from national GeoJSON sources
2. Run `uv run resolve-domains` to populate municipality_domains.json
3. First scan: `uv run scan-certs`
4. Fix any import issues in tls.py (unused hashlib import)
5. Deploy to UpCloud Helsinki + Coolify
6. Set GitHub repository URL in index.html and methodology.html
7. Decide on license (MIT vs EUPL-1.2)

## Hosting plan

- **Provider:** UpCloud Helsinki (Finnish jurisdiction, GDPR)
- **Platform:** Coolify (self-hosted PaaS, open source)
- **Cost:** ~7 €/month (VPS) or ~3 €/month (Object Storage static)
- **TLS cert:** Buypass (Norwegian ACME) for sovereignty dogfooding
- **Domain:** .fi (Traficom/Ficora) — Finnish registry
- **CI/CD:** GitHub Actions (code only, no sensitive data)

## AI Agent sync

- Last Warp AI update: 2026-03-24T19:32:00Z
- Related files: CLAUDE.md (same content, English)
- Cross-references: none
