# CAmap Nordics — Session Memory

**session_start:** 2026-03-24T19:32:00Z
**phase:** Initial scaffold creation

## Session summary

Created complete project scaffold from planning documents v2 + v3 + hosting plan.
All files generated in a single session.

## What was created

### Python package (src/cert_sovereignty/)
- models.py — Jurisdiction, RiskLevel, SignalKind, Evidence, CertChainEntry, ClassificationResult
- signatures.py — CASignature database (Let's Encrypt, DigiCert, Sectigo, Amazon, Google, GoDaddy, Cloudflare, Entrust, SSL.com, ZeroSSL, Microsoft, GlobalSign, HARICA, Certum, D-TRUST, SwissSign, Buypass, Telia)
- tls.py — OpenSSL subprocess scanner + Python ssl fallback
- probes.py — DNS CAA + crt.sh CT log probes
- classifier.py — Evidence aggregation, confidence rules (_CA_RULES)
- resolve.py — Wikidata SPARQL + domain guessing with Nordic character transliteration
- pipeline.py — scan_many() with semaphore, build_data_json(), write_output()
- analyze.py — compute_stats(), print_report()
- cli.py — resolve-domains, scan-certs, analyze, update-ccadb
- log.py — Loguru config
- constants.py — All constants, Wikidata SPARQL queries per country, CCADB URLs

### Tests (tests/)
- conftest.py — fixtures (letsencrypt_leaf, buypass_leaf, evidence, sample_data_json)
- test_signatures.py — match_patterns, CA database validation
- test_classifier.py — _aggregate, _rule_confidence, classify()
- test_tls.py — _extract_pem_certs, _parse_brief_output, _match_cert_to_ca
- test_probes.py — probe_caa (mocked), probe_ct_log error handling
- test_pipeline.py — serialize_result, build_data_json, write_output
- test_data_validation.py — compute_stats, data.json schema validation

### GitHub Actions
- ci.yml — ruff + pytest on push/PR
- nightly.yml — cron 02:00 UTC, scan-certs, commit data.json
- deploy.yml — GitHub Pages deploy on index.html/css/js/data changes

### Frontend
- index.html — Leaflet map, Finnish UI, CARTO basemap
- methodology.html — Finnish methodology page
- css/shared.css — CSS variables, nav, badges, utilities
- css/map.css — Map layout, legend, popup, chain visualization
- css/content.css — Content page typography
- js/map-shared.js — initMap, buildPopup, getMuniColor, addLegend, fetchMapData
- js/nav.js — Active link highlighting

### Data files
- overrides.json — Helsinki (hel.fi), Espoo, Stockholm, Oslo, Copenhagen
- municipality_domains.json — empty array (populated by resolve-domains)
- data.json — empty template
- CLAUDE.md — AI context (English)
- ai_context.md — AI context (Finnish)
- README.md — Finnish README
- LICENCE — placeholder

## Known issues to fix

1. tls.py has unused `hashlib` import and dead code in `_parse_x509_cert`
2. pipeline.py uses dynamic `__import__` for models — should use direct imports
3. resolve.py constants reference `HTTP_TIMEOUT` from constants.py (verify it's defined there ✓)

## Handoff notes

Next session should:
1. Run `uv sync` to install dependencies
2. Fix tls.py import issues
3. Run pytest to verify baseline passes
4. Generate nordic-municipalities.topojson
5. Run first resolve-domains scan
