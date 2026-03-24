# CAmap Nordics — AI Session Context

**last_verified:** 2026-03-24T21:16:00Z
**project_version:** 0.1.2
**status:** Active development — scan results live on GitHub Pages

## Current state

- 884 municipalities with resolved domains (FI:299, SE:288, NO:204, DK:93)
- Scan results: 399 US-controlled (45%), 49 EU (6%), 32 Nordic (4%), 404 unknown (46%)
- Unknown breakdown: ~372 were OpenSSL timeouts → FIXED with asyncio SSL rewrite
- GitHub Pages: https://koldex.github.io/ca-sovereignty-map/
- Map was broken (Leaflet SRI hash wrong + data.min.json not committed) → both FIXED

## Key files changed in this session

- `tls.py`: rewritten to use asyncio SSL as primary (eliminates subprocess timeout issues)
- `dns.py`: fixed `dns.resolver.NXDOMAIN` (was `dns.exception.NXDOMAIN` → 821 failures)
- `index.html`, `methodology.html`, `js/map-shared.js`: converted to English
- `README.md`: comprehensive rewrite with architecture + deployment docs
- `CLAUDE.md`, `ai_context.md`: updated to English

## Pending tasks for next session

1. Re-run `bootstrap_domains.py` + `scan-certs` with improved asyncio SSL scanner
2. Commit + push updated data.json / data.min.json
3. Investigate remaining ~45% unknown:
   - Likely HTTP-only or shared hosting (esp. Norway/Sweden)
   - Some may need overrides.json entries
4. Add more overrides.json corrections
5. Consider adding Iceland (IS) municipalities

## Architecture decisions log

| Date | Decision | Reason |
|------|----------|--------|
| 2026-03-24 | asyncio SSL as primary TLS scanner | OpenSSL subprocess timed out for 372/884 domains |
| 2026-03-24 | www fallback in scanner | ~10% of certs are on www subdomain only |
| 2026-03-24 | GISCO LAU 2021 for boundaries | Best single source for FI+SE+NO+DK municipalities |
| 2026-03-24 | domain priority order fix | slug.fi before www.slug.fi (alphabetical was wrong) |
