"""Municipality domain resolution.

Two-phase process (cf. mxmap's resolve.py):
1. Query Wikidata SPARQL for official municipality websites per country
2. Fall back to domain guessing (slugified name + country TLD variations)
3. Validate domains via DNS A/AAAA lookup
4. Apply manual overrides from overrides.json
"""

from __future__ import annotations

import json
import re
import unicodedata
from pathlib import Path

import httpx
import stamina
from loguru import logger

from .constants import (
    COUNTRY_TLDS,
    NORDIC_TRANSLITERATIONS,
    SKIP_DOMAINS,
    WIKIDATA_QUERIES,
    WIKIDATA_SPARQL_ENDPOINT,
    HTTP_TIMEOUT,
)
from .dns import domain_resolves


# ── Wikidata SPARQL ───────────────────────────────────────────────────────────


@stamina.retry(
    on=(httpx.HTTPStatusError, httpx.ConnectError, httpx.TimeoutException),
    attempts=3,
    wait_initial=2.0,
)
async def _sparql_query(query: str) -> list[dict]:
    """Execute a Wikidata SPARQL query and return bindings."""
    headers = {
        "Accept": "application/sparql-results+json",
        "User-Agent": "CAmap-Nordics/0.1 (https://github.com/camap-nordics)",
    }
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT) as client:
        r = await client.get(
            WIKIDATA_SPARQL_ENDPOINT,
            params={"query": query, "format": "json"},
            headers=headers,
        )
        r.raise_for_status()
        data = r.json()
        return data["results"]["bindings"]


async def fetch_wikidata_domains(country: str) -> dict[str, str]:
    """Fetch official municipality websites from Wikidata for a country.

    Returns dict: municipality_code → website URL
    """
    query = WIKIDATA_QUERIES.get(country)
    if not query:
        logger.warning("No Wikidata query defined for country {}", country)
        return {}

    logger.info("Querying Wikidata for {} municipalities...", country)
    try:
        bindings = await _sparql_query(query)
    except Exception as e:
        logger.error("Wikidata query failed for {}: {}", country, e)
        return {}

    domains: dict[str, str] = {}
    for row in bindings:
        code = row.get("code", {}).get("value", "")
        website = row.get("website", {}).get("value", "")
        label = row.get("itemLabel", {}).get("value", "")

        if not code:
            continue

        if website:
            domain = _extract_domain(website)
            if domain and not _is_skip_domain(domain):
                domains[f"{country}-{code}"] = domain
                logger.debug("Wikidata: {}-{} ({}) → {}", country, code, label, domain)

    logger.info("Got {} domains from Wikidata for {}", len(domains), country)
    return domains


# ── Domain slug generation ────────────────────────────────────────────────────


def _slugify_name(name: str) -> list[str]:
    """Generate URL-safe slugs from a municipality name.

    Handles Nordic special characters (ä, ö, å, ø, æ, ð, þ).
    Returns multiple variants (with and without transliteration).
    """
    # Lowercase
    name_lower = name.lower()

    # Transliterate Nordic characters
    transliterated = ""
    for char in name_lower:
        transliterated += NORDIC_TRANSLITERATIONS.get(char, char)

    # Replace spaces and hyphens with hyphens
    slug = re.sub(r"[\s-]+", "-", transliterated)

    # Remove non-ASCII characters
    slug = re.sub(r"[^a-z0-9-]", "", slug)
    slug = slug.strip("-")

    # Also try NFD normalization (removes combining diacritics)
    nfd = unicodedata.normalize("NFD", name_lower)
    ascii_slug = re.sub(r"[^a-z0-9\s-]", "", nfd)
    ascii_slug = re.sub(r"[\s-]+", "-", ascii_slug).strip("-")

    slugs = list(dict.fromkeys([slug, ascii_slug]))  # deduplicate, preserve order
    return [s for s in slugs if s]  # filter empty


def guess_domains(name: str, country: str, region: str = "") -> list[str]:
    """Generate plausible domain guesses for a Nordic municipality.

    Cf. mxmap's guess_domains() for Swiss municipalities.
    """
    slugs = _slugify_name(name)
    tld = COUNTRY_TLDS.get(country, "eu")
    candidates: set[str] = set()

    for slug in slugs:
        if not slug:
            continue

        candidates.add(f"{slug}.{tld}")
        candidates.add(f"www.{slug}.{tld}")

        if country == "SE":
            candidates.add(f"{slug}.kommun.se")
            candidates.add(f"www.{slug}.se")
        elif country == "NO":
            candidates.add(f"{slug}.kommune.no")
            candidates.add(f"www.{slug}.kommune.no")
        elif country == "DK":
            candidates.add(f"{slug}.dk")
        elif country == "FI":
            candidates.add(f"{slug}.fi")

    return sorted(candidates)


# ── Domain validation ─────────────────────────────────────────────────────────


def _extract_domain(url: str) -> str:
    """Extract bare domain from a URL."""
    # Strip protocol
    url = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)
    # Strip path and query
    domain = url.split("/")[0].split("?")[0].split("#")[0]
    # Strip www.
    if domain.startswith("www."):
        domain = domain[4:]
    return domain.lower().strip()


def _is_skip_domain(domain: str) -> bool:
    """Check if domain should be skipped."""
    for skip in SKIP_DOMAINS:
        if domain.endswith(skip):
            return True
    return False


async def validate_domain(domain: str) -> bool:
    """Check if a domain has DNS records and is reachable."""
    if not domain or _is_skip_domain(domain):
        return False
    return await domain_resolves(domain)


# ── Overrides ─────────────────────────────────────────────────────────────────


def load_overrides(overrides_path: Path) -> dict[str, dict]:
    """Load manual domain overrides from overrides.json."""
    if not overrides_path.exists():
        logger.warning("overrides.json not found at {}", overrides_path)
        return {}
    with open(overrides_path) as f:
        return json.load(f)


# ── Main resolution entry point ───────────────────────────────────────────────


async def resolve_municipality_domain(
    municipality_id: str,
    name: str,
    country: str,
    wikidata_domains: dict[str, str],
    overrides: dict[str, dict],
    region: str = "",
) -> str | None:
    """Resolve the best domain for a municipality.

    Priority order:
    1. Manual override (overrides.json)
    2. Wikidata official website
    3. Domain guess (validated via DNS)
    """
    # Priority 1: manual override
    if municipality_id in overrides:
        return overrides[municipality_id].get("domain")

    # Priority 2: Wikidata
    if municipality_id in wikidata_domains:
        domain = wikidata_domains[municipality_id]
        if await validate_domain(domain):
            return domain
        logger.debug("Wikidata domain {} for {} does not resolve", domain, municipality_id)

    # Priority 3: domain guessing
    for candidate in guess_domains(name, country, region):
        if await validate_domain(candidate):
            logger.debug("Guessed domain {} for {}", candidate, municipality_id)
            return candidate

    logger.warning("No domain found for {} ({})", municipality_id, name)
    return None
