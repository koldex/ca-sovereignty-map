"""Constants: Wikidata SPARQL queries, country configs, skip lists.

Each Nordic country has its own municipality Wikidata item class and
official municipal code property.
"""

from __future__ import annotations

# ── Countries covered ─────────────────────────────────────────────────────────

COUNTRIES: list[str] = ["FI", "SE", "NO", "DK", "EE", "LV", "LT"]
# IS (Iceland) omitted by default — only ~70 municipalities

COUNTRY_NAMES: dict[str, str] = {
    "FI": "Finland",
    "SE": "Sweden",
    "NO": "Norway",
    "DK": "Denmark",
    "IS": "Iceland",
    "EE": "Estonia",
    "LV": "Latvia",
    "LT": "Lithuania",
}

COUNTRY_TLDS: dict[str, str] = {
    "FI": "fi",
    "SE": "se",
    "NO": "no",
    "DK": "dk",
    "IS": "is",
    "EE": "ee",
    "LV": "lv",
    "LT": "lt",
}

# ── Wikidata SPARQL queries per country ───────────────────────────────────────
# Each query returns: item, itemLabel, officialWebsite, municipalCode
# Cf. mxmap's WIKIDATA_QUERY for Swiss municipalities

WIKIDATA_SPARQL_ENDPOINT = "https://query.wikidata.org/sparql"

# Finnish municipalities: wd:Q515501 = "municipality of Finland"
WIKIDATA_QUERY_FI = """
SELECT ?item ?itemLabel ?website ?code WHERE {
  ?item wdt:P31 wd:Q515501 .
  OPTIONAL { ?item wdt:P856 ?website . }
  OPTIONAL { ?item wdt:P440 ?code . }
  SERVICE wikibase:label { bd:serviceParam wikibase:language "fi,sv,en" . }
}
ORDER BY ?code
"""

# Swedish municipalities: wd:Q127448 = "municipality of Sweden"
WIKIDATA_QUERY_SE = """
SELECT ?item ?itemLabel ?website ?code WHERE {
  ?item wdt:P31 wd:Q127448 .
  OPTIONAL { ?item wdt:P856 ?website . }
  OPTIONAL { ?item wdt:P525 ?code . }
  SERVICE wikibase:label { bd:serviceParam wikibase:language "sv,en" . }
}
ORDER BY ?code
"""

# Norwegian municipalities: wd:Q755707 = "municipality of Norway"
WIKIDATA_QUERY_NO = """
SELECT ?item ?itemLabel ?website ?code WHERE {
  ?item wdt:P31 wd:Q755707 .
  OPTIONAL { ?item wdt:P856 ?website . }
  OPTIONAL { ?item wdt:P2504 ?code . }
  SERVICE wikibase:label { bd:serviceParam wikibase:language "nb,nn,en" . }
}
ORDER BY ?code
"""

# Danish municipalities: wd:Q1198380 = "municipality of Denmark"
WIKIDATA_QUERY_DK = """
SELECT ?item ?itemLabel ?website ?code WHERE {
  ?item wdt:P31 wd:Q1198380 .
  OPTIONAL { ?item wdt:P856 ?website . }
  OPTIONAL { ?item wdt:P1168 ?code . }
  SERVICE wikibase:label { bd:serviceParam wikibase:language "da,en" . }
}
ORDER BY ?code
"""


# Estonian municipalities: wd:Q748664 = "omavalitsus" (Estonian municipality)
WIKIDATA_QUERY_EE = """
SELECT ?item ?itemLabel ?website ?code WHERE {
  ?item wdt:P31 wd:Q748664 .
  OPTIONAL { ?item wdt:P856 ?website . }
  OPTIONAL { ?item wdt:P1260 ?code . }
  SERVICE wikibase:label { bd:serviceParam wikibase:language "et,en" . }
}
ORDER BY ?code
"""

# Latvian municipalities: wd:Q1967285 = "novads" (Latvian municipality)
WIKIDATA_QUERY_LV = """
SELECT ?item ?itemLabel ?website ?code WHERE {
  ?item wdt:P31/wdt:P279* wd:Q1967285 .
  OPTIONAL { ?item wdt:P856 ?website . }
  OPTIONAL { ?item wdt:P1260 ?code . }
  SERVICE wikibase:label { bd:serviceParam wikibase:language "lv,en" . }
}
ORDER BY ?code
"""

# Lithuanian municipalities: wd:Q586272 = "savivaldybė" (Lithuanian municipality)
WIKIDATA_QUERY_LT = """
SELECT ?item ?itemLabel ?website ?code WHERE {
  ?item wdt:P31 wd:Q586272 .
  OPTIONAL { ?item wdt:P856 ?website . }
  OPTIONAL { ?item wdt:P511 ?code . }
  SERVICE wikibase:label { bd:serviceParam wikibase:language "lt,en" . }
}
ORDER BY ?code
"""

WIKIDATA_QUERIES: dict[str, str] = {
    "FI": WIKIDATA_QUERY_FI,
    "SE": WIKIDATA_QUERY_SE,
    "NO": WIKIDATA_QUERY_NO,
    "DK": WIKIDATA_QUERY_DK,
    "EE": WIKIDATA_QUERY_EE,
    "LV": WIKIDATA_QUERY_LV,
    "LT": WIKIDATA_QUERY_LT,
}

# ── Official national APIs ─────────────────────────────────────────────────────
# Used for authoritative municipality lists

NATIONAL_API_URLS: dict[str, str] = {
    # Statistics Finland: list of municipalities
    "FI": "https://data.stat.fi/api/classifications/v2/classifications/kunta_1_20240101/classificationItems?content=data&meta=max&lang=fi&format=json",
    # SCB: Swedish municipalities
    "SE": "https://api.scb.se/OV0104/v1/doris/sv/ssd/START/OE/OE0101/OE0101B/LanKommun",
    # SSB: Norwegian municipalities
    "NO": "https://data.ssb.no/api/v0/no/table/10826",
    # Danmarks Statistik
    "DK": "https://api.statbank.dk/v1/tableinfo/REGK11",
}

# ── Domains to skip ───────────────────────────────────────────────────────────
# Cf. mxmap's SKIP_DOMAINS

SKIP_DOMAINS: frozenset[str] = frozenset(
    [
        # Generic / redirect domains
        "kommuner.se",
        "kommune.no",
        "kunta.fi",
        # Known CDN/proxy endpoints
        "cloudfront.net",
        "azurewebsites.net",
        "pages.dev",
        # Latvian municipality shared portal — ABANDONED/PARKED.
        # novads.lv is registered to a Russian domain parking service
        # (DomainParking.ru, cert *.domainparking.ru). All *.novads.lv
        # subdomains resolve to a 'domain for sale' page.
        # Latvia reformed from 119 → 43+9 municipalities in July 2021;
        # the old shared portal was never transferred to the new entities.
        "novads.lv",
        # Specific Latvian domains parked by DomainParking.ru
        "lielvardes.lv",  # 'lielvardes.lv is for sale' (DomainParking.ru)
        # Wrong Lithuanian domains
        "traku.lt",  # Redirects to facebook.com/traku.turtas (real estate), not municipality
    ]
)

# ── Nordic character transliteration ─────────────────────────────────────────
# For slug generation from municipality names
# Cf. mxmap's umlaut handling

NORDIC_TRANSLITERATIONS: dict[str, str] = {
    # Finnish/Swedish
    "ä": "a",
    "ö": "o",
    "å": "a",
    "ü": "u",
    # Norwegian/Danish
    "ø": "o",
    "æ": "ae",
    # Icelandic
    "ð": "d",
    "þ": "th",
    "í": "i",
    "ó": "o",
    "ú": "u",
    "ý": "y",
    "é": "e",
    "á": "a",
    # Estonian
    "õ": "o",
    # Latvian
    "ā": "a",
    "č": "c",
    "ē": "e",
    "ģ": "g",
    "ī": "i",
    "ķ": "k",
    "ļ": "l",
    "ņ": "n",
    "š": "s",
    "ū": "u",
    "ž": "z",
    # Lithuanian (č š ž shared above)
    "ą": "a",
    "ę": "e",
    "ė": "e",
    "į": "i",
    "ų": "u",
}

# ── Geopolitical risk regions ─────────────────────────────────────────────────

GEOPOLITICAL_REGIONS: dict[str, dict] = {
    "FIVE_EYES": {
        "countries": {"US", "GB", "CA", "AU", "NZ"},
        "label": "Five Eyes",
        "risk": "CRITICAL",
        "color": "#e74c3c",
        "legal_framework": "US CLOUD Act, UK Investigatory Powers Act, CA CSIS Act",
        "description": (
            "Intelligence-sharing alliance — broadest legal powers to compel CA action"
        ),
    },
    "EU_EEA": {
        "countries": {
            "AT",
            "BE",
            "BG",
            "HR",
            "CY",
            "CZ",
            "DK",
            "EE",
            "FI",
            "FR",
            "DE",
            "GR",
            "HU",
            "IE",
            "IT",
            "LV",
            "LT",
            "LU",
            "MT",
            "NL",
            "PL",
            "PT",
            "RO",
            "SK",
            "SI",
            "ES",
            "SE",
            "IS",
            "LI",
            "NO",
        },
        "label": "EU/EEA",
        "risk": "LOW",
        "color": "#3498db",
        "legal_framework": "GDPR, eIDAS 2.0, EU Cybersecurity Act",
        "description": "EU law protects — Schrems II limits data transfers to third countries",
    },
    "NORDIC": {
        "countries": {"FI", "SE", "NO", "DK", "IS"},
        "label": "Nordic",
        "risk": "MINIMAL",
        "color": "#2ecc71",
        "legal_framework": "National data protection laws + GDPR",
        "description": "Nordic jurisdiction — highest trust level for Nordic municipalities",
    },
    "NINE_EYES": {
        "countries": {"US", "GB", "CA", "AU", "NZ", "DK", "FR", "NL", "NO"},
        "label": "Nine Eyes",
        "risk": "MEDIUM",
        "color": "#f39c12",
        "note": "DK, FR, NL, NO are also EU/EEA — EU law protects, but intelligence risk remains",
    },
    "ALLIED_NON_EU": {
        "countries": {"JP", "CH", "KR", "TW", "SG", "IL"},
        "label": "Allied non-EU",
        "risk": "MEDIUM",
        "color": "#f39c12",
        "legal_framework": "Varies by country",
        "description": "No EU protection, but no direct US CLOUD Act risk",
    },
    "ADVERSARIAL": {
        "countries": {"CN", "RU", "BY", "IR", "KP"},
        "label": "Adversarial jurisdiction",
        "risk": "CRITICAL",
        "color": "#8e44ad",
        "description": ("States with significant geopolitical tensions with Western democracies"),
    },
}

# ── Category mapping (for frontend color coding) ─────────────────────────────

CATEGORY_MAP: dict[str, str] = {
    "us": "us-controlled",
    "eu": "eu-controlled",
    "nordic": "nordic",
    "allied": "allied",
    "other": "unknown",
}

# ── Scan configuration ────────────────────────────────────────────────────────

DEFAULT_PORT = 443
TLS_TIMEOUT = 15  # seconds
SEMAPHORE_LIMIT = 50  # concurrent TLS scans
HTTP_TIMEOUT = 30  # seconds for HTTP requests
MAX_CT_ENTRIES = 50  # max crt.sh results per domain

# ── CCADB URLs ────────────────────────────────────────────────────────────────

CCADB_ALL_CERTS_CSV = "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv2"
CCADB_CAA_IDENTIFIERS = "https://ccadb.my.salesforce-sites.com/ccadb/AllCAAIdentifiersReport"
CCADB_MOZILLA_INCLUDED = (
    "https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReportCSVFormat"
)
