"""CA fingerprint signatures — analogous to mxmap's ProviderSignature.

Each CASignature defines pattern-matching rules for identifying a CA
from certificate fields (issuer CN/O, OCSP URLs, CAA values).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from .models import Jurisdiction, RiskLevel


class CASignature(BaseModel):
    """Certificate authority fingerprint.

    Cf. mxmap ProviderSignature:
    - mx_patterns → issuer_patterns
    - asns → ocsp_domains, crl_domains
    """

    model_config = ConfigDict(frozen=True)

    name: str  # Display name
    jurisdiction: Jurisdiction
    risk_level: RiskLevel
    hq_country: str  # HQ country (ISO 3166-1 alpha-2)
    parent_company: str = ""
    cloud_act_subject: bool = False
    # Pattern matching (case-insensitive substring, like mxmap)
    issuer_org_patterns: tuple[str, ...] = ()  # Issuer O= field
    issuer_cn_patterns: tuple[str, ...] = ()  # Issuer CN= field
    root_cn_patterns: tuple[str, ...] = ()  # Root CA CN= field
    ocsp_url_patterns: tuple[str, ...] = ()  # OCSP responder URL
    crl_url_patterns: tuple[str, ...] = ()  # CRL distribution URL
    caa_values: tuple[str, ...] = ()  # DNS CAA tag values
    notes: str = ""


def match_patterns(value: str, patterns: tuple[str, ...] | list[str]) -> bool:
    """Case-insensitive match of value against any pattern.

    Short patterns (≤4 chars, e.g. Let's Encrypt intermediates 'R3', 'R4',
    'E1') require an exact match to prevent false positives such as 'R4'
    matching as a substring of 'Sectigo Public Server Authentication Root R46'.
    Longer patterns use substring matching as before (cf. mxmap).
    """
    if not value or not patterns:
        return False
    lower = value.lower()
    for p in patterns:
        p_lower = p.lower()
        if len(p_lower) <= 4:
            # Short code: must match the entire value exactly
            if lower == p_lower:
                return True
        else:
            if p_lower in lower:
                return True
    return False


# ── CA Signature Database ─────────────────────────────────────────────────────

SIGNATURES: list[CASignature] = [
    # ─── US-BASED (CLOUD Act subject) ─────────────────────────────────────────
    CASignature(
        name="Let's Encrypt (ISRG)",
        jurisdiction=Jurisdiction.US,
        risk_level=RiskLevel.HIGH,
        hq_country="US",
        parent_company="Internet Security Research Group",
        cloud_act_subject=True,
        issuer_org_patterns=("Let's Encrypt",),
        issuer_cn_patterns=("R3", "R4", "R10", "R11", "E1", "E2", "E5", "E6"),
        root_cn_patterns=("ISRG Root X1", "ISRG Root X2"),
        ocsp_url_patterns=(
            "ocsp.int-x3.letsencrypt.org",
            "r3.o.lencr.org",
            "r10.o.lencr.org",
            "r11.o.lencr.org",
            "e5.o.lencr.org",
        ),
        caa_values=("letsencrypt.org",),
        notes="Nonprofit but US jurisdiction. Largest free certificate issuer.",
    ),
    CASignature(
        name="DigiCert",
        jurisdiction=Jurisdiction.US,
        risk_level=RiskLevel.CRITICAL,
        hq_country="US",
        parent_company="DigiCert Inc. (Thoma Bravo PE)",
        cloud_act_subject=True,
        issuer_org_patterns=("DigiCert",),
        issuer_cn_patterns=(
            "DigiCert Global Root",
            "DigiCert TLS",
            "GeoTrust",
            "Thawte",
            "RapidSSL",
            "DigiCert SHA2",
            "DigiCert Assured",
        ),
        root_cn_patterns=(
            "DigiCert Global Root G2",
            "DigiCert Global Root CA",
            "DigiCert High Assurance",
        ),
        ocsp_url_patterns=("ocsp.digicert.com",),
        crl_url_patterns=("crl3.digicert.com", "crl4.digicert.com"),
        caa_values=("digicert.com",),
    ),
    CASignature(
        name="Sectigo (Comodo)",
        jurisdiction=Jurisdiction.US,
        risk_level=RiskLevel.CRITICAL,
        hq_country="US",
        parent_company="Sectigo Limited",
        cloud_act_subject=True,
        issuer_org_patterns=("Sectigo", "COMODO", "USERTrust"),
        issuer_cn_patterns=(
            "Sectigo RSA",
            "USERTrust RSA",
            "COMODO RSA",
            "AAA Certificate Services",
        ),
        ocsp_url_patterns=(
            "ocsp.sectigo.com",
            "ocsp.comodoca.com",
            "ocsp.usertrust.com",
        ),
        caa_values=("sectigo.com", "comodoca.com"),
    ),
    CASignature(
        name="Amazon Trust Services",
        jurisdiction=Jurisdiction.US,
        risk_level=RiskLevel.CRITICAL,
        hq_country="US",
        parent_company="Amazon.com Inc.",
        cloud_act_subject=True,
        issuer_org_patterns=("Amazon",),
        issuer_cn_patterns=("Amazon Root CA", "Amazon RSA", "Amazon ECDSA"),
        ocsp_url_patterns=("ocsp.rootca1.amazontrust.com",),
        caa_values=("amazon.com", "amazontrust.com"),
    ),
    CASignature(
        name="Google Trust Services",
        jurisdiction=Jurisdiction.US,
        risk_level=RiskLevel.CRITICAL,
        hq_country="US",
        parent_company="Alphabet Inc.",
        cloud_act_subject=True,
        issuer_org_patterns=("Google Trust Services",),
        issuer_cn_patterns=(
            "GTS Root R1",
            "GTS Root R2",
            "GTS Root R3",
            "GTS Root R4",
            "GTS CA 1P5",
            "WR2",
        ),
        ocsp_url_patterns=("ocsp.pki.goog",),
        caa_values=("pki.goog",),
    ),
    CASignature(
        name="GoDaddy / Starfield",
        jurisdiction=Jurisdiction.US,
        risk_level=RiskLevel.CRITICAL,
        hq_country="US",
        parent_company="GoDaddy Inc.",
        cloud_act_subject=True,
        issuer_org_patterns=("GoDaddy", "Starfield"),
        issuer_cn_patterns=(
            "Go Daddy Root",
            "Starfield Root",
            "Go Daddy Secure",
            "Starfield Secure",
        ),
        caa_values=("godaddy.com", "starfieldtech.com"),
    ),
    CASignature(
        name="Cloudflare",
        jurisdiction=Jurisdiction.US,
        risk_level=RiskLevel.CRITICAL,
        hq_country="US",
        parent_company="Cloudflare Inc.",
        cloud_act_subject=True,
        issuer_org_patterns=("Cloudflare",),
        issuer_cn_patterns=("Cloudflare Inc ECC CA",),
        notes="Often uses DigiCert or Google TS as intermediate issuer.",
    ),
    CASignature(
        name="Entrust",
        jurisdiction=Jurisdiction.US,
        risk_level=RiskLevel.CRITICAL,
        hq_country="US",
        parent_company="Entrust Corporation",
        cloud_act_subject=True,
        issuer_org_patterns=("Entrust",),
        issuer_cn_patterns=(
            "Entrust Root",
            "Entrust Certification",
            # Entrust OV TLS and DV TLS issuing CAs (Rovaniemi uses this)
            "Entrust OV TLS",
            "Entrust DV TLS",
        ),
        caa_values=("entrust.net",),
        notes="Chrome/Firefox restricted trust from 2024 onwards.",
    ),
    CASignature(
        name="SSL.com",
        jurisdiction=Jurisdiction.US,
        risk_level=RiskLevel.CRITICAL,
        hq_country="US",
        parent_company="SSL Corp",
        cloud_act_subject=True,
        issuer_org_patterns=("SSL.com", "SSL Corp"),
        caa_values=("ssl.com",),
    ),
    CASignature(
        name="ZeroSSL (apilayer/Idera)",
        jurisdiction=Jurisdiction.US,
        risk_level=RiskLevel.CRITICAL,
        hq_country="US",
        parent_company="apilayer GmbH (Idera Inc.)",
        cloud_act_subject=True,
        issuer_org_patterns=("ZeroSSL",),
        issuer_cn_patterns=("ZeroSSL RSA", "ZeroSSL ECC"),
        caa_values=("sectigo.com",),
        notes="Austrian company (apilayer) but US owner (Idera). Uses Sectigo root.",
    ),
    CASignature(
        name="Microsoft",
        jurisdiction=Jurisdiction.US,
        risk_level=RiskLevel.CRITICAL,
        hq_country="US",
        parent_company="Microsoft Corporation",
        cloud_act_subject=True,
        issuer_org_patterns=("Microsoft",),
        issuer_cn_patterns=("Microsoft RSA TLS", "Microsoft Azure TLS"),
        notes="Used for Azure-hosted services.",
    ),
    # ─── EU-BASED ─────────────────────────────────────────────────────────────
    CASignature(
        name="GlobalSign",
        jurisdiction=Jurisdiction.EU,
        risk_level=RiskLevel.LOW,
        hq_country="BE",
        parent_company="GMO Internet Group (JP)",
        cloud_act_subject=False,
        issuer_org_patterns=("GlobalSign",),
        issuer_cn_patterns=(
            "GlobalSign Root CA",
            "GlobalSign GCC",
            "GlobalSign Atlas",
            "GlobalSign Root R46",
        ),
        ocsp_url_patterns=("ocsp.globalsign.com",),
        caa_values=("globalsign.com",),
        notes="HQ Belgium, owner Japanese GMO Group.",
    ),
    CASignature(
        name="HARICA",
        jurisdiction=Jurisdiction.EU,
        risk_level=RiskLevel.LOW,
        hq_country="GR",
        parent_company="Hellenic Academic and Research Institutions CA",
        cloud_act_subject=False,
        issuer_org_patterns=("HARICA",),
        issuer_cn_patterns=(
            "HARICA TLS RSA Root",
            "HARICA TLS ECC Root",
            # GÉANT TLS issuing CAs chain up to HARICA as the root CA.
            # 'GEANT TLS RSA 1', 'GEANT TLS ECC 1', etc.
            "GEANT TLS",
        ),
        caa_values=("harica.gr",),
    ),
    CASignature(
        name="Certum (Asseco)",
        jurisdiction=Jurisdiction.EU,
        risk_level=RiskLevel.LOW,
        hq_country="PL",
        parent_company="Asseco Data Systems",
        cloud_act_subject=False,
        issuer_org_patterns=("Certum", "Unizeto"),
        issuer_cn_patterns=("Certum Trusted Network", "Certum EC-384"),
        caa_values=("certum.pl",),
    ),
    CASignature(
        name="D-TRUST (Bundesdruckerei)",
        jurisdiction=Jurisdiction.EU,
        risk_level=RiskLevel.LOW,
        hq_country="DE",
        parent_company="Bundesdruckerei GmbH",
        cloud_act_subject=False,
        issuer_org_patterns=("D-Trust", "Bundesdruckerei"),
        issuer_cn_patterns=("D-TRUST Root",),
        notes="German federal printing company — strong EU sovereignty.",
    ),
    CASignature(
        name="SwissSign",
        jurisdiction=Jurisdiction.ALLIED,
        risk_level=RiskLevel.MEDIUM,
        hq_country="CH",
        parent_company="SwissSign Group AG (Swiss Post)",
        cloud_act_subject=False,
        issuer_org_patterns=("SwissSign",),
        issuer_cn_patterns=("SwissSign Silver", "SwissSign Gold"),
        caa_values=("swisssign.com",),
        notes="Swiss Post subsidiary — Swiss jurisdiction.",
    ),
    # ─── NORDIC ───────────────────────────────────────────────────────────────
    CASignature(
        name="Buypass",
        jurisdiction=Jurisdiction.NORDIC,
        risk_level=RiskLevel.MINIMAL,
        hq_country="NO",
        parent_company="Buypass AS",
        cloud_act_subject=False,
        issuer_org_patterns=("Buypass",),
        issuer_cn_patterns=("Buypass Class 2", "Buypass Class 3"),
        caa_values=("buypass.com",),
        notes="Norwegian CA. Also offers free ACME certificates.",
    ),
    CASignature(
        name="Telia (TSSL)",
        jurisdiction=Jurisdiction.NORDIC,
        risk_level=RiskLevel.MINIMAL,
        hq_country="SE",
        parent_company="Telia Company AB",
        cloud_act_subject=False,
        issuer_org_patterns=("Telia",),
        issuer_cn_patterns=("Telia Root",),
        notes="Swedish telecom — Nordic jurisdiction.",
    ),
]


# ── Nordic ISP/hosting ASNs ───────────────────────────────────────────────────
# Cf. mxmap SWISS_ISP_ASNS

NORDIC_ISP_ASNS: dict[int, str] = {
    # Finland
    1759: "Telia Finland",
    6667: "Elisa Oyj",
    16086: "DNA Oyj",
    20569: "CSC - IT Center for Science",
    # Sweden
    2831: "Telia Sverige",
    3301: "Telia Company",
    8473: "Bahnhof",
    12552: "IP-Only",
    29518: "Bredband2",
    # Norway
    2116: "Telenor Norge",
    12929: "Altibox / Lyse",
    # Denmark
    3292: "TDC / Nuuday",
    15516: "Stofa / Norlys",
}
