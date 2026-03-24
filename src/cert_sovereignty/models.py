"""Pydantic models for the cert sovereignty classifier.

Follows mxmap's model pattern: Evidence → ClassificationResult.
"""

from __future__ import annotations

import enum

from pydantic import BaseModel, ConfigDict, Field


class Jurisdiction(str, enum.Enum):
    """CA's legal jurisdiction — determines kill-switch risk."""

    US = "us"  # US CLOUD Act subject
    EU = "eu"  # EU/EEA (not Nordic)
    NORDIC = "nordic"  # FI/SE/NO/DK/IS
    ALLIED = "allied"  # Allied non-EU (JP, CH, UK, CA)
    OTHER = "other"  # Unknown / other


class RiskLevel(str, enum.Enum):
    """Kill-switch risk level."""

    CRITICAL = "critical"  # US-controlled, direct revocation risk
    HIGH = "high"  # US-controlled but nonprofit/limited
    MEDIUM = "medium"  # Allied or multinational
    LOW = "low"  # EU-controlled
    MINIMAL = "minimal"  # Nordic / national


class SignalKind(str, enum.Enum):
    """Certificate signal type (cf. mxmap: MX, SPF, DKIM...)."""

    LEAF_ISSUER = "leaf_issuer"
    INTERMEDIATE_ISSUER = "intermediate_issuer"
    ROOT_CA = "root_ca"
    CAA_RECORD = "caa_record"
    CT_LOG = "ct_log"
    OCSP_ENDPOINT = "ocsp_endpoint"
    CRL_ENDPOINT = "crl_endpoint"


class Evidence(BaseModel):
    """Single piece of evidence for CA identification.

    Directly mirrors mxmap's Evidence model:
    kind + provider → weight + detail + raw
    """

    model_config = ConfigDict(frozen=True)

    kind: SignalKind
    jurisdiction: Jurisdiction
    ca_name: str
    weight: float = Field(ge=0.0, le=1.0)
    detail: str
    raw: str = ""


class CertChainEntry(BaseModel):
    """A single certificate in a chain."""

    model_config = ConfigDict(frozen=True)

    position: int  # 0=leaf, 1=intermediate, 2+=root
    cert_type: str  # "leaf", "intermediate", "root"
    subject_cn: str = ""
    subject_org: str = ""
    subject_country: str = ""
    issuer_cn: str = ""
    issuer_org: str = ""
    issuer_country: str = ""
    not_before: str = ""
    not_after: str = ""
    serial_hex: str = ""
    sig_algorithm: str = ""
    sha256_fingerprint: str = ""
    # CCADB enrichment fields
    ccadb_match: bool = False
    ca_owner: str = ""
    ca_country: str = ""
    tls_capable: bool | None = None
    revocation_status: str = ""


class ClassificationResult(BaseModel):
    """CA classification result for one domain.

    Cf. mxmap: ClassificationResult(provider, confidence, evidence, gateway, mx_hosts, spf_raw)
    """

    model_config = ConfigDict(frozen=True)

    domain: str
    primary_ca: str
    ca_owner: str = ""
    ca_country: str = ""
    jurisdiction: Jurisdiction
    risk_level: RiskLevel
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[Evidence] = []
    cert_chain: list[CertChainEntry] = []
    caa_records: list[str] = []
    ct_issuers: list[str] = []
    tls_version: str = ""
    verification: str = ""
    error: str | None = None
    scan_timestamp: str = ""


class MunicipalityRecord(BaseModel):
    """Full municipality data record for data.json."""

    id: str  # e.g. "FI-049"
    name: str
    name_sv: str = ""
    name_local: str = ""
    country: str  # ISO 3166-1 alpha-2
    region: str = ""
    domain: str = ""
    population: int | None = None
    classification: ClassificationResult | None = None
    override_reason: str = ""
