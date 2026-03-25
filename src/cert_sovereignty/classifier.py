"""Classify domains by aggregating TLS/DNS evidence into CA + jurisdiction + confidence.

Algorithm (adapted from mxmap's classifier):
1. Collect evidence from TLS scan (leaf, intermediate, root) + DNS probes (CAA, CT)
2. Winner: CA with highest weighted evidence sum
3. Confidence: rule-based scoring matching evidence combination
4. Jurisdiction: determined by winning CA's CASignature
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from .models import (
    ClassificationResult,
    Evidence,
    Jurisdiction,
    RiskLevel,
    SignalKind,
)
from .signatures import SIGNATURES, CASignature

_S = SignalKind


@dataclass(frozen=True)
class _Rule:
    name: str
    signal_types: frozenset[SignalKind]
    confidence: float


# Confidence rules (cf. mxmap's _PROVIDER_RULES)
_CA_RULES: tuple[_Rule, ...] = (
    # 3+ signals → high confidence
    _Rule("leaf_inter_root", frozenset({_S.LEAF_ISSUER, _S.INTERMEDIATE_ISSUER, _S.ROOT_CA}), 0.95),
    _Rule(
        "leaf_inter_caa", frozenset({_S.LEAF_ISSUER, _S.INTERMEDIATE_ISSUER, _S.CAA_RECORD}), 0.95
    ),
    _Rule("leaf_caa_ct", frozenset({_S.LEAF_ISSUER, _S.CAA_RECORD, _S.CT_LOG}), 0.90),
    # 2 signals → medium-high
    _Rule("leaf_inter", frozenset({_S.LEAF_ISSUER, _S.INTERMEDIATE_ISSUER}), 0.90),
    _Rule("leaf_caa", frozenset({_S.LEAF_ISSUER, _S.CAA_RECORD}), 0.85),
    _Rule("leaf_ct", frozenset({_S.LEAF_ISSUER, _S.CT_LOG}), 0.80),
    # 2 signals without leaf — e.g. academic chains where the leaf issuing CA
    # is not yet in our DB but both intermediate and root are (Oulu/HARICA/GÉANT)
    _Rule("inter_root", frozenset({_S.INTERMEDIATE_ISSUER, _S.ROOT_CA}), 0.85),
    _Rule("inter_caa", frozenset({_S.INTERMEDIATE_ISSUER, _S.CAA_RECORD}), 0.80),
    # 1 signal
    _Rule("leaf_only", frozenset({_S.LEAF_ISSUER}), 0.75),
    _Rule("inter_only", frozenset({_S.INTERMEDIATE_ISSUER}), 0.65),
    _Rule("caa_only", frozenset({_S.CAA_RECORD}), 0.50),
    _Rule("root_only", frozenset({_S.ROOT_CA}), 0.50),
    _Rule("fallback", frozenset(), 0.30),
)

# Map jurisdiction → risk level (minimum risk per jurisdiction)
_JURISDICTION_RISK: dict[Jurisdiction, RiskLevel] = {
    Jurisdiction.US: RiskLevel.HIGH,
    Jurisdiction.EU: RiskLevel.LOW,
    Jurisdiction.NORDIC: RiskLevel.MINIMAL,
    Jurisdiction.ALLIED: RiskLevel.MEDIUM,
    Jurisdiction.OTHER: RiskLevel.MEDIUM,
}

_UNKNOWN_RESULT_TEMPLATE = {
    "primary_ca": "Unknown",
    "ca_owner": "",
    "ca_country": "",
    "jurisdiction": Jurisdiction.OTHER,
    "risk_level": RiskLevel.MEDIUM,
    "confidence": 0.0,
}


def _find_signature(ca_name: str) -> CASignature | None:
    """Find CASignature by name."""
    for sig in SIGNATURES:
        if sig.name == ca_name:
            return sig
    return None


def _aggregate(evidence: list[Evidence]) -> tuple[str, float, list[Evidence]]:
    """Aggregate evidence to determine winning CA.

    Returns (winner_ca_name, weighted_score, winner_evidence).
    Directly mirrors mxmap's _aggregate() logic.
    """
    if not evidence:
        return "Unknown", 0.0, []

    # Sum weights per CA name
    scores: dict[str, float] = defaultdict(float)
    ca_evidence: dict[str, list[Evidence]] = defaultdict(list)

    for ev in evidence:
        scores[ev.ca_name] += ev.weight
        ca_evidence[ev.ca_name].append(ev)

    winner = max(scores, key=lambda k: scores[k])
    return winner, scores[winner], ca_evidence[winner]


def _rule_confidence(evidence: list[Evidence]) -> float:
    """Determine confidence score from evidence signal combination.

    Directly mirrors mxmap's _rule_confidence() logic.
    """
    signal_types = frozenset(ev.kind for ev in evidence)

    for rule in _CA_RULES:
        if rule.signal_types.issubset(signal_types):
            return rule.confidence

    return 0.30


def classify(
    domain: str,
    tls_evidence: list[Evidence],
    caa_evidence: list[Evidence],
    ct_evidence: list[Evidence],
    chain: list,
    caa_records: list[str],
    ct_issuers: list[str],
    tls_version: str = "",
    verification: str = "",
    error: str | None = None,
    cert_mismatch: bool = False,
    http_accessible: bool | None = None,
    scanned_domain: str = "",
) -> ClassificationResult:
    """Classify a domain's CA sovereignty from all collected evidence.

    Aggregates all signal types and applies confidence scoring rules.
    """
    all_evidence = tls_evidence + caa_evidence + ct_evidence

    if not all_evidence and error:
        return ClassificationResult(
            domain=domain,
            primary_ca="Unknown",
            jurisdiction=Jurisdiction.OTHER,
            risk_level=RiskLevel.MEDIUM,
            confidence=0.0,
            error=error,
        )

    winner_ca, score, winner_evidence = _aggregate(all_evidence)
    confidence = _rule_confidence(winner_evidence)

    sig = _find_signature(winner_ca)
    if sig:
        jurisdiction = sig.jurisdiction
        risk_level = sig.risk_level
        ca_owner = sig.parent_company
        ca_country = sig.hq_country
    else:
        jurisdiction = Jurisdiction.OTHER
        risk_level = RiskLevel.MEDIUM
        ca_owner = ""
        ca_country = ""

    return ClassificationResult(
        domain=domain,
        primary_ca=winner_ca,
        ca_owner=ca_owner,
        ca_country=ca_country,
        jurisdiction=jurisdiction,
        risk_level=risk_level,
        confidence=confidence,
        evidence=all_evidence,
        cert_chain=chain,
        caa_records=caa_records,
        ct_issuers=ct_issuers,
        tls_version=tls_version,
        verification=verification,
        error=error,
        cert_mismatch=cert_mismatch,
        http_accessible=http_accessible,
        scanned_domain=scanned_domain,
    )
