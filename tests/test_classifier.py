"""Tests for CA classification logic."""

from __future__ import annotations

import pytest

from cert_sovereignty.classifier import _aggregate, _rule_confidence, classify
from cert_sovereignty.models import Evidence, Jurisdiction, RiskLevel, SignalKind


def make_evidence(kind: SignalKind, ca_name: str, weight: float) -> Evidence:
    return Evidence(
        kind=kind,
        jurisdiction=Jurisdiction.US,
        ca_name=ca_name,
        weight=weight,
        detail=f"test evidence for {ca_name}",
        raw="",
    )


def test_aggregate_single_ca() -> None:
    ev = [make_evidence(SignalKind.LEAF_ISSUER, "Let's Encrypt (ISRG)", 0.35)]
    winner, score, winner_ev = _aggregate(ev)
    assert winner == "Let's Encrypt (ISRG)"
    assert abs(score - 0.35) < 0.001
    assert len(winner_ev) == 1


def test_aggregate_multiple_signals_same_ca() -> None:
    ev = [
        make_evidence(SignalKind.LEAF_ISSUER, "DigiCert", 0.35),
        make_evidence(SignalKind.CAA_RECORD, "DigiCert", 0.10),
        make_evidence(SignalKind.INTERMEDIATE_ISSUER, "DigiCert", 0.25),
    ]
    winner, score, _ = _aggregate(ev)
    assert winner == "DigiCert"
    assert abs(score - 0.70) < 0.001


def test_aggregate_competing_cas() -> None:
    ev = [
        make_evidence(SignalKind.LEAF_ISSUER, "Let's Encrypt (ISRG)", 0.35),
        make_evidence(SignalKind.CAA_RECORD, "DigiCert", 0.10),
    ]
    winner, _, _ = _aggregate(ev)
    assert winner == "Let's Encrypt (ISRG)"


def test_aggregate_empty() -> None:
    winner, score, ev = _aggregate([])
    assert winner == "Unknown"
    assert score == 0.0
    assert ev == []


def test_rule_confidence_leaf_inter_root() -> None:
    ev = [
        make_evidence(SignalKind.LEAF_ISSUER, "X", 0.35),
        make_evidence(SignalKind.INTERMEDIATE_ISSUER, "X", 0.25),
        make_evidence(SignalKind.ROOT_CA, "X", 0.15),
    ]
    assert _rule_confidence(ev) == 0.95


def test_rule_confidence_leaf_only() -> None:
    ev = [make_evidence(SignalKind.LEAF_ISSUER, "X", 0.35)]
    assert _rule_confidence(ev) == 0.75


def test_rule_confidence_empty() -> None:
    assert _rule_confidence([]) == 0.30


def test_classify_letsencrypt() -> None:
    tls_ev = [
        make_evidence(SignalKind.LEAF_ISSUER, "Let's Encrypt (ISRG)", 0.35),
        make_evidence(SignalKind.INTERMEDIATE_ISSUER, "Let's Encrypt (ISRG)", 0.25),
    ]
    result = classify(
        domain="example.fi",
        tls_evidence=tls_ev,
        caa_evidence=[],
        ct_evidence=[],
        chain=[],
        caa_records=[],
        ct_issuers=[],
    )
    assert result.primary_ca == "Let's Encrypt (ISRG)"
    assert result.jurisdiction == Jurisdiction.US
    assert result.confidence == 0.90
    assert result.risk_level == RiskLevel.HIGH


def test_classify_buypass_nordic() -> None:
    tls_ev = [
        make_evidence(SignalKind.LEAF_ISSUER, "Buypass", 0.35),
    ]
    # Override jurisdiction for test
    from cert_sovereignty.models import Jurisdiction as J

    tls_ev_nordic = [
        Evidence(
            kind=SignalKind.LEAF_ISSUER,
            jurisdiction=J.NORDIC,
            ca_name="Buypass",
            weight=0.35,
            detail="test",
            raw="",
        )
    ]

    result = classify(
        domain="oslo.kommune.no",
        tls_evidence=tls_ev_nordic,
        caa_evidence=[],
        ct_evidence=[],
        chain=[],
        caa_records=[],
        ct_issuers=[],
    )
    assert result.primary_ca == "Buypass"
    assert result.jurisdiction == Jurisdiction.NORDIC
    assert result.risk_level == RiskLevel.MINIMAL


def test_classify_with_error() -> None:
    result = classify(
        domain="broken.fi",
        tls_evidence=[],
        caa_evidence=[],
        ct_evidence=[],
        chain=[],
        caa_records=[],
        ct_issuers=[],
        error="Connection timeout",
    )
    assert result.primary_ca == "Unknown"
    assert result.error == "Connection timeout"
    assert result.confidence == 0.0
