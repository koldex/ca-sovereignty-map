"""Shared pytest fixtures for cert_sovereignty tests."""

from __future__ import annotations

import pytest

from cert_sovereignty.models import (
    CertChainEntry,
    Evidence,
    Jurisdiction,
    SignalKind,
)


@pytest.fixture
def letsencrypt_leaf() -> CertChainEntry:
    """Sample Let's Encrypt leaf certificate chain entry."""
    return CertChainEntry(
        position=0,
        cert_type="leaf",
        subject_cn="example.fi",
        subject_org="",
        subject_country="",
        issuer_cn="R10",
        issuer_org="Let's Encrypt",
        issuer_country="US",
        not_before="2026-01-01T00:00:00+00:00",
        not_after="2026-04-01T00:00:00+00:00",
        serial_hex="0xdeadbeef",
        sig_algorithm="1.2.840.113549.1.1.11",
        sha256_fingerprint="AABBCC",
    )


@pytest.fixture
def isrg_intermediate() -> CertChainEntry:
    """Sample ISRG intermediate certificate."""
    return CertChainEntry(
        position=1,
        cert_type="intermediate",
        subject_cn="R10",
        subject_org="Let's Encrypt",
        subject_country="US",
        issuer_cn="ISRG Root X1",
        issuer_org="Internet Security Research Group",
        issuer_country="US",
        not_before="2024-03-13T00:00:00+00:00",
        not_after="2027-03-12T23:59:59+00:00",
        serial_hex="0x1234",
        sig_algorithm="1.2.840.113549.1.1.11",
        sha256_fingerprint="DDEEFF",
    )


@pytest.fixture
def buypass_leaf() -> CertChainEntry:
    """Sample Buypass (Norwegian) leaf certificate."""
    return CertChainEntry(
        position=0,
        cert_type="leaf",
        subject_cn="oslo.kommune.no",
        issuer_cn="Buypass Class 2 CA",
        issuer_org="Buypass",
        issuer_country="NO",
        sha256_fingerprint="112233",
    )


@pytest.fixture
def leaf_evidence() -> Evidence:
    """Sample leaf issuer evidence for Let's Encrypt."""
    return Evidence(
        kind=SignalKind.LEAF_ISSUER,
        jurisdiction=Jurisdiction.US,
        ca_name="Let's Encrypt (ISRG)",
        weight=0.35,
        detail="leaf_issuer: issuer_org=Let's Encrypt → Let's Encrypt (ISRG)",
        raw="Let's Encrypt|R10",
    )


@pytest.fixture
def caa_evidence() -> Evidence:
    """Sample CAA record evidence."""
    return Evidence(
        kind=SignalKind.CAA_RECORD,
        jurisdiction=Jurisdiction.US,
        ca_name="Let's Encrypt (ISRG)",
        weight=0.10,
        detail="CAA issue=letsencrypt.org → Let's Encrypt (ISRG)",
        raw="letsencrypt.org",
    )


@pytest.fixture
def sample_data_json() -> dict:
    """Minimal valid data.json structure for testing."""
    return {
        "generated": "2026-03-24T04:00:00Z",
        "commit": "abc1234",
        "total": 2,
        "counts": {
            "us-controlled": 1,
            "eu-controlled": 0,
            "nordic": 1,
            "allied": 0,
            "unknown": 0,
        },
        "municipalities": {
            "FI-049": {
                "id": "FI-049",
                "name": "Espoo",
                "country": "FI",
                "domain": "espoo.fi",
                "primary_ca": "Let's Encrypt (ISRG)",
                "jurisdiction": "us",
                "risk_level": "high",
                "category": "us-controlled",
                "classification_confidence": 95.0,
            },
            "NO-0301": {
                "id": "NO-0301",
                "name": "Oslo",
                "country": "NO",
                "domain": "oslo.kommune.no",
                "primary_ca": "Buypass",
                "jurisdiction": "nordic",
                "risk_level": "minimal",
                "category": "nordic",
                "classification_confidence": 85.0,
            },
        },
    }
