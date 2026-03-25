"""Tests for CA signature matching."""

from __future__ import annotations

from cert_sovereignty.models import Jurisdiction, RiskLevel
from cert_sovereignty.signatures import SIGNATURES, match_patterns


def test_match_patterns_basic() -> None:
    assert match_patterns("Let's Encrypt", ("Let's Encrypt",)) is True
    assert match_patterns("DigiCert TLS RSA", ("DigiCert",)) is True
    assert match_patterns("Buypass Class 2", ("COMODO",)) is False


def test_match_patterns_case_insensitive() -> None:
    assert match_patterns("let's encrypt", ("LET'S ENCRYPT",)) is True
    assert match_patterns("DIGICERT", ("digicert",)) is True


def test_match_patterns_empty() -> None:
    assert match_patterns("", ("Let's Encrypt",)) is False
    assert match_patterns("Let's Encrypt", ()) is False
    assert match_patterns("", ()) is False


def test_match_patterns_short_exact_match_only() -> None:
    """Short patterns (≤4 chars) must NOT match as substring inside longer strings."""
    # 'R4' is a Let's Encrypt intermediate CN—must NOT match inside 'Root R46' (Sectigo)
    assert match_patterns("Sectigo Public Server Authentication Root R46", ("R4",)) is False
    # But it MUST still match when the value IS exactly 'R4'
    assert match_patterns("R4", ("R4",)) is True
    # 'R10' is long enough for substring matching
    assert match_patterns("Let's Encrypt R10", ("R10",)) is False  # R10 is ≤4 chars, exact only
    assert match_patterns("R10", ("R10",)) is True
    # Longer pattern still uses substring
    assert match_patterns("HARICA TLS RSA Root CA 2021", ("HARICA TLS",)) is True


def test_signatures_not_empty() -> None:
    assert len(SIGNATURES) > 5


def test_letsencrypt_signature() -> None:
    sig = next(s for s in SIGNATURES if "Let's Encrypt" in s.name)
    assert sig.jurisdiction == Jurisdiction.US
    assert sig.risk_level == RiskLevel.HIGH
    assert sig.cloud_act_subject is True
    assert sig.hq_country == "US"
    assert "letsencrypt.org" in sig.caa_values


def test_buypass_signature() -> None:
    sig = next(s for s in SIGNATURES if "Buypass" in s.name)
    assert sig.jurisdiction == Jurisdiction.NORDIC
    assert sig.risk_level == RiskLevel.MINIMAL
    assert sig.hq_country == "NO"
    assert sig.cloud_act_subject is False


def test_all_signatures_have_required_fields() -> None:
    for sig in SIGNATURES:
        assert sig.name
        assert sig.hq_country
        assert isinstance(sig.jurisdiction, Jurisdiction)
        assert isinstance(sig.risk_level, RiskLevel)


def test_no_duplicate_signature_names() -> None:
    names = [sig.name for sig in SIGNATURES]
    assert len(names) == len(set(names)), "Duplicate CA signature names found"
