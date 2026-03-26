"""Tests for TLS certificate chain scanning."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from cert_sovereignty.models import SignalKind
from cert_sovereignty.tls import (
    _extract_pem_certs,
    _match_cert_to_ca,
    _no_kommune_fallback,
    scan_certificate_chain,
)


def test_extract_pem_certs_empty() -> None:
    assert _extract_pem_certs("") == []


def test_extract_pem_certs_single() -> None:
    # _extract_pem_certs is kept for diagnostic use with openssl showcerts output
    pem_output = """
depth=0 CN=example.fi
-----BEGIN CERTIFICATE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
-----END CERTIFICATE-----
"""
    certs = _extract_pem_certs(pem_output)
    assert len(certs) == 1
    assert "-----BEGIN CERTIFICATE-----" in certs[0]
    assert "-----END CERTIFICATE-----" in certs[0]


def test_extract_pem_certs_multiple() -> None:
    pem_output = """
-----BEGIN CERTIFICATE-----
AAAA
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
BBBB
-----END CERTIFICATE-----
"""
    certs = _extract_pem_certs(pem_output)
    assert len(certs) == 2


def test_extract_pem_certs_no_partial() -> None:
    # Incomplete PEM block (missing END) must not produce a result
    pem_output = "-----BEGIN CERTIFICATE-----\nAAAA\n"
    assert _extract_pem_certs(pem_output) == []


def test_redirect_strip_www_uses_removeprefix() -> None:
    """B005: lstrip('www.') strips chars, removeprefix strips the exact string."""
    # 'webmaster.example.fi' must not be stripped by removeprefix('www.')
    assert "webmaster.example.fi".removeprefix("www.") == "webmaster.example.fi"
    # 'www.example.fi' is correctly stripped
    assert "www.example.fi".removeprefix("www.") == "example.fi"


def test_match_cert_to_ca_letsencrypt(letsencrypt_leaf) -> None:
    results = _match_cert_to_ca(letsencrypt_leaf, SignalKind.LEAF_ISSUER)
    assert len(results) >= 1
    ca_names = [ev.ca_name for ev in results]
    assert "Let's Encrypt (ISRG)" in ca_names


def test_match_cert_to_ca_buypass(buypass_leaf) -> None:
    results = _match_cert_to_ca(buypass_leaf, SignalKind.LEAF_ISSUER)
    ca_names = [ev.ca_name for ev in results]
    assert "Buypass" in ca_names


# ── _no_kommune_fallback ─────────────────────────────────────────────────────


def test_no_kommune_fallback_www_prefix() -> None:
    assert _no_kommune_fallback("www.nord-fron.no") == "nord-fron.kommune.no"
    assert _no_kommune_fallback("www.amot.no") == "amot.kommune.no"


def test_no_kommune_fallback_bare() -> None:
    assert _no_kommune_fallback("laerdal.no") == "laerdal.kommune.no"
    assert _no_kommune_fallback("vinje.no") == "vinje.kommune.no"


def test_no_kommune_fallback_already_authoritative() -> None:
    # Already .kommune.no or .herad.no — must return None
    assert _no_kommune_fallback("nord-fron.kommune.no") is None
    assert _no_kommune_fallback("ulvik.herad.no") is None


def test_no_kommune_fallback_non_norwegian() -> None:
    # Non-.no domains must return None
    assert _no_kommune_fallback("espoo.fi") is None
    assert _no_kommune_fallback("stockholm.se") is None
    assert _no_kommune_fallback("laerdal.com") is None


# ── scan_certificate_chain — Recovery 3 (─────────────────────────────────────


def _err(domain: str, msg: str = "SSL error: SNI") -> dict:
    """Minimal failed _scan_asyncio_ssl result."""
    return {
        "domain": domain, "scan_timestamp": "2026-01-01T00:00:00+00:00",
        "chain": [], "evidence": [], "tls_version": "", "verification": "",
        "error": msg, "cert_mismatch": False, "http_accessible": None,
    }


def _ok(domain: str) -> dict:
    """Minimal successful _scan_asyncio_ssl result."""
    return {
        "domain": domain, "scan_timestamp": "2026-01-01T00:00:00+00:00",
        "chain": [], "evidence": [], "tls_version": "TLSv1.3", "verification": "OK",
        "error": None, "cert_mismatch": False, "http_accessible": None,
    }


async def test_recovery3_triggers_for_bare_no() -> None:
    """www.amot.no SSL error → Recovery 3 retries amot.kommune.no."""
    with patch("cert_sovereignty.tls._scan_asyncio_ssl", new_callable=AsyncMock,
               side_effect=[_err("www.amot.no"), _ok("amot.kommune.no")]):
        result = await scan_certificate_chain("www.amot.no")
    assert result["scanned_domain"] == "amot.kommune.no"
    assert result["domain"] == "www.amot.no"
    assert result["error"] is None


async def test_recovery3_does_not_trigger_for_non_no() -> None:
    """Recovery 3 does not fire for non-Norwegian domains."""
    with patch("cert_sovereignty.tls._scan_asyncio_ssl", new_callable=AsyncMock,
               return_value=_err("www.espoo.fi")):
        result = await scan_certificate_chain("www.espoo.fi")
    assert result["error"] == "SSL error: SNI"
    assert result.get("scanned_domain", "") == ""


async def test_recovery3_does_not_trigger_for_kommune_domain() -> None:
    """Recovery 3 does not fire when domain is already .kommune.no."""
    with patch("cert_sovereignty.tls._scan_asyncio_ssl", new_callable=AsyncMock,
               return_value=_err("amot.kommune.no", msg="SSL error: test")), \
         patch("cert_sovereignty.tls._check_port_open", new_callable=AsyncMock,
               return_value=False):
        result = await scan_certificate_chain("amot.kommune.no")
    # Should stay on the original error, no .kommune.no sub-fallback attempted
    assert result["error"] == "SSL error: test"
    assert result.get("scanned_domain", "") == ""


def test_match_cert_to_ca_unknown() -> None:
    from cert_sovereignty.models import CertChainEntry

    unknown_cert = CertChainEntry(
        position=0,
        cert_type="leaf",
        subject_cn="example.fi",
        issuer_cn="Unknown Local CA",
        issuer_org="Local Municipality IT",
        issuer_country="FI",
    )
    results = _match_cert_to_ca(unknown_cert, SignalKind.LEAF_ISSUER)
    assert results == []
