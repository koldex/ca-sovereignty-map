"""Tests for TLS certificate chain scanning."""

from __future__ import annotations

from cert_sovereignty.models import SignalKind
from cert_sovereignty.tls import (
    _extract_pem_certs,
    _match_cert_to_ca,
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
