"""Tests for TLS certificate chain scanning."""

from __future__ import annotations

import pytest

from cert_sovereignty.models import SignalKind
from cert_sovereignty.tls import (
    _extract_pem_certs,
    _match_cert_to_ca,
    _parse_brief_output,
)


def test_extract_pem_certs_empty() -> None:
    assert _extract_pem_certs("") == []


def test_extract_pem_certs_single() -> None:
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


def test_parse_brief_output_ok() -> None:
    output = """
CONNECTION ESTABLISHED
Protocol version: TLSv1.3
Ciphersuite: TLS_AES_256_GCM_SHA384
Peer certificate: CN=example.fi
Verification: OK
"""
    info = _parse_brief_output(output)
    assert info["verification_status"] == "OK"
    assert info["tls_version"] == "TLSv1.3"
    assert info["ciphersuite"] == "TLS_AES_256_GCM_SHA384"


def test_parse_brief_output_fail() -> None:
    output = "Verification: FAILED\n"
    info = _parse_brief_output(output)
    assert info["verification_status"] == "FAILED"


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
