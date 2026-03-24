"""TLS certificate chain scanner.

Primary mechanism: OpenSSL subprocess (reliable, available in all CI/CD).
Fallback: Python ssl module (Python 3.13+ for full chain via get_verified_chain).

Scanning strategy — three levels:
  1. openssl s_client -connect domain:443 -issuer -dates  (quick info, ~1s)
  2. openssl s_client -connect domain:443 -showcerts      (full chain, ~3s)
  3. openssl s_client -connect domain:443 -brief          (validation, ~2s)

Signal weights (cf. mxmap's WEIGHTS dict):
  LEAF_ISSUER: 0.35 — strongest signal
  INTERMEDIATE_ISSUER: 0.25
  ROOT_CA: 0.15
  CAA_RECORD: 0.10
  CT_LOG: 0.08
  OCSP_ENDPOINT: 0.04
  CRL_ENDPOINT: 0.03
"""

from __future__ import annotations

import asyncio
import ssl
import subprocess
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from loguru import logger

from .models import CertChainEntry, Evidence, SignalKind
from .signatures import SIGNATURES, match_patterns

WEIGHTS: dict[SignalKind, float] = {
    SignalKind.LEAF_ISSUER: 0.35,
    SignalKind.INTERMEDIATE_ISSUER: 0.25,
    SignalKind.ROOT_CA: 0.15,
    SignalKind.CAA_RECORD: 0.10,
    SignalKind.CT_LOG: 0.08,
    SignalKind.OCSP_ENDPOINT: 0.04,
    SignalKind.CRL_ENDPOINT: 0.03,
}


# ── OpenSSL subprocess scanner ────────────────────────────────────────────────


async def scan_certificate_chain(
    domain: str,
    port: int = 443,
    timeout: int = 15,
) -> dict:
    """Scan TLS cert chain for domain. Returns a raw dict with chain + evidence."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _scan_openssl_sync, domain, port, timeout)


def _scan_openssl_sync(domain: str, port: int, timeout: int) -> dict:
    """Synchronous OpenSSL-based TLS scan — called from executor."""
    result: dict = {
        "domain": domain,
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "chain": [],
        "evidence": [],
        "tls_version": "",
        "verification": "",
        "error": None,
    }

    try:
        # Level 2: Full chain via -showcerts
        proc_chain = subprocess.run(
            [
                "bash",
                "-c",
                f"echo | openssl s_client -connect {domain}:{port} -showcerts 2>/dev/null",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if proc_chain.returncode == 0 and proc_chain.stdout:
            pem_certs = _extract_pem_certs(proc_chain.stdout)

            for i, pem in enumerate(pem_certs):
                try:
                    cert = x509.load_pem_x509_certificate(pem.encode(), default_backend())
                    is_self_signed = cert.subject == cert.issuer
                    cert_type = (
                        "leaf"
                        if i == 0
                        else ("root" if is_self_signed else "intermediate")
                    )

                    entry = _parse_x509_cert(cert, i, cert_type)
                    result["chain"].append(entry)

                    kind = (
                        SignalKind.LEAF_ISSUER
                        if i == 0
                        else (
                            SignalKind.ROOT_CA if cert_type == "root" else SignalKind.INTERMEDIATE_ISSUER
                        )
                    )
                    result["evidence"].extend(_match_cert_to_ca(entry, kind))
                except Exception as e:
                    logger.debug("Failed to parse cert {} for {}: {}", i, domain, e)

        # Level 3: Validation via -brief
        proc_brief = subprocess.run(
            [
                "bash",
                "-c",
                f"echo | openssl s_client -connect {domain}:{port} -brief 2>&1",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if proc_brief.returncode == 0:
            brief_info = _parse_brief_output(proc_brief.stdout)
            result["tls_version"] = brief_info.get("tls_version", "")
            result["verification"] = brief_info.get("verification_status", "")

    except subprocess.TimeoutExpired:
        result["error"] = f"OpenSSL timeout ({timeout}s)"
    except FileNotFoundError:
        logger.debug("openssl not found for {} — falling back to Python ssl", domain)
        return _scan_python_ssl_fallback(domain, port)
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
        logger.debug("TLS scan error for {}: {}", domain, e)

    return result


def _extract_pem_certs(showcerts_output: str) -> list[str]:
    """Extract PEM certificates from openssl -showcerts output."""
    pems: list[str] = []
    current_pem: list[str] = []
    in_cert = False

    for line in showcerts_output.split("\n"):
        if "-----BEGIN CERTIFICATE-----" in line:
            in_cert = True
            current_pem = [line]
        elif "-----END CERTIFICATE-----" in line:
            current_pem.append(line)
            pems.append("\n".join(current_pem))
            current_pem = []
            in_cert = False
        elif in_cert:
            current_pem.append(line)

    return pems


def _parse_brief_output(output: str) -> dict:
    """Parse 'openssl s_client -brief' output."""
    info: dict = {}
    for line in output.strip().split("\n"):
        line = line.strip()
        if line.startswith("Verification:"):
            info["verification_status"] = line.split(":", 1)[1].strip()
        elif line.startswith("Protocol version:"):
            info["tls_version"] = line.split(":", 1)[1].strip()
        elif line.startswith("Ciphersuite:"):
            info["ciphersuite"] = line.split(":", 1)[1].strip()
    return info


# ── Python ssl fallback ───────────────────────────────────────────────────────


def _scan_python_ssl_fallback(domain: str, port: int) -> dict:
    """Fallback TLS scanner using Python's ssl module."""
    import socket

    result: dict = {
        "domain": domain,
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "chain": [],
        "evidence": [],
        "tls_version": "",
        "verification": "",
        "error": None,
    }

    try:
        ctx = ssl.create_default_context()

        with socket.create_connection((domain, port), timeout=15) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                result["tls_version"] = ssock.version() or ""
                result["verification"] = "OK"

                der_cert = ssock.getpeercert(binary_form=True)
                if der_cert:
                    cert = x509.load_der_x509_certificate(der_cert, default_backend())
                    entry = _parse_x509_cert(cert, 0, "leaf")
                    result["chain"].append(entry)
                    result["evidence"].extend(_match_cert_to_ca(entry, SignalKind.LEAF_ISSUER))

                # Python 3.13+: get_verified_chain() returns full chain
                if hasattr(ssock, "get_verified_chain"):
                    der_chain = ssock.get_verified_chain()
                    for i, der in enumerate(der_chain[1:], start=1):
                        cert = x509.load_der_x509_certificate(der, default_backend())
                        is_self_signed = cert.subject == cert.issuer
                        cert_type = "root" if is_self_signed else "intermediate"
                        entry = _parse_x509_cert(cert, i, cert_type)
                        result["chain"].append(entry)
                        kind = SignalKind.ROOT_CA if cert_type == "root" else SignalKind.INTERMEDIATE_ISSUER
                        result["evidence"].extend(_match_cert_to_ca(entry, kind))

    except ssl.SSLCertVerificationError as e:
        result["error"] = f"SSL verification failed: {e}"
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
        logger.debug("Python ssl fallback error for {}: {}", domain, e)

    return result


# ── Certificate parsing ───────────────────────────────────────────────────────


def _get_name_attr(name: x509.Name, oid: object) -> str:
    """Extract a single attribute from an X.509 Name."""
    try:
        attrs = name.get_attributes_for_oid(oid)  # type: ignore[arg-type]
        return attrs[0].value if attrs else ""
    except Exception:
        return ""


def _parse_x509_cert(cert: x509.Certificate, position: int, cert_type: str) -> CertChainEntry:
    """Parse X.509 certificate into CertChainEntry."""
    from cryptography.hazmat.primitives import hashes

    OID = x509.oid.NameOID

    # SHA-256 fingerprint
    sha256 = cert.fingerprint(hashes.SHA256()).hex().upper()

    return CertChainEntry(
        position=position,
        cert_type=cert_type,
        subject_cn=_get_name_attr(cert.subject, OID.COMMON_NAME),
        subject_org=_get_name_attr(cert.subject, OID.ORGANIZATION_NAME),
        subject_country=_get_name_attr(cert.subject, OID.COUNTRY_NAME),
        issuer_cn=_get_name_attr(cert.issuer, OID.COMMON_NAME),
        issuer_org=_get_name_attr(cert.issuer, OID.ORGANIZATION_NAME),
        issuer_country=_get_name_attr(cert.issuer, OID.COUNTRY_NAME),
        not_before=cert.not_valid_before_utc.isoformat(),
        not_after=cert.not_valid_after_utc.isoformat(),
        serial_hex=hex(cert.serial_number),
        sig_algorithm=cert.signature_algorithm_oid.dotted_string,
        sha256_fingerprint=sha256,
    )


def _match_cert_to_ca(entry: CertChainEntry, kind: SignalKind) -> list[Evidence]:
    """Match a cert chain entry against CA signatures.

    Follows mxmap's probe_mx() pattern: iterate signatures,
    match patterns, yield Evidence objects.
    """
    results: list[Evidence] = []

    for sig in SIGNATURES:
        matched = False
        detail_parts: list[str] = []

        if match_patterns(entry.issuer_org, sig.issuer_org_patterns):
            matched = True
            detail_parts.append(f"issuer_org={entry.issuer_org}")

        if match_patterns(entry.issuer_cn, sig.issuer_cn_patterns):
            matched = True
            detail_parts.append(f"issuer_cn={entry.issuer_cn}")

        if kind == SignalKind.ROOT_CA and match_patterns(
            entry.subject_cn, sig.root_cn_patterns
        ):
            matched = True
            detail_parts.append(f"root_cn={entry.subject_cn}")

        if matched:
            results.append(
                Evidence(
                    kind=kind,
                    jurisdiction=sig.jurisdiction,
                    ca_name=sig.name,
                    weight=WEIGHTS[kind],
                    detail=f"{kind.value}: {', '.join(detail_parts)} → {sig.name}",
                    raw=f"{entry.issuer_org}|{entry.issuer_cn}",
                )
            )

    return results
