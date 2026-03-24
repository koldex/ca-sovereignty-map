"""TLS certificate chain scanner.

Primary: asyncio SSL (asyncio.open_connection with ssl=).
Avoids OpenSSL subprocess timeout issues — handles ALPN/SNI natively.
www fallback: if domain:443 fails, automatically tries www.{domain}:443.
"""

from __future__ import annotations

import asyncio
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
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


async def scan_certificate_chain(domain: str, port: int = 443, timeout: int = 15) -> dict:
    """Scan TLS cert chain. Uses asyncio SSL + www fallback."""
    result = await _scan_asyncio_ssl(domain, port, timeout)

    if result["error"] and not domain.startswith("www."):
        www_result = await _scan_asyncio_ssl(f"www.{domain}", port, timeout)
        if not www_result["error"]:
            www_result["domain"] = domain
            www_result["scanned_domain"] = f"www.{domain}"
            logger.debug("Used www fallback for {}", domain)
            return www_result

    return result


async def _scan_asyncio_ssl(domain: str, port: int, timeout: int) -> dict:
    """Scan using asyncio SSL — handles SNI/ALPN properly, reliable timeout."""
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
        ssl_ctx = ssl.create_default_context()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(domain, port, ssl=ssl_ctx, server_hostname=domain),
            timeout=timeout,
        )
        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj:
            result["tls_version"] = ssl_obj.version() or ""
            result["verification"] = "OK"
            der_cert = ssl_obj.getpeercert(binary_form=True)
            if der_cert:
                cert = x509.load_der_x509_certificate(der_cert, default_backend())
                entry = _parse_x509_cert(cert, 0, "leaf")
                result["chain"].append(entry)
                result["evidence"].extend(_match_cert_to_ca(entry, SignalKind.LEAF_ISSUER))
            # Full chain (Python 3.13+)
            if hasattr(ssl_obj, "get_verified_chain"):
                try:
                    for i, der in enumerate(ssl_obj.get_verified_chain()[1:], start=1):
                        cert = x509.load_der_x509_certificate(der, default_backend())
                        ct = "root" if cert.subject == cert.issuer else "intermediate"
                        entry = _parse_x509_cert(cert, i, ct)
                        result["chain"].append(entry)
                        kind = SignalKind.ROOT_CA if ct == "root" else SignalKind.INTERMEDIATE_ISSUER
                        result["evidence"].extend(_match_cert_to_ca(entry, kind))
                except Exception:
                    pass
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=2)
        except Exception:
            pass
    except asyncio.TimeoutError:
        result["error"] = f"Connection timeout ({timeout}s)"
    except ssl.SSLCertVerificationError as e:
        result["error"] = f"SSL verification failed: {e}"
    except ssl.SSLError as e:
        result["error"] = f"SSL error: {e}"
    except (ConnectionRefusedError, OSError) as e:
        result["error"] = f"Connection error: {e}"
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
        logger.debug("TLS scan error for {}: {}", domain, e)
    return result


def _get_name_attr(name: x509.Name, oid: object) -> str:
    try:
        attrs = name.get_attributes_for_oid(oid)  # type: ignore[arg-type]
        return attrs[0].value if attrs else ""
    except Exception:
        return ""


def _parse_x509_cert(cert: x509.Certificate, position: int, cert_type: str) -> CertChainEntry:
    OID = x509.oid.NameOID
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
        sha256_fingerprint=cert.fingerprint(hashes.SHA256()).hex().upper(),
    )


def _match_cert_to_ca(entry: CertChainEntry, kind: SignalKind) -> list[Evidence]:
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
        if kind == SignalKind.ROOT_CA and match_patterns(entry.subject_cn, sig.root_cn_patterns):
            matched = True
            detail_parts.append(f"root_cn={entry.subject_cn}")
        if matched:
            results.append(Evidence(
                kind=kind,
                jurisdiction=sig.jurisdiction,
                ca_name=sig.name,
                weight=WEIGHTS[kind],
                detail=f"{kind.value}: {', '.join(detail_parts)} → {sig.name}",
                raw=f"{entry.issuer_org}|{entry.issuer_cn}",
            ))
    return results


# Kept for diagnostics / manual inspection
def _extract_pem_certs(showcerts_output: str) -> list[str]:
    pems, current, in_cert = [], [], False
    for line in showcerts_output.split("\n"):
        if "-----BEGIN CERTIFICATE-----" in line:
            in_cert = True; current = [line]
        elif "-----END CERTIFICATE-----" in line:
            current.append(line); pems.append("\n".join(current)); in_cert = False
        elif in_cert:
            current.append(line)
    return pems
