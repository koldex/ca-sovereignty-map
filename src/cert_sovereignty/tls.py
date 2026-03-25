"""TLS certificate chain scanner.

Primary: asyncio SSL with explicit IPv4 resolution.

Root cause of most timeouts: Nordic municipal servers have both A and AAAA records,
but their IPv6 port 443 endpoints are firewalled/unreachable. asyncio.open_connection
on macOS prefers IPv6 (like most modern stacks), causing 15-second timeouts for servers
that work fine on IPv4 in under 300ms.

Fix: resolve IPv4 address explicitly and connect to it (passing server_hostname for SNI).

Recovery chain when primary fails:
  1. www fallback            — try www.{domain}:443
  2. Cert mismatch recovery  — SSL verify failed → connect without verify (shared hosting)
  3. HTTP-only probe         — timeout/reset → check if port 80 is open

Additional enrichment after successful scan:
  4. HTTPS redirect following — if domain redirects to a different host (e.g.
     stockholm.se → start.stockholm), scan the redirect target instead so we
     classify the CA actually serving municipality content.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import UTC, datetime

import httpx
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

_RETRY_ERRORS = ("Connection timeout", "Connection error", "Connection reset")


async def scan_certificate_chain(domain: str, port: int = 443, timeout: int = 15) -> dict:
    """Scan TLS cert chain with full recovery chain + redirect following."""
    result = await _scan_asyncio_ssl(domain, port, timeout)

    # ── Recovery 1: www fallback ──────────────────────────────────────────────
    if result["error"] and not domain.startswith("www."):
        www = await _scan_asyncio_ssl(f"www.{domain}", port, timeout)
        if not www["error"]:
            www["domain"] = domain
            www["scanned_domain"] = f"www.{domain}"
            return www

    # ── Recovery 2: cert mismatch → shared hosting ────────────────────────────
    if result["error"] and "SSL verification failed" in result["error"]:
        shared = await _scan_asyncio_ssl_no_verify(domain, port, min(timeout, 10))
        if not shared.get("error") and shared.get("chain"):
            shared["domain"] = domain
            shared["cert_mismatch"] = True
            return shared
        if not domain.startswith("www."):
            shared_www = await _scan_asyncio_ssl_no_verify(f"www.{domain}", port, min(timeout, 10))
            if not shared_www.get("error") and shared_www.get("chain"):
                shared_www["domain"] = domain
                shared_www["scanned_domain"] = f"www.{domain}"
                shared_www["cert_mismatch"] = True
                return shared_www

    # ── Recovery 3: HTTP-only probe ───────────────────────────────────────────
    if result["error"] and any(s in result["error"] for s in _RETRY_ERRORS):
        http_ok = await _check_port_open(domain, 80, timeout=5)
        result["http_accessible"] = http_ok
        if http_ok:
            result["error"] = "http_only"

    # ── Enrichment 4: HTTPS cross-domain redirect following ───────────────────
    # Only run when we successfully got a cert — check if the domain redirects
    # to a different host (e.g. stockholm.se → start.stockholm). If so, the
    # redirect target is the actual municipal website; scan it instead.
    if not result["error"] and result.get("chain"):
        redirect_host = await _follow_https_redirect(domain, timeout=6)
        if redirect_host:
            logger.debug("Following cross-domain redirect: {} → {}", domain, redirect_host)
            redir_result = await _scan_asyncio_ssl(redirect_host, port, min(timeout, 10))
            if not redir_result.get("error") and redir_result.get("chain"):
                redir_result["domain"] = domain
                redir_result["scanned_domain"] = redirect_host
                return redir_result

    return result


async def _scan_asyncio_ssl(domain: str, port: int, timeout: int) -> dict:
    return await _connect_and_scan(domain, port, timeout, verify=True)


async def _scan_asyncio_ssl_no_verify(domain: str, port: int, timeout: int) -> dict:
    return await _connect_and_scan(domain, port, timeout, verify=False)


async def _connect_and_scan(domain: str, port: int, timeout: int, verify: bool) -> dict:
    """Core TLS scan. Prefers IPv4 to avoid broken-IPv6 timeouts."""
    result: dict = {
        "domain": domain,
        "scan_timestamp": datetime.now(UTC).isoformat(),
        "chain": [],
        "evidence": [],
        "tls_version": "",
        "verification": "",
        "error": None,
        "cert_mismatch": False,
        "http_accessible": None,
    }

    try:
        ssl_ctx = ssl.create_default_context()
        if not verify:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        # Resolve to IPv4 explicitly to avoid broken-IPv6 endpoints.
        # Many Nordic municipal servers have AAAA records but their IPv6
        # port 443 is firewalled — IPv4 works fine in <300ms.
        connect_target: str = domain
        try:
            loop = asyncio.get_event_loop()
            ipv4_infos = await asyncio.wait_for(
                loop.getaddrinfo(domain, port, family=socket.AF_INET, type=socket.SOCK_STREAM),
                timeout=5,
            )
            if ipv4_infos:
                connect_target = ipv4_infos[0][4][0]
        except Exception:
            pass  # No IPv4 → fall back to hostname (system default, may use IPv6)

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(connect_target, port, ssl=ssl_ctx, server_hostname=domain),
            timeout=timeout,
        )

        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj:
            result["tls_version"] = ssl_obj.version() or ""
            result["verification"] = "OK" if verify else "unverified"
            der_cert = ssl_obj.getpeercert(binary_form=True)
            if der_cert:
                cert = x509.load_der_x509_certificate(der_cert, default_backend())
                entry = _parse_x509_cert(cert, 0, "leaf")
                result["chain"].append(entry)
                result["evidence"].extend(_match_cert_to_ca(entry, SignalKind.LEAF_ISSUER))
            if hasattr(ssl_obj, "get_verified_chain"):
                try:
                    for i, der in enumerate(ssl_obj.get_verified_chain()[1:], start=1):
                        cert = x509.load_der_x509_certificate(der, default_backend())
                        ct = "root" if cert.subject == cert.issuer else "intermediate"
                        entry = _parse_x509_cert(cert, i, ct)
                        result["chain"].append(entry)
                        kind = (
                            SignalKind.ROOT_CA if ct == "root" else SignalKind.INTERMEDIATE_ISSUER
                        )
                        result["evidence"].extend(_match_cert_to_ca(entry, kind))
                except Exception:
                    pass

        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=2)
        except Exception:
            pass

    except TimeoutError:
        result["error"] = f"Connection timeout ({timeout}s)"
    except ssl.SSLCertVerificationError as e:
        result["error"] = f"SSL verification failed: {e}"
    except ssl.SSLError as e:
        result["error"] = f"SSL error: {e}"
    except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
        result["error"] = f"Connection error: {e}"
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
        logger.debug("TLS scan error for {}: {}", domain, e)

    return result


# ── HTTPS redirect following ──────────────────────────────────────────────────


async def _follow_https_redirect(domain: str, timeout: int = 6) -> str | None:
    """Return the final hostname after following HTTPS redirects, or None.

    Returns None if:
    - No redirect occurs (final host == original domain)
    - The redirect is only path/query (same host, e.g. /en → /)
    - Request fails

    Uses httpx (already a project dependency) with verify=False so we can
    detect redirects even from servers with cert mismatches.
    """
    try:
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=timeout,
        ) as client:
            resp = await client.head(f"https://{domain}/")
            # Use removeprefix, not lstrip — lstrip strips any char in the string
            final_host = resp.url.host.lower().removeprefix("www.")
            original = domain.lower().removeprefix("www.")
            if final_host != original:
                # Cross-domain redirect found
                return resp.url.host  # Return actual final host including www if present
    except Exception:
        pass
    return None


# ── HTTP-only probe ───────────────────────────────────────────────────────────


async def _check_port_open(domain: str, port: int, timeout: int = 5) -> bool:
    """Return True if a TCP connection to domain:port succeeds within timeout."""
    try:
        # Also try IPv4 explicitly here
        loop = asyncio.get_event_loop()
        try:
            ipv4_infos = await asyncio.wait_for(
                loop.getaddrinfo(domain, port, family=socket.AF_INET, type=socket.SOCK_STREAM),
                timeout=3,
            )
            target = ipv4_infos[0][4][0] if ipv4_infos else domain
        except Exception:
            target = domain

        _, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port),
            timeout=timeout,
        )
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=1)
        except Exception:
            pass
        return True
    except Exception:
        return False


# ── Certificate parsing ───────────────────────────────────────────────────────


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


def _extract_pem_certs(showcerts_output: str) -> list[str]:
    pems: list[str] = []
    current: list[str] = []
    in_cert = False
    for line in showcerts_output.split("\n"):
        if "-----BEGIN CERTIFICATE-----" in line:
            in_cert = True
            current = [line]
        elif "-----END CERTIFICATE-----" in line:
            current.append(line)
            pems.append("\n".join(current))
            in_cert = False
        elif in_cert:
            current.append(line)
    return pems
