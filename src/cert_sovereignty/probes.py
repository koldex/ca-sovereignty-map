"""DNS-based probes for CA sovereignty (CAA records, CT logs).

Extends mxmap's probe pattern with certificate-specific signals.
Reuses dns.py (resolve_robust) directly.
"""

from __future__ import annotations

import httpx
import stamina
from loguru import logger

from .constants import HTTP_TIMEOUT, MAX_CT_ENTRIES
from .dns import resolve_robust
from .models import Evidence, SignalKind
from .signatures import SIGNATURES, match_patterns
from .tls import WEIGHTS


async def probe_caa(domain: str) -> list[Evidence]:
    """Query DNS CAA records — indicates which CAs are AUTHORIZED.

    CAA records are the domain owner's explicit declaration of which
    CA may issue certificates. Strong signal for CA identification.
    """
    results: list[Evidence] = []
    answer = await resolve_robust(domain, "CAA")

    if answer is None:
        return results

    for rdata in answer:
        if rdata.flags == 0 and rdata.tag in ("issue", "issuewild"):
            ca_value = rdata.value.lower().strip().strip('"')
            for sig in SIGNATURES:
                if match_patterns(ca_value, sig.caa_values):
                    results.append(
                        Evidence(
                            kind=SignalKind.CAA_RECORD,
                            jurisdiction=sig.jurisdiction,
                            ca_name=sig.name,
                            weight=WEIGHTS[SignalKind.CAA_RECORD],
                            detail=f"CAA {rdata.tag}={ca_value} → {sig.name}",
                            raw=ca_value,
                        )
                    )

    return results


@stamina.retry(
    on=(httpx.HTTPStatusError, httpx.ConnectError, httpx.TimeoutException),
    attempts=2,
    wait_initial=1.0,
)
async def _fetch_crtsh(client: httpx.AsyncClient, domain: str) -> list[dict]:
    """Query crt.sh Certificate Transparency API."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    r = await client.get(url, timeout=HTTP_TIMEOUT)
    r.raise_for_status()
    return r.json()


async def probe_ct_log(domain: str) -> list[Evidence]:
    """Query Certificate Transparency logs via crt.sh.

    Provides historical view of which CAs have issued certs for this domain.
    Not the strongest signal (historical), but useful for validation.
    """
    results: list[Evidence] = []
    try:
        async with httpx.AsyncClient() as client:
            entries = await _fetch_crtsh(client, domain)

            # Deduplicate by issuer
            seen_issuers: set[str] = set()
            for entry in entries[:MAX_CT_ENTRIES]:
                issuer = entry.get("issuer_name", "")
                if not issuer or issuer in seen_issuers:
                    continue
                seen_issuers.add(issuer)

                for sig in SIGNATURES:
                    combined = sig.issuer_org_patterns + sig.issuer_cn_patterns
                    if match_patterns(issuer, combined):
                        results.append(
                            Evidence(
                                kind=SignalKind.CT_LOG,
                                jurisdiction=sig.jurisdiction,
                                ca_name=sig.name,
                                weight=WEIGHTS[SignalKind.CT_LOG],
                                detail=f"CT log issuer: {issuer} → {sig.name}",
                                raw=issuer,
                            )
                        )
                        break

    except Exception as e:
        logger.debug("CT log query failed for {}: {}", domain, e)

    return results
