"""DNS resolution utilities.

Reused directly from mxmap's dns.py pattern:
- resolve_robust(): multi-resolver fallback (System → Quad9 → Cloudflare)
- Used by both the domain resolver and CAA probe.
"""

from __future__ import annotations

import asyncio

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver
from loguru import logger

# Fallback resolvers (in order of preference)
_RESOLVERS = [
    None,  # System default
    "9.9.9.9",  # Quad9
    "1.1.1.1",  # Cloudflare
    "8.8.8.8",  # Google (last resort)
]


async def resolve_robust(
    domain: str,
    rdtype: str,
    *,
    timeout: float = 5.0,
) -> dns.resolver.Answer | None:
    """Resolve a DNS record type with multi-resolver fallback.

    Tries system resolver first, then Quad9, Cloudflare, Google.
    Returns the first successful answer or None.

    Directly mirrors mxmap's resolve_robust().
    """
    for nameserver in _RESOLVERS:
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout

            if nameserver is not None:
                resolver.nameservers = [nameserver]

            answer = await resolver.resolve(domain, rdtype)
            return answer

        except dns.resolver.NXDOMAIN:
            # Domain doesn't exist — no need to try other resolvers
            return None
        except dns.resolver.NoAnswer:
            # Record type doesn't exist — no need to try other resolvers
            return None
        except (dns.exception.DNSException, OSError, asyncio.TimeoutError) as e:
            ns_label = nameserver or "system"
            logger.debug("DNS {} {} via {}: {}", rdtype, domain, ns_label, e)
            continue

    return None


async def lookup_a(domain: str) -> list[str]:
    """Return A record IP addresses for a domain."""
    answer = await resolve_robust(domain, "A")
    if answer is None:
        return []
    return [rdata.address for rdata in answer]


async def lookup_caa(domain: str) -> list[tuple[int, str, str]]:
    """Return CAA records as (flags, tag, value) tuples."""
    answer = await resolve_robust(domain, "CAA")
    if answer is None:
        return []
    results = []
    for rdata in answer:
        results.append((rdata.flags, rdata.tag, rdata.value))
    return results


async def domain_resolves(domain: str) -> bool:
    """Check if a domain has at least one A or AAAA record."""
    a_records = await lookup_a(domain)
    if a_records:
        return True
    answer = await resolve_robust(domain, "AAAA")
    return answer is not None and len(answer) > 0
