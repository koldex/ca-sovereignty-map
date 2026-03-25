"""Pipeline orchestration: scan → classify → serialize.

Three-phase pipeline:
  Phase 1 (resolve-domains): Wikidata + national APIs + domain guessing
  Phase 2 (scan-certs):      TLS scan + DNS probes + CCADB enrichment → classify
  Phase 3 (analyze):         Statistics + diff + report

Follows mxmap's pipeline.py pattern with semaphore-limited concurrency.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from loguru import logger

from .classifier import classify
from .constants import CATEGORY_MAP, SEMAPHORE_LIMIT
from .models import ClassificationResult, Jurisdiction, RiskLevel
from .probes import probe_caa, probe_ct_log
from .tls import scan_certificate_chain

# ── Phase 2: Certificate scanning ─────────────────────────────────────────────


async def scan_domain(
    domain: str,
    *,
    port: int = 443,
    semaphore: asyncio.Semaphore,
    skip_ct: bool = False,
) -> ClassificationResult:
    """Scan a single domain and return classification result."""
    async with semaphore:
        logger.debug("Scanning {}", domain)  # debug level to keep progress bar clean

        # TLS certificate chain scan
        tls_result = await scan_certificate_chain(domain, port=port)
        tls_evidence = tls_result.get("evidence", [])
        chain = tls_result.get("chain", [])
        tls_version = tls_result.get("tls_version", "")
        verification = tls_result.get("verification", "")
        error = tls_result.get("error")

        # DNS CAA records
        caa_evidence = await probe_caa(domain)
        caa_records = [ev.raw for ev in caa_evidence]

        # Certificate Transparency logs (optional, slower)
        ct_evidence = []
        ct_issuers: list[str] = []
        if not skip_ct:
            ct_evidence = await probe_ct_log(domain)
            ct_issuers = list(dict.fromkeys(ev.raw for ev in ct_evidence))

        return classify(
            domain=domain,
            tls_evidence=tls_evidence,
            caa_evidence=caa_evidence,
            ct_evidence=ct_evidence,
            chain=chain,
            caa_records=caa_records,
            ct_issuers=ct_issuers,
            tls_version=tls_version,
            verification=verification,
            error=error,
            cert_mismatch=tls_result.get("cert_mismatch", False),
            http_accessible=tls_result.get("http_accessible"),
            scanned_domain=tls_result.get("scanned_domain", ""),
        )


async def scan_many(
    domains: list[str],
    *,
    concurrency: int = SEMAPHORE_LIMIT,
    skip_ct: bool = False,
) -> dict[str, ClassificationResult]:
    """Scan multiple domains concurrently, printing a live progress bar."""
    total = len(domains)
    semaphore = asyncio.Semaphore(concurrency)

    # Wrap each scan_domain coroutine to track completions
    async def _tracked(domain: str) -> tuple[str, ClassificationResult]:
        result = await scan_domain(domain, semaphore=semaphore, skip_ct=skip_ct)
        return domain, result

    tasks = [asyncio.create_task(_tracked(d)) for d in domains]

    output: dict[str, ClassificationResult] = {}
    done_count = 0
    classified = 0
    start_time = time.monotonic()

    PROGRESS_EVERY = max(1, total // 50)  # update ~50 times

    for coro in asyncio.as_completed(tasks):
        try:
            domain, result = await coro
        except Exception as exc:
            # Shouldn't happen — _tracked catches all errors — but just in case
            logger.error("Unexpected exception in scan task: {}", exc)
            continue

        if isinstance(result, Exception):
            logger.error("scan_domain raised: {}", result)
            domain_key = str(result)
            output[domain_key] = ClassificationResult(
                domain=domain_key,
                primary_ca="Unknown",
                jurisdiction=Jurisdiction.OTHER,
                risk_level=RiskLevel.MEDIUM,
                confidence=0.0,
                error=str(result),
            )
        else:
            output[domain] = result
            if result.jurisdiction.value != "other":
                classified += 1

        done_count += 1

        if done_count % PROGRESS_EVERY == 0 or done_count == total:
            elapsed = time.monotonic() - start_time
            pct = done_count / total * 100
            rate = done_count / elapsed if elapsed > 0 else 0
            eta = (total - done_count) / rate if rate > 0 else 0
            bar_len = 30
            filled = int(bar_len * done_count / total)
            bar = "█" * filled + "░" * (bar_len - filled)
            line = (
                f"\r  [{bar}] {done_count}/{total} ({pct:.0f}%)"
                f"  classified: {classified}"
                f"  {rate:.1f} dom/s"
                f"  ETA: {int(eta)}s  "
            )
            sys.stderr.write(line)
            sys.stderr.flush()

    sys.stderr.write("\n")
    sys.stderr.flush()
    return output


# ── Serialization ──────────────────────────────────────────────────────────────


def serialize_result(
    result: ClassificationResult,
    municipality_meta: dict,
    shared_hosting: bool = False,
    shared_cert_fp: str = "",
) -> dict:
    """Serialize a ClassificationResult to the data.json municipality format."""
    jurisdiction_str = result.jurisdiction.value
    category = CATEGORY_MAP.get(jurisdiction_str, "unknown")

    # Derive a human-readable error_category
    error = result.error or ""
    if error == "http_only":
        error_category = "http_only"
    elif result.cert_mismatch:
        error_category = "shared_hosting"
    elif shared_hosting:
        error_category = "shared_hosting"
    elif "timeout" in error.lower():
        error_category = "timeout"
    elif "verification failed" in error.lower():
        error_category = "ssl_mismatch"
    elif "ssl" in error.lower():
        error_category = "ssl_error"
    elif error:
        error_category = "connection_error"
    else:
        error_category = ""

    return {
        "id": municipality_meta.get("id", ""),
        "name": municipality_meta.get("name", ""),
        "name_sv": municipality_meta.get("name_sv", ""),
        "country": municipality_meta.get("country", ""),
        "region": municipality_meta.get("region", ""),
        "domain": result.domain,
        "scanned_domain": result.scanned_domain or "",
        "population": municipality_meta.get("population"),
        "primary_ca": result.primary_ca,
        "ca_owner": result.ca_owner,
        "ca_country": result.ca_country,
        "jurisdiction": jurisdiction_str,
        "risk_level": result.risk_level.value,
        "category": category,
        "classification_confidence": round(result.confidence * 100, 1),
        "cert_chain": [entry.model_dump(exclude_none=True) for entry in result.cert_chain],
        "caa_records": result.caa_records,
        "ct_issuers": result.ct_issuers,
        "tls_info": {
            "tls_version": result.tls_version,
            "verification": result.verification,
        },
        "classification_signals": [
            {
                "kind": ev.kind.value,
                "ca_name": ev.ca_name,
                "weight": ev.weight,
                "detail": ev.detail,
            }
            for ev in result.evidence
        ],
        # Context fields
        "cert_mismatch": result.cert_mismatch,
        "http_accessible": result.http_accessible,
        "shared_hosting": shared_hosting,
        "shared_cert_fingerprint": shared_cert_fp,
        "error_category": error_category,
        "error": result.error,
        "scan_timestamp": result.scan_timestamp,
    }


def _detect_shared_hosting(
    results: dict[str, ClassificationResult],
    threshold: int = 5,
) -> dict[str, tuple[bool, str]]:
    """Return {domain: (is_shared, fingerprint)} for domains sharing a cert.

    If threshold or more domains share the same leaf cert SHA-256 fingerprint,
    they are on a shared hosting platform.
    """
    from collections import Counter

    # Count fingerprints across all successful scans
    fp_count: Counter[str] = Counter()
    domain_fp: dict[str, str] = {}
    for domain, result in results.items():
        if result.cert_chain:
            fp = result.cert_chain[0].sha256_fingerprint
            if fp:
                fp_count[fp] += 1
                domain_fp[domain] = fp

    shared_fps = {fp for fp, count in fp_count.items() if count >= threshold}
    if shared_fps:
        logger.info(
            "Shared hosting detected: {} fingerprints used by {}+ municipalities",
            len(shared_fps),
            threshold,
        )
        for fp in shared_fps:
            count = fp_count[fp]
            logger.info("  {} ({} municipalities)", fp[:16] + "...", count)

    return {domain: (fp in shared_fps, fp) for domain, fp in domain_fp.items()}


def build_data_json(
    municipalities: list[dict],
    results: dict[str, ClassificationResult],
    *,
    commit: str = "",
) -> dict:
    """Build the final data.json payload with shared hosting detection."""
    generated = datetime.now(UTC).isoformat()

    # Detect shared hosting (5+ municipalities with same leaf cert)
    shared_info = _detect_shared_hosting(results)

    # Count breakdown including http_only
    counts: dict[str, int] = {
        "us-controlled": 0,
        "eu-controlled": 0,
        "nordic": 0,
        "allied": 0,
        "http_only": 0,
        "unknown": 0,
    }

    muni_data: dict[str, dict] = {}

    for muni in municipalities:
        muni_id = muni["id"]
        domain = muni.get("domain", "")
        result = results.get(domain)

        if result:
            is_shared, fp = shared_info.get(domain, (False, ""))
            serialized = serialize_result(result, muni, shared_hosting=is_shared, shared_cert_fp=fp)
            if result.error == "http_only":
                counts["http_only"] = counts.get("http_only", 0) + 1
            else:
                category = serialized.get("category", "unknown")
                counts[category] = counts.get(category, 0) + 1
        else:
            serialized = {
                **muni,
                "error": "no_domain",
                "category": "unknown",
                "error_category": "no_domain",
            }
            counts["unknown"] += 1

        muni_data[muni_id] = serialized

    return {
        "generated": generated,
        "commit": commit,
        "scan_method": "asyncio_ssl",
        "total": len(municipalities),
        "counts": counts,
        "municipalities": muni_data,
    }


def write_output(data: dict, output_dir: Path) -> None:
    """Write data.json and data.min.json to output directory."""
    full_path = output_dir / "data.json"
    min_path = output_dir / "data.min.json"

    with open(full_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    logger.info("Wrote {}", full_path)

    with open(min_path, "w", encoding="utf-8") as f:
        json.dump(data, f, separators=(",", ":"), ensure_ascii=False)
    logger.info("Wrote {}", min_path)
