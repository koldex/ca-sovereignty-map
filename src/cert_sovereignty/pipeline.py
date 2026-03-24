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
import shutil
from datetime import datetime, timezone
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
    """Scan a single domain and return classification result.

    Uses semaphore to limit concurrency (cf. mxmap's classify_many()).
    """
    async with semaphore:
        logger.info("Scanning {}", domain)

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
        )


async def scan_many(
    domains: list[str],
    *,
    concurrency: int = SEMAPHORE_LIMIT,
    skip_ct: bool = False,
) -> dict[str, ClassificationResult]:
    """Scan multiple domains concurrently with semaphore limiting.

    Cf. mxmap's classify_many().
    """
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [
        scan_domain(domain, semaphore=semaphore, skip_ct=skip_ct)
        for domain in domains
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    output: dict[str, ClassificationResult] = {}
    for domain, result in zip(domains, results):
        if isinstance(result, Exception):
            logger.error("scan_domain({}) raised: {}", domain, result)
            output[domain] = ClassificationResult(
                domain=domain,
                primary_ca="Unknown",
                jurisdiction=Jurisdiction.OTHER,
                risk_level=RiskLevel.MEDIUM,
                confidence=0.0,
                error=str(result),
            )
        else:
            output[domain] = result

    return output


# ── Serialization ──────────────────────────────────────────────────────────────


def serialize_result(result: ClassificationResult, municipality_meta: dict) -> dict:
    """Serialize a ClassificationResult to the data.json municipality format."""
    jurisdiction_str = result.jurisdiction.value
    category = CATEGORY_MAP.get(jurisdiction_str, "unknown")

    return {
        "id": municipality_meta.get("id", ""),
        "name": municipality_meta.get("name", ""),
        "name_sv": municipality_meta.get("name_sv", ""),
        "country": municipality_meta.get("country", ""),
        "region": municipality_meta.get("region", ""),
        "domain": result.domain,
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
        "error": result.error,
        "scan_timestamp": result.scan_timestamp,
    }


def build_data_json(
    municipalities: list[dict],
    results: dict[str, ClassificationResult],
    *,
    commit: str = "",
) -> dict:
    """Build the final data.json payload.

    Cf. mxmap's build_data_json().
    """
    generated = datetime.now(timezone.utc).isoformat()

    # Count by jurisdiction
    counts: dict[str, int] = {
        "us-controlled": 0,
        "eu-controlled": 0,
        "nordic": 0,
        "allied": 0,
        "unknown": 0,
    }

    muni_data: dict[str, dict] = {}

    for muni in municipalities:
        muni_id = muni["id"]
        domain = muni.get("domain", "")
        result = results.get(domain)

        if result:
            serialized = serialize_result(result, muni)
            category = serialized.get("category", "unknown")
            counts[category] = counts.get(category, 0) + 1
        else:
            serialized = {**muni, "error": "no_domain", "category": "unknown"}
            counts["unknown"] += 1

        muni_data[muni_id] = serialized

    return {
        "generated": generated,
        "commit": commit,
        "scan_method": "openssl_subprocess",
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
