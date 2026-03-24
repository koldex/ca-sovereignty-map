"""CLI entry points for the cert_sovereignty pipeline.

Commands:
  resolve-domains  Phase 1: Resolve municipality domains via Wikidata + guessing
  scan-certs       Phase 2: TLS scan + classify all resolved domains
  analyze          Phase 3: Print statistics report from data.json
  update-ccadb     Fetch latest CCADB CSV database
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from loguru import logger

from .log import setup_logging

ROOT = Path(__file__).parent.parent.parent  # project root


def resolve_domains() -> None:
    """Phase 1: Resolve municipality domains.

    Reads overrides.json + Wikidata SPARQL + domain guessing.
    Writes municipality_domains.json.
    """
    import argparse

    parser = argparse.ArgumentParser(description="Resolve Nordic municipality domains")
    parser.add_argument("--countries", nargs="+", default=["FI", "SE", "NO", "DK"])
    parser.add_argument("--output", default=str(ROOT / "municipality_domains.json"))
    parser.add_argument("--overrides", default=str(ROOT / "overrides.json"))
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    setup_logging(args.verbose)

    async def _run() -> None:
        from .resolve import fetch_wikidata_domains, load_overrides, resolve_municipality_domain

        overrides = load_overrides(Path(args.overrides))
        all_results: list[dict] = []

        for country in args.countries:
            logger.info("Resolving domains for {}", country)
            wikidata_domains = await fetch_wikidata_domains(country)

            # TODO: Fetch from national APIs for authoritative municipality list
            # For now, use Wikidata results as the municipality list
            for muni_id, domain in wikidata_domains.items():
                all_results.append(
                    {
                        "id": muni_id,
                        "country": country,
                        "domain": domain,
                        "source": "wikidata",
                    }
                )

        output_path = Path(args.output)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(all_results, f, indent=2, ensure_ascii=False)

        logger.info("Wrote {} municipality domains to {}", len(all_results), output_path)

    asyncio.run(_run())


def scan_certs() -> None:
    """Phase 2: Scan TLS certificates for all municipalities.

    Reads municipality_domains.json + overrides.json.
    Writes data.json + data.min.json.
    """
    import argparse

    parser = argparse.ArgumentParser(description="Scan TLS certificates for Nordic municipalities")
    parser.add_argument("--input", default=str(ROOT / "municipality_domains.json"))
    parser.add_argument("--output-dir", default=str(ROOT))
    parser.add_argument("--concurrency", type=int, default=50)
    parser.add_argument("--skip-ct", action="store_true", help="Skip CT log queries")
    parser.add_argument("--country", help="Scan only this country")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    setup_logging(args.verbose)

    async def _run() -> None:
        from .pipeline import build_data_json, scan_many, write_output

        input_path = Path(args.input)
        if not input_path.exists():
            logger.error("Input file not found: {}", input_path)
            sys.exit(1)

        with open(input_path, encoding="utf-8") as f:
            municipalities = json.load(f)

        # Optionally filter by country
        if args.country:
            municipalities = [m for m in municipalities if m.get("country") == args.country]
            logger.info("Filtered to {} {} municipalities", len(municipalities), args.country)

        # Extract domain list
        domains = [m["domain"] for m in municipalities if m.get("domain")]
        logger.info("Scanning {} domains with concurrency={}", len(domains), args.concurrency)

        results = await scan_many(
            domains,
            concurrency=args.concurrency,
            skip_ct=args.skip_ct,
        )

        data = build_data_json(municipalities, results)
        write_output(data, Path(args.output_dir))

    asyncio.run(_run())


def analyze() -> None:
    """Phase 3: Print statistics report from data.json."""
    import argparse

    parser = argparse.ArgumentParser(description="Analyze CA sovereignty data")
    parser.add_argument("--input", default=str(ROOT / "data.json"))
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    from .analyze import compute_stats, load_data, print_report

    data_path = Path(args.input)
    if not data_path.exists():
        logger.error("data.json not found: {}", data_path)
        sys.exit(1)

    data = load_data(data_path)
    stats = compute_stats(data)

    if args.json:
        print(json.dumps(stats, indent=2, ensure_ascii=False))
    else:
        print_report(stats)


def update_ccadb() -> None:
    """Fetch latest CCADB CSV and save to ccadb_cache.json."""
    import argparse

    parser = argparse.ArgumentParser(description="Update CCADB certificate database")
    parser.add_argument("--output", default=str(ROOT / "ccadb_cache.json"))
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    setup_logging(args.verbose)

    async def _run() -> None:
        import csv
        import io

        import httpx

        from .constants import CCADB_ALL_CERTS_CSV

        logger.info("Fetching CCADB certificate database...")
        async with httpx.AsyncClient(timeout=60) as client:
            r = await client.get(CCADB_ALL_CERTS_CSV)
            r.raise_for_status()
            csv_text = r.text

        entries = {}
        reader = csv.DictReader(io.StringIO(csv_text))
        for row in reader:
            fp = row.get("SHA-256 Fingerprint", "").upper().replace(":", "")
            if fp:
                entries[fp] = {
                    "ca_owner": row.get("CA Owner", ""),
                    "issuer_cn": row.get("Certificate Name", row.get("Issuer CommonName", "")),
                    "country": row.get("Country", ""),
                    "tls_capable": row.get("TLS Capable", "").lower() == "true",
                }

        output_path = Path(args.output)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(entries, f, separators=(",", ":"))

        logger.info("Wrote {} CCADB entries to {}", len(entries), output_path)

    asyncio.run(_run())
