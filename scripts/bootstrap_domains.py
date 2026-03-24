#!/usr/bin/env python3
"""Bootstrap municipality_domains.json from TopoJSON + domain guessing.

Alternative to 'resolve-domains' when Wikidata is unavailable.
Reads nordic-municipalities.topojson, applies overrides.json,
then runs domain guessing with DNS validation for the rest.

Usage:
    uv run python scripts/bootstrap_domains.py [--country FI] [--concurrency 40]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from cert_sovereignty.resolve import guess_domains, validate_domain

COUNTRIES = ["FI", "SE", "NO", "DK"]
CONCURRENCY = 40


def load_topojson_municipalities(topojson_path: Path, countries: list[str]) -> list[dict]:
    """Extract municipality list from TopoJSON file."""
    with open(topojson_path) as f:
        topo = json.load(f)

    geometries = topo["objects"]["municipalities"]["geometries"]
    municipalities = []
    for g in geometries:
        props = g.get("properties", {})
        country = props.get("country", "")
        if country not in countries:
            continue
        municipalities.append({
            "id": props["id"],
            "name": props["name"],
            "country": country,
            "population": props.get("population", 0),
        })

    return municipalities


def load_overrides(overrides_path: Path) -> dict[str, str]:
    """Load manual domain overrides. Returns {municipality_id: domain}."""
    if not overrides_path.exists():
        return {}
    with open(overrides_path) as f:
        data = json.load(f)
    return {
        k: v["domain"]
        for k, v in data.items()
        if k != "_comment" and isinstance(v, dict) and "domain" in v
    }


async def resolve_municipality_domain(
    muni: dict,
    overrides: dict[str, str],
    semaphore: asyncio.Semaphore,
) -> dict | None:
    """Resolve domain for a single municipality."""
    muni_id = muni["id"]
    name = muni["name"]
    country = muni["country"]

    # Priority 1: manual override
    if muni_id in overrides:
        domain = overrides[muni_id]
        return {**muni, "domain": domain, "domain_source": "override"}

    # Priority 2: domain guessing with DNS validation
    async with semaphore:
        candidates = guess_domains(name, country)
        for candidate in candidates:
            try:
                if await validate_domain(candidate):
                    return {**muni, "domain": candidate, "domain_source": "guess"}
            except Exception:
                continue

    # No domain found
    return {**muni, "domain": None, "domain_source": "not_found"}


async def resolve_all(
    municipalities: list[dict],
    overrides: dict[str, str],
    concurrency: int = CONCURRENCY,
) -> list[dict]:
    """Resolve domains for all municipalities concurrently."""
    semaphore = asyncio.Semaphore(concurrency)
    total = len(municipalities)
    resolved = 0
    not_found = 0

    print(f"Resolving domains for {total} municipalities (concurrency={concurrency})...")
    print("(This may take a few minutes for DNS lookups)")
    print()

    tasks = [
        resolve_municipality_domain(muni, overrides, semaphore)
        for muni in municipalities
    ]

    results = []
    for i, coro in enumerate(asyncio.as_completed(tasks), 1):
        result = await coro
        if result:
            results.append(result)
            if result.get("domain"):
                resolved += 1
            else:
                not_found += 1

        if i % 50 == 0 or i == total:
            pct = i / total * 100
            print(f"  Progress: {i}/{total} ({pct:.0f}%) — found: {resolved}, not found: {not_found}")

    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Bootstrap municipality_domains.json from TopoJSON"
    )
    parser.add_argument("--topojson", default=str(ROOT / "nordic-municipalities.topojson"))
    parser.add_argument("--overrides", default=str(ROOT / "overrides.json"))
    parser.add_argument("--output", default=str(ROOT / "municipality_domains.json"))
    parser.add_argument("--country", nargs="+", default=COUNTRIES,
                        help="Countries to process (default: all)")
    parser.add_argument("--concurrency", type=int, default=CONCURRENCY)
    parser.add_argument("--include-not-found", action="store_true",
                        help="Include municipalities with no domain found")
    args = parser.parse_args()

    topojson_path = Path(args.topojson)
    if not topojson_path.exists():
        print(f"ERROR: {topojson_path} not found. Run scripts/generate_topojson.py first.")
        sys.exit(1)

    print("=" * 60)
    print("CAmap Nordics — Domain Bootstrap")
    print("=" * 60)
    print(f"Countries: {args.country}")
    print()

    # Load data
    municipalities = load_topojson_municipalities(topojson_path, args.country)
    overrides = load_overrides(Path(args.overrides))
    print(f"Loaded {len(municipalities)} municipalities from TopoJSON")
    print(f"Loaded {len(overrides)} manual overrides")
    print()

    # Resolve
    results = asyncio.run(resolve_all(municipalities, overrides, args.concurrency))

    # Filter and sort
    with_domain = [r for r in results if r.get("domain")]
    without_domain = [r for r in results if not r.get("domain")]

    print(f"\nResults:")
    print(f"  With domain:    {len(with_domain)}")
    print(f"  Without domain: {len(without_domain)}")

    # Write output
    output = with_domain if not args.include_not_found else results
    output.sort(key=lambda r: (r["country"], r["id"]))

    output_path = Path(args.output)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"\nWrote {len(output)} entries → {output_path}")
    print()
    print("Next step: uv run scan-certs --skip-ct")


if __name__ == "__main__":
    main()
