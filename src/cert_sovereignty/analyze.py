"""Statistics analysis for CA sovereignty data.

Adapted from mxmap's analyze.py — same structure, CA-specific metrics.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

from loguru import logger


def load_data(data_path: Path) -> dict:
    """Load data.json file."""
    with open(data_path, encoding="utf-8") as f:
        return json.load(f)


def compute_stats(data: dict) -> dict:
    """Compute statistics from data.json municipalities.

    Returns dict with global + per-country breakdowns.
    """
    municipalities = data.get("municipalities", {})

    global_ca_counter: Counter[str] = Counter()
    global_jurisdiction_counter: Counter[str] = Counter()
    country_stats: dict[str, dict] = defaultdict(
        lambda: {
            "total": 0,
            "by_jurisdiction": Counter(),
            "by_ca": Counter(),
            "by_risk": Counter(),
            "no_domain": 0,
            "errors": 0,
        }
    )

    for muni_id, muni in municipalities.items():
        country = muni.get("country", "UNKNOWN")
        jurisdiction = muni.get("jurisdiction", "other")
        ca = muni.get("primary_ca", "Unknown")
        risk = muni.get("risk_level", "unknown")
        error = muni.get("error")
        domain = muni.get("domain", "")

        country_stats[country]["total"] += 1

        if not domain or error == "no_domain":
            country_stats[country]["no_domain"] += 1
            continue

        if error and error != "no_domain":
            country_stats[country]["errors"] += 1

        country_stats[country]["by_jurisdiction"][jurisdiction] += 1
        country_stats[country]["by_ca"][ca] += 1
        country_stats[country]["by_risk"][risk] += 1

        global_jurisdiction_counter[jurisdiction] += 1
        global_ca_counter[ca] += 1

    return {
        "total": len(municipalities),
        "global": {
            "by_jurisdiction": dict(global_jurisdiction_counter.most_common()),
            "by_ca": dict(global_ca_counter.most_common(20)),
        },
        "by_country": {
            country: {
                "total": stats["total"],
                "no_domain": stats["no_domain"],
                "errors": stats["errors"],
                "by_jurisdiction": dict(stats["by_jurisdiction"].most_common()),
                "by_ca": dict(stats["by_ca"].most_common(10)),
                "by_risk": dict(stats["by_risk"].most_common()),
                "us_pct": round(
                    stats["by_jurisdiction"].get("us", 0)
                    / max(stats["total"] - stats["no_domain"], 1)
                    * 100,
                    1,
                ),
            }
            for country, stats in sorted(country_stats.items())
        },
    }


def print_report(stats: dict) -> None:
    """Print a human-readable analysis report to stdout."""
    print("\n" + "=" * 60)
    print("CAmap Nordics — CA Sovereignty Analysis")
    print("=" * 60)

    print(f"\nTotal municipalities: {stats['total']}")

    print("\nGlobal jurisdiction breakdown:")
    for jurisdiction, count in stats["global"]["by_jurisdiction"].items():
        pct = count / max(stats["total"], 1) * 100
        bar = "█" * int(pct / 2)
        print(f"  {jurisdiction:12s} {count:4d}  {pct:5.1f}%  {bar}")

    print("\nTop 10 CAs globally:")
    for i, (ca, count) in enumerate(
        list(stats["global"]["by_ca"].items())[:10], start=1
    ):
        pct = count / max(stats["total"], 1) * 100
        print(f"  {i:2d}. {ca:40s} {count:4d}  ({pct:.1f}%)")

    print("\nPer-country breakdown:")
    for country, cstats in stats["by_country"].items():
        total = cstats["total"]
        us_pct = cstats.get("us_pct", 0)
        no_domain = cstats.get("no_domain", 0)
        print(
            f"\n  {country}: {total} municipalities "
            f"({no_domain} without domain, {us_pct:.0f}% US-controlled)"
        )
        for jurisdiction, count in cstats["by_jurisdiction"].items():
            pct = count / max(total - no_domain, 1) * 100
            print(f"    {jurisdiction:12s} {count:4d}  ({pct:.1f}%)")

    print("\n" + "=" * 60)
