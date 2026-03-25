"""Tests for data.json schema validation."""

from __future__ import annotations

from cert_sovereignty.analyze import compute_stats


def test_compute_stats_basic(sample_data_json) -> None:
    stats = compute_stats(sample_data_json)
    assert stats["total"] == 2
    assert "by_jurisdiction" in stats["global"]
    assert "by_ca" in stats["global"]
    assert "by_country" in stats


def test_compute_stats_jurisdictions(sample_data_json) -> None:
    stats = compute_stats(sample_data_json)
    jurisdictions = stats["global"]["by_jurisdiction"]
    assert "us" in jurisdictions
    assert "nordic" in jurisdictions
    assert jurisdictions["us"] == 1
    assert jurisdictions["nordic"] == 1


def test_compute_stats_by_country(sample_data_json) -> None:
    stats = compute_stats(sample_data_json)
    assert "FI" in stats["by_country"]
    assert "NO" in stats["by_country"]
    fi = stats["by_country"]["FI"]
    assert fi["total"] == 1
    assert fi["by_jurisdiction"]["us"] == 1


def test_compute_stats_empty() -> None:
    empty_data = {"municipalities": {}}
    stats = compute_stats(empty_data)
    assert stats["total"] == 0
    assert stats["global"]["by_jurisdiction"] == {}


def test_compute_stats_no_domain() -> None:
    data = {
        "municipalities": {
            "FI-001": {
                "id": "FI-001",
                "name": "TestKunta",
                "country": "FI",
                "domain": "",
                "error": "no_domain",
            }
        }
    }
    stats = compute_stats(data)
    assert stats["by_country"]["FI"]["no_domain"] == 1


def test_data_json_required_fields(sample_data_json) -> None:
    """Validate required top-level fields in data.json."""
    required = ["generated", "total", "counts", "municipalities"]
    for field in required:
        assert field in sample_data_json, f"Missing required field: {field}"


def test_municipality_required_fields(sample_data_json) -> None:
    """Validate required fields in each municipality record."""
    required = ["id", "name", "country", "primary_ca", "jurisdiction", "category"]
    for muni_id, muni in sample_data_json["municipalities"].items():
        for field in required:
            assert field in muni, f"Municipality {muni_id} missing field: {field}"
