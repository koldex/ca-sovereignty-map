"""Tests for pipeline orchestration and serialization."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from cert_sovereignty.models import ClassificationResult, Jurisdiction, RiskLevel
from cert_sovereignty.pipeline import build_data_json, serialize_result, write_output


def make_result(domain: str, jurisdiction: Jurisdiction, ca: str) -> ClassificationResult:
    return ClassificationResult(
        domain=domain,
        primary_ca=ca,
        jurisdiction=jurisdiction,
        risk_level=RiskLevel.HIGH if jurisdiction == Jurisdiction.US else RiskLevel.MINIMAL,
        confidence=0.90,
    )


def test_serialize_result_fields() -> None:
    result = make_result("espoo.fi", Jurisdiction.US, "Let's Encrypt (ISRG)")
    meta = {"id": "FI-049", "name": "Espoo", "country": "FI", "region": "Uusimaa"}
    serialized = serialize_result(result, meta)

    assert serialized["id"] == "FI-049"
    assert serialized["name"] == "Espoo"
    assert serialized["domain"] == "espoo.fi"
    assert serialized["jurisdiction"] == "us"
    assert serialized["category"] == "us-controlled"
    assert serialized["classification_confidence"] == 90.0


def test_serialize_result_nordic() -> None:
    result = make_result("oslo.kommune.no", Jurisdiction.NORDIC, "Buypass")
    meta = {"id": "NO-0301", "name": "Oslo", "country": "NO", "region": ""}
    serialized = serialize_result(result, meta)

    assert serialized["category"] == "nordic"
    assert serialized["jurisdiction"] == "nordic"


def test_build_data_json_structure() -> None:
    municipalities = [
        {"id": "FI-049", "name": "Espoo", "country": "FI", "domain": "espoo.fi"},
        {"id": "NO-0301", "name": "Oslo", "country": "NO", "domain": "oslo.kommune.no"},
    ]
    results = {
        "espoo.fi": make_result("espoo.fi", Jurisdiction.US, "Let's Encrypt (ISRG)"),
        "oslo.kommune.no": make_result("oslo.kommune.no", Jurisdiction.NORDIC, "Buypass"),
    }
    data = build_data_json(municipalities, results, commit="abc123")

    assert data["commit"] == "abc123"
    assert data["total"] == 2
    assert "FI-049" in data["municipalities"]
    assert "NO-0301" in data["municipalities"]
    assert data["counts"]["us-controlled"] == 1
    assert data["counts"]["nordic"] == 1


def test_write_output() -> None:
    data = {"generated": "2026-03-24T04:00:00Z", "total": 0, "municipalities": {}}

    with tempfile.TemporaryDirectory() as tmpdir:
        write_output(data, Path(tmpdir))
        full = Path(tmpdir) / "data.json"
        mini = Path(tmpdir) / "data.min.json"

        assert full.exists()
        assert mini.exists()

        # Validate JSON
        with open(full) as f:
            loaded = json.load(f)
        assert loaded["total"] == 0

        # Min version should be smaller
        assert mini.stat().st_size < full.stat().st_size
