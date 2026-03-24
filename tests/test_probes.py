"""Tests for DNS-based probes (CAA, CT logs)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cert_sovereignty.models import SignalKind
from cert_sovereignty.probes import probe_caa, probe_ct_log


@pytest.mark.asyncio
async def test_probe_caa_no_records() -> None:
    with patch("cert_sovereignty.probes.resolve_robust", new_callable=AsyncMock) as mock_resolve:
        mock_resolve.return_value = None
        results = await probe_caa("example.fi")
    assert results == []


@pytest.mark.asyncio
async def test_probe_caa_letsencrypt() -> None:
    mock_rdata = MagicMock()
    mock_rdata.flags = 0
    mock_rdata.tag = "issue"
    mock_rdata.value = "letsencrypt.org"

    mock_answer = MagicMock()
    mock_answer.__iter__ = MagicMock(return_value=iter([mock_rdata]))

    with patch("cert_sovereignty.probes.resolve_robust", new_callable=AsyncMock) as mock_resolve:
        mock_resolve.return_value = mock_answer
        results = await probe_caa("example.fi")

    assert len(results) >= 1
    ca_names = [ev.ca_name for ev in results]
    assert "Let's Encrypt (ISRG)" in ca_names
    assert all(ev.kind == SignalKind.CAA_RECORD for ev in results)


@pytest.mark.asyncio
async def test_probe_caa_issuewild() -> None:
    mock_rdata = MagicMock()
    mock_rdata.flags = 0
    mock_rdata.tag = "issuewild"
    mock_rdata.value = "digicert.com"

    mock_answer = MagicMock()
    mock_answer.__iter__ = MagicMock(return_value=iter([mock_rdata]))

    with patch("cert_sovereignty.probes.resolve_robust", new_callable=AsyncMock) as mock_resolve:
        mock_resolve.return_value = mock_answer
        results = await probe_caa("example.fi")

    assert len(results) >= 1
    ca_names = [ev.ca_name for ev in results]
    assert "DigiCert" in ca_names


@pytest.mark.asyncio
async def test_probe_ct_log_error_graceful() -> None:
    """CT log query errors should be handled gracefully (return empty list)."""
    with patch("cert_sovereignty.probes._fetch_crtsh", side_effect=Exception("network error")):
        results = await probe_ct_log("example.fi")
    assert results == []
