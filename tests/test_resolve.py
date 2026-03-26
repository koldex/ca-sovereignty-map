"""Tests for municipality domain resolution."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

from cert_sovereignty.resolve import (
    _cname_exits_no,
    _extract_domain,
    _is_no_bare_domain,
    _slugify_name,
    _tls_reachable,
    guess_domains,
    validate_domain,
)


def test_slugify_finnish_name() -> None:
    slugs = _slugify_name("Hämeenlinna")
    assert "hameenlinna" in slugs


def test_slugify_swedish_name() -> None:
    slugs = _slugify_name("Göteborg")
    assert "goteborg" in slugs


def test_slugify_norwegian_name() -> None:
    slugs = _slugify_name("Tromsø")
    assert "tromso" in slugs


def test_slugify_danish_name() -> None:
    slugs = _slugify_name("Aabenraa")
    # No special chars, should be unchanged
    assert "aabenraa" in slugs


def test_slugify_with_ae() -> None:
    slugs = _slugify_name("Æbeltoft")
    assert "aebeltoft" in slugs


def test_extract_domain_basic() -> None:
    assert _extract_domain("https://www.espoo.fi") == "espoo.fi"
    assert _extract_domain("http://www.stockholm.se/") == "stockholm.se"
    assert _extract_domain("https://oslo.kommune.no/om-oslo") == "oslo.kommune.no"


def test_extract_domain_no_www() -> None:
    assert _extract_domain("https://espoo.fi") == "espoo.fi"


def test_guess_domains_finland() -> None:
    domains = guess_domains("Espoo", "FI")
    assert "espoo.fi" in domains


def test_guess_domains_norway() -> None:
    domains = guess_domains("Oslo", "NO")
    assert "oslo.kommune.no" in domains
    assert "oslo.no" in domains


def test_guess_domains_sweden() -> None:
    domains = guess_domains("Stockholm", "SE")
    assert "stockholm.se" in domains
    assert "stockholm.kommun.se" in domains


def test_guess_domains_no_empty_slugs() -> None:
    # Edge case: very short name
    domains = guess_domains("As", "NO")
    assert all(d for d in domains)  # no empty strings


def test_guess_domains_nordic_special_chars() -> None:
    # Hämeenlinna → hameenlinna.fi
    domains = guess_domains("Hämeenlinna", "FI")
    assert any("hameenlinna" in d for d in domains)


# ── _is_no_bare_domain ────────────────────────────────────────────────────────


def test_is_no_bare_domain_rejects_kommune() -> None:
    assert _is_no_bare_domain("amot.kommune.no") is False
    assert _is_no_bare_domain("www.amot.kommune.no") is False


def test_is_no_bare_domain_rejects_herad() -> None:
    assert _is_no_bare_domain("ulvik.herad.no") is False


def test_is_no_bare_domain_accepts_bare() -> None:
    assert _is_no_bare_domain("amot.no") is True
    assert _is_no_bare_domain("www.amot.no") is True
    assert _is_no_bare_domain("laerdal.no") is True
    assert _is_no_bare_domain("www.nord-fron.no") is True


def test_is_no_bare_domain_rejects_non_no() -> None:
    assert _is_no_bare_domain("espoo.fi") is False
    assert _is_no_bare_domain("stockholm.se") is False
    assert _is_no_bare_domain("laerdal.com") is False


# ── _cname_exits_no ────────────────────────────────────────────────────


async def test_cname_exits_no_no_cname_record() -> None:
    """No CNAME record — resolve_robust returns None → does not exit."""
    with patch("cert_sovereignty.resolve.resolve_robust", new_callable=AsyncMock, return_value=None):
        assert await _cname_exits_no("laerdal.no") is False


async def test_cname_exits_no_stays_within_no() -> None:
    """CNAME target is still within .no → does not exit."""
    rdata = MagicMock()
    rdata.target = "www.laerdal.no."
    with patch("cert_sovereignty.resolve.resolve_robust", new_callable=AsyncMock, return_value=[rdata]):
        assert await _cname_exits_no("laerdal.no") is False


async def test_cname_exits_no_exits_to_com() -> None:
    """CNAME to .com → exits .no TLD."""
    rdata = MagicMock()
    rdata.target = "laerdal.com."
    with patch("cert_sovereignty.resolve.resolve_robust", new_callable=AsyncMock, return_value=[rdata]):
        assert await _cname_exits_no("laerdal.no") is True


# ── _tls_reachable ───────────────────────────────────────────────────────


async def test_tls_reachable_ssl_error() -> None:
    """SSL error during handshake → False."""
    import ssl
    with patch("asyncio.open_connection", new_callable=AsyncMock,
               side_effect=ssl.SSLError("TLSV1_UNRECOGNIZED_NAME")):
        assert await _tls_reachable("www.nord-fron.no") is False


async def test_tls_reachable_connection_refused() -> None:
    """Connection refused → False."""
    with patch("asyncio.open_connection", new_callable=AsyncMock,
               side_effect=ConnectionRefusedError()):
        assert await _tls_reachable("www.rindal.no") is False


async def test_tls_reachable_timeout() -> None:
    """Timeout → False."""
    with patch("asyncio.open_connection", new_callable=AsyncMock,
               side_effect=TimeoutError()):
        assert await _tls_reachable("www.amot.no") is False


async def test_tls_reachable_success() -> None:
    """Successful TLS handshake → True."""
    mock_writer = MagicMock()
    mock_writer.close = MagicMock()
    mock_writer.wait_closed = AsyncMock(return_value=None)
    with patch("asyncio.open_connection",
               new_callable=AsyncMock, return_value=(MagicMock(), mock_writer)):
        assert await _tls_reachable("vinje.kommune.no") is True


# ── validate_domain ───────────────────────────────────────────────────────


async def test_validate_domain_rejects_skip_domain() -> None:
    """laerdal.no is in SKIP_DOMAINS → False without any network call."""
    assert await validate_domain("laerdal.no") is False


async def test_validate_domain_rejects_empty() -> None:
    assert await validate_domain("") is False


async def test_validate_domain_rejects_no_dns() -> None:
    with patch("cert_sovereignty.resolve.domain_resolves",
               new_callable=AsyncMock, return_value=False):
        assert await validate_domain("nonexistent.fi") is False


async def test_validate_domain_rejects_cname_exit() -> None:
    """Bare .no with CNAME exiting .no → False."""
    with patch("cert_sovereignty.resolve.domain_resolves",
               new_callable=AsyncMock, return_value=True), \
         patch("cert_sovereignty.resolve._cname_exits_no",
               new_callable=AsyncMock, return_value=True):
        assert await validate_domain("laerdal2.no") is False


async def test_validate_domain_rejects_tls_failure() -> None:
    """Bare .no with TLS failure → False."""
    with patch("cert_sovereignty.resolve.domain_resolves",
               new_callable=AsyncMock, return_value=True), \
         patch("cert_sovereignty.resolve._cname_exits_no",
               new_callable=AsyncMock, return_value=False), \
         patch("cert_sovereignty.resolve._tls_reachable",
               new_callable=AsyncMock, return_value=False):
        assert await validate_domain("www.amot.no") is False


async def test_validate_domain_accepts_bare_no_with_good_tls() -> None:
    """Bare .no with no CNAME exit and working TLS → True."""
    with patch("cert_sovereignty.resolve.domain_resolves",
               new_callable=AsyncMock, return_value=True), \
         patch("cert_sovereignty.resolve._cname_exits_no",
               new_callable=AsyncMock, return_value=False), \
         patch("cert_sovereignty.resolve._tls_reachable",
               new_callable=AsyncMock, return_value=True):
        assert await validate_domain("www.stavanger.no") is True


async def test_validate_domain_skips_extra_checks_for_kommune() -> None:
    """*.kommune.no skips CNAME and TLS checks entirely."""
    with patch("cert_sovereignty.resolve.domain_resolves",
               new_callable=AsyncMock, return_value=True), \
         patch("cert_sovereignty.resolve._cname_exits_no",
               new_callable=AsyncMock) as mock_cname, \
         patch("cert_sovereignty.resolve._tls_reachable",
               new_callable=AsyncMock) as mock_tls:
        result = await validate_domain("amot.kommune.no")
    assert result is True
    mock_cname.assert_not_called()
    mock_tls.assert_not_called()
