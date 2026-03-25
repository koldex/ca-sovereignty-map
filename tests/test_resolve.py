"""Tests for municipality domain resolution."""

from __future__ import annotations

from cert_sovereignty.resolve import _extract_domain, _slugify_name, guess_domains


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
