"""Browserless URL extraction with explicit HTML and host boundaries."""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup

from ...urls import host_allowed

_URL_PATTERNS = (
    re.compile(r"""["']((?:https?:)?//[^"'<>\s]{1,2048})["']""", re.IGNORECASE),
    re.compile(r"""["']((?:\.\.?/|/)[^"'<>\s]{1,2048})["']"""),
)
_TRAILING = "\\,;:)]}"
_NON_ENDPOINT_SUFFIXES = (
    ".avif", ".bmp", ".css", ".gif", ".ico", ".jpeg", ".jpg", ".map", ".png",
    ".svg", ".ttf", ".webp", ".woff", ".woff2",
)


def base_href(html_text: str, page_url: str) -> str:
    if "<" not in (html_text or ""):
        return page_url
    soup = BeautifulSoup(html_text or "", "html.parser")
    tag = soup.find("base", href=True)
    if tag is None:
        return page_url
    candidate = urljoin(page_url, str(tag.get("href", "")).strip())
    if urlsplit(candidate).scheme not in ("http", "https"):
        return page_url
    return candidate


def normalise_extracted_url(raw: str, source_url: str, document_base: str) -> str | None:
    value = str(raw or "").strip().rstrip(_TRAILING)
    if not value or value.startswith(("data:", "javascript:", "mailto:", "tel:")):
        return None
    absolute = urljoin(document_base or source_url, value)
    parts = urlsplit(absolute)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return None
    clean = urlunsplit((parts.scheme.lower(), parts.netloc, parts.path or "/", parts.query, ""))
    if clean.lower().endswith(_NON_ENDPOINT_SUFFIXES):
        return None
    return clean


def extract_script_urls(html_text: str, page_url: str, target_url: str) -> list[str]:
    if "<" not in (html_text or ""):
        return []
    soup = BeautifulSoup(html_text or "", "html.parser")
    document_base = base_href(html_text, page_url)
    result: list[str] = []
    seen: set[str] = set()
    for tag in soup.find_all("script", src=True):
        candidate = normalise_extracted_url(str(tag.get("src", "")), page_url, document_base)
        if candidate and host_allowed(target_url, candidate) and candidate not in seen:
            seen.add(candidate)
            result.append(candidate)
    return result


def extract_urls(text: str, source_url: str, target_url: str, document_base: str | None = None) -> set[str]:
    base = document_base or source_url
    found: set[str] = set()
    for pattern in _URL_PATTERNS:
        for match in pattern.finditer(text or ""):
            candidate = normalise_extracted_url(match.group(1), source_url, base)
            if candidate and host_allowed(target_url, candidate):
                found.add(candidate)
    return found


__all__ = [
    "base_href",
    "extract_script_urls",
    "extract_urls",
    "normalise_extracted_url",
]
