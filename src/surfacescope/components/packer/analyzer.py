"""Passive webpack/chunk and API endpoint analysis."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup

from ...urls import canonical_url, host_allowed
from ..jsfinder.extract import base_href

PACKER_MARKERS = (
    "__NEXT_DATA__",
    "__webpack_require__",
    "docusaurus",
    "gatsby",
    "phoenix",
    "vite",
    "webpack",
    "webpackJsonp",
)
STATIC_EXTENSIONS = (
    ".avif", ".css", ".gif", ".ico", ".jpeg", ".jpg", ".map", ".png", ".svg", ".ttf", ".webp", ".woff", ".woff2",
)
STATIC_ENDPOINT_EXTENSIONS = STATIC_EXTENSIONS + (".js", ".mjs")
_SCRIPT_PATH = re.compile(r"""["']([^"'<>\\]{1,2048}?\.(?:m?js)(?:\?[^"'<>\\]{0,512})?)["']""", re.IGNORECASE)
_SOURCE_MAP = re.compile(r"""sourceMappingURL\s*=\s*([^\s*]+)""", re.IGNORECASE)
_API_CALL = re.compile(
    r"""(?:fetch|axios\s*\.\s*(?P<method>get|post|put|patch|delete)|axios|\.\s*(?P<method2>get|post|put|patch|delete))\s*\(?\s*["']([^"'<>\\]{1,2048})["']""",
    re.IGNORECASE,
)
_PATH_LITERAL = re.compile(r"""["']((?:https?://|/)[^"'<>\\]{1,2048})["']""")
_METHOD_HINT = re.compile(r"""method\s*[:=]\s*["'](get|post|put|patch|delete)["']""", re.IGNORECASE)
_PLACEHOLDER = re.compile(r"[{}<>]|(?:^|/)\.\.?(?:/|$)")
_METHOD_CONTEXT = 160


@dataclass(frozen=True, slots=True)
class Endpoint:
    url: str
    method: str = "GET"
    source_asset: str = ""
    technique: str = "static-js-extraction"
    method_source: str = "explicit"

    @property
    def key(self) -> tuple[str, str]:
        return (self.method.upper(), canonical_url(self.url))


@dataclass(slots=True)
class PackerDocument:
    page_url: str
    markers: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)


def analyse_document(html_text: str, page_url: str, target_url: str) -> PackerDocument:
    lower = (html_text or "").lower()
    document = PackerDocument(
        page_url=page_url,
        markers=[marker for marker in PACKER_MARKERS if marker.lower() in lower],
        scripts=extract_scripts(html_text, page_url, target_url),
        endpoints=extract_endpoints(html_text, page_url, target_url),
    )
    return document


def extract_scripts(html_text: str, page_url: str, target_url: str) -> list[str]:
    document_base = base_href(html_text, page_url) if "<base" in (html_text or "").lower() else page_url
    soup = BeautifulSoup(html_text or "", "html.parser") if "<script" in (html_text or "").lower() else None
    result: list[str] = []
    if soup is not None:
        for tag in soup.find_all("script", src=True):
            candidate = _normalise(str(tag.get("src", "")), page_url, document_base, target_url, allow_static=True)
            if candidate:
                result.append(candidate)
    for match in _SCRIPT_PATH.finditer(html_text or ""):
        candidate = _normalise(match.group(1), page_url, document_base, target_url, allow_static=True)
        if candidate:
            result.append(candidate)
    return _dedupe(result)


def extract_endpoints(text: str, source_url: str, target_url: str) -> list[Endpoint]:
    document_base = source_url
    result: list[Endpoint] = []
    default_method = "GET"
    for match in _API_CALL.finditer(text or ""):
        method = (match.group("method") or match.group("method2") or default_method).upper()
        candidate = _normalise(match.group(3), source_url, document_base, target_url)
        if candidate:
            result.append(Endpoint(candidate, method, source_url, method_source="explicit"))
    for match in _PATH_LITERAL.finditer(text or ""):
        if any(endpoint.url == _normalise(match.group(1), source_url, document_base, target_url) for endpoint in result):
            continue
        candidate = _normalise(match.group(1), source_url, document_base, target_url)
        if candidate:
            nearby = _METHOD_HINT.search(
                (text or "")[max(0, match.start() - _METHOD_CONTEXT) : match.start() + _METHOD_CONTEXT]
            )
            method = nearby.group(1).upper() if nearby else default_method
            result.append(
                Endpoint(
                    candidate,
                    method,
                    source_url,
                    method_source="context" if nearby else "inferred",
                )
            )
    return _dedupe_endpoints(result)


def source_map_urls(text: str, source_url: str, target_url: str) -> list[str]:
    result: list[str] = []
    for match in _SOURCE_MAP.finditer(text or ""):
        candidate = _normalise(match.group(1), source_url, source_url, target_url, allow_static=True)
        if candidate:
            result.append(candidate)
    return _dedupe(result)


def _normalise(
    raw: str,
    source_url: str,
    document_base: str,
    target_url: str,
    *,
    allow_static: bool = False,
) -> str | None:
    value = str(raw or "").replace("\\/", "/").strip().rstrip("\\,;:)]}")
    if not value or value.startswith(("data:", "javascript:", "mailto:", "#")):
        return None
    if not allow_static and value.lower().endswith(STATIC_ENDPOINT_EXTENSIONS):
        return None
    if _PLACEHOLDER.search(value):
        return None
    try:
        absolute = urljoin(document_base or source_url, value)
    except ValueError:
        return None
    parts = urlsplit(absolute)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return None
    if not host_allowed(target_url, absolute):
        return None
    return urlunsplit((parts.scheme.lower(), parts.netloc, parts.path or "/", parts.query, ""))


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _dedupe_endpoints(values: list[Endpoint]) -> list[Endpoint]:
    seen: set[tuple[str, str]] = set()
    indexes: dict[tuple[str, str], int] = {}
    result: list[Endpoint] = []
    rank = {"explicit": 3, "context": 2, "inferred": 1}
    for value in values:
        if value.key not in seen:
            seen.add(value.key)
            indexes[value.key] = len(result)
            result.append(value)
            continue
        index = indexes[value.key]
        if rank.get(value.method_source, 0) > rank.get(result[index].method_source, 0):
            result[index] = value
    return result


__all__ = [
    "Endpoint",
    "PACKER_MARKERS",
    "PackerDocument",
    "analyse_document",
    "extract_endpoints",
    "extract_scripts",
    "source_map_urls",
]
