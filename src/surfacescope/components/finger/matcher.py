"""Efficient matching for Finger-compatible rules.

The upstream rule set contains thousands of rules and more than ten thousand
keywords. Linear full-body scans per rule are too expensive, so keyword rules
are indexed with a small pure-Python Aho-Corasick automaton and evaluated once
per location.
"""

from __future__ import annotations

import base64
import hashlib
import html
import re
from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

_TITLE_RE = re.compile(r"<title\b[^>]*>(.*?)</title\s*>", re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")
_ICON_RE = re.compile(r"<link\b(?P<attrs>[^>]*)>", re.IGNORECASE | re.DOTALL)
_ATTR_RE = re.compile(r"(?P<name>[A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*(?P<value>['\"])(?P<content>.*?)(?P=value)", re.DOTALL)
_TOKEN_KEYWORD_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")

# These strings occur on many unrelated applications. They remain useful as
# supporting evidence, but must not make an ``or`` rule match by themselves.
# Keeping the filter here preserves the upstream rule asset byte-for-byte.
_LOW_SIGNAL_BODY_KEYWORDS = frozenset(
    {
        "cache/",
        "index.php",
        "login.php",
        "admin.php",
        "config.php",
        "robots.txt",
        "favicon.ico",
    }
)
_LOW_SIGNAL_HEADER_KEYWORDS = frozenset(
    {
        "php",
        "x-powered-by: php",
        "asp.net",
        "server",
    }
)
_LOW_SIGNAL_URL_SEGMENTS = frozenset(
    {
        "admin",
        "api",
        "app",
        "assets",
        "dashboard",
        "docs",
        "endpoints",
        "health",
        "healthz",
        "home",
        "index",
        "info",
        "login",
        "logout",
        "main",
        "overview",
        "public",
        "rest",
        "root",
        "static",
        "status",
        "swagger",
        "ui",
        "version",
        "web",
    }
)
_URL_VERSION_SEGMENT_RE = re.compile(r"^v\d+$")


def parse_title(text: str) -> str:
    match = _TITLE_RE.search(text or "")
    if not match:
        return ""
    title = _TAG_RE.sub(" ", match.group(1))
    return " ".join(html.unescape(title).split())


def murmur3_32(data: bytes, seed: int = 0) -> int:
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    rounded = length & ~3
    for offset in range(0, rounded, 4):
        k1 = int.from_bytes(data[offset : offset + 4], "little")
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF
    tail = data[rounded:]
    if len(tail) >= 3:
        h1 ^= tail[2] << 16
    if len(tail) >= 2:
        h1 ^= tail[1] << 8
    if len(tail) >= 1:
        h1 ^= tail[0]
        h1 = (h1 * c1) & 0xFFFFFFFF
        h1 = ((h1 << 15) | (h1 >> 17)) & 0xFFFFFFFF
        h1 = (h1 * c2) & 0xFFFFFFFF
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def favicon_hashes(data: bytes) -> dict[str, str]:
    return {
        "ehole": str(murmur3_32(base64.encodebytes(data))),
        "fofa": str(murmur3_32(base64.b64encode(data))),
        "md5": hashlib.md5(data).hexdigest(),
    }


def favicon_href(text: str) -> str:
    for match in _ICON_RE.finditer(text or ""):
        attrs = {
            item.group("name").lower(): html.unescape(item.group("content")).strip()
            for item in _ATTR_RE.finditer(match.group("attrs"))
        }
        rel = attrs.get("rel", "").lower().split()
        if any(value in {"icon", "shortcut", "apple-touch-icon", "mask-icon"} for value in rel) and attrs.get("href"):
            return attrs["href"]
    return ""


def _header_keyword_present(keyword: str, text: str) -> bool:
    """Require token boundaries for bare alphanumeric header keywords.

    A raw substring match makes rules such as ``eHTTP`` fire on
    ``Server: SimpleHTTP/0.6``. Structured header keywords containing spaces
    or colons keep their historical substring semantics.
    """

    lowered = keyword.lower()
    if not _TOKEN_KEYWORD_RE.fullmatch(keyword):
        return lowered in text
    start = 0
    while True:
        index = text.find(lowered, start)
        if index < 0:
            return False
        before = text[index - 1] if index else ""
        after_index = index + len(lowered)
        after = text[after_index] if after_index < len(text) else ""
        if (not before or not before.isalnum()) and (not after or not after.isalnum()):
            return True
        start = index + 1


def _url_keyword_present(keyword: str, text: str) -> bool:
    """Match path rules on segment boundaries instead of arbitrary substrings."""

    lowered = keyword.lower()
    if not lowered.startswith("/"):
        return lowered in text
    before_boundaries = {"", "\n", "/", "?", "&", "=", ";"}
    after_boundaries = {"", "\n", "/", "?", "#", "&", "=", ";"}
    start = 0
    while True:
        index = text.find(lowered, start)
        if index < 0:
            return False
        before = text[index - 1] if index else ""
        after_index = index + len(lowered)
        after = text[after_index] if after_index < len(text) else ""
        if before in before_boundaries and after in after_boundaries:
            return True
        start = index + 1


def _url_keyword_specific(keyword: str) -> bool:
    """Reject URL-only rules made entirely from generic path vocabulary."""

    path = keyword.split("?", 1)[0].split("#", 1)[0]
    segments = [segment.lower() for segment in path.split("/") if segment]
    if not segments:
        return False
    return any(
        segment not in _LOW_SIGNAL_URL_SEGMENTS
        and not _URL_VERSION_SEGMENT_RE.fullmatch(segment)
        for segment in segments
    )


class _AhoCorasick:
    def __init__(self, patterns: Iterable[tuple[str, int]]) -> None:
        self._next: list[dict[str, int]] = [{}]
        self._fail: list[int] = [0]
        self._outputs: list[list[int]] = [[]]
        for pattern, pattern_id in patterns:
            if not pattern:
                continue
            node = 0
            for character in pattern:
                child = self._next[node].get(character)
                if child is None:
                    child = len(self._next)
                    self._next[node][character] = child
                    self._next.append({})
                    self._fail.append(0)
                    self._outputs.append([])
                node = child
            self._outputs[node].append(pattern_id)
        queue: deque[int] = deque()
        for child in self._next[0].values():
            queue.append(child)
        while queue:
            node = queue.popleft()
            for character, child in self._next[node].items():
                queue.append(child)
                state = self._fail[node]
                while state and character not in self._next[state]:
                    state = self._fail[state]
                self._fail[child] = self._next[state].get(character, 0)
                self._outputs[child].extend(self._outputs[self._fail[child]])

    def search(self, text: str) -> set[int]:
        state = 0
        found: set[int] = set()
        for character in text:
            while state and character not in self._next[state]:
                state = self._fail[state]
            state = self._next[state].get(character, 0)
            if self._outputs[state]:
                found.update(self._outputs[state])
        return found


@dataclass(frozen=True, slots=True)
class RuleMatch:
    cms: str
    method: str
    location: str
    confidence: float
    evidence: tuple[str, ...]
    version: str = ""
    model: str = ""
    rule_index: int = 0


@dataclass(frozen=True, slots=True)
class _CompiledRule:
    index: int
    cms: str
    method: str
    location: str
    keywords: tuple[str, ...]
    logic: str
    version_re: re.Pattern[str] | None
    model_re: re.Pattern[str] | None
    expected_server: tuple[str, ...]


class FingerMatcher:
    def __init__(self, rules: list[dict[str, Any]]) -> None:
        self.rules: list[_CompiledRule] = []
        keyword_patterns: dict[str, list[tuple[int, str]]] = defaultdict(list)
        self._keyword_indexes: dict[str, _AhoCorasick] = {}
        self._keyword_map: dict[str, dict[int, tuple[int, str]]] = {}
        for raw in rules:
            if not isinstance(raw, dict):
                continue
            cms = str(raw.get("cms", "unknown")).strip()
            method = str(raw.get("method", "keyword")).strip().lower()
            location = str(raw.get("location", "body")).strip().lower()
            if method not in {"keyword", "regula", "faviconhash"}:
                continue
            if location not in {"title", "header", "body", "url"}:
                location = "body"
            raw_keywords = raw.get("keyword", [])
            if not isinstance(raw_keywords, list):
                raw_keywords = [raw_keywords]
            keywords = tuple(str(value) for value in raw_keywords if str(value))
            try:
                version_re = re.compile(str(raw.get("version_regex")), re.IGNORECASE) if raw.get("version_regex") else None
            except re.error:
                version_re = None
            try:
                model_re = re.compile(str(raw.get("model_regex")), re.IGNORECASE) if raw.get("model_regex") else None
            except re.error:
                model_re = None
            expected_server = tuple(str(value).lower() for value in raw.get("expected_server", []) if str(value))
            compiled = _CompiledRule(
                index=len(self.rules),
                cms=cms,
                method=method,
                location=location,
                keywords=keywords,
                logic=str(raw.get("logic", "and")).lower(),
                version_re=version_re,
                model_re=model_re,
                expected_server=expected_server,
            )
            self.rules.append(compiled)
            if method == "keyword":
                for keyword in keywords:
                    lowered = keyword.lower()
                    if lowered:
                        keyword_patterns[location].append((lowered, len(keyword_patterns[location])))
                        self._keyword_map.setdefault(location, {})[len(keyword_patterns[location]) - 1] = (
                            compiled.index,
                            keyword,
                        )
        for location, patterns in keyword_patterns.items():
            self._keyword_indexes[location] = _AhoCorasick(patterns)

    @property
    def rule_count(self) -> int:
        return len(self.rules)

    def match(
        self,
        *,
        url: str,
        text: str,
        headers: dict[str, str],
        favicon_hash_values: set[str] | None = None,
    ) -> list[RuleMatch]:
        title = parse_title(text)
        parsed = urlsplit(url)
        path = parsed.path or "/"
        path_query = path + (("?" + parsed.query) if parsed.query else "")
        url_value = "\n".join((path_query, path, path.rstrip("/"), path.rstrip("/") + "/"))
        header_value = "\n".join(
            [str(dict(headers))]
            + [f"{key}: {value}\n{key.lower()}: {value}\n({key}: {value}" for key, value in headers.items()]
        )
        location_text = {
            "title": title.lower(),
            "header": header_value.lower(),
            "body": (text or "").lower(),
            "url": url_value.lower(),
        }
        matched_keywords: dict[int, set[str]] = defaultdict(set)
        for location, automaton in self._keyword_indexes.items():
            pattern_ids = automaton.search(location_text[location])
            mapping = self._keyword_map[location]
            for pattern_id in pattern_ids:
                rule_index, keyword = mapping[pattern_id]
                if location == "header" and not _header_keyword_present(keyword, location_text[location]):
                    continue
                if location == "url" and not _url_keyword_present(keyword, location_text[location]):
                    continue
                matched_keywords[rule_index].add(keyword)

        favicon_values = {str(value) for value in (favicon_hash_values or set())}
        results: list[RuleMatch] = []
        for rule in self.rules:
            evidence: tuple[str, ...] = ()
            matched = False
            if rule.method == "faviconhash":
                hits = [keyword for keyword in rule.keywords if keyword in favicon_values]
                matched = bool(hits)
                evidence = tuple(hits[:4])
            elif rule.method == "keyword":
                hits = matched_keywords.get(rule.index, set())
                if rule.logic == "or":
                    # Low-signal strings are supporting evidence only. They
                    # may never make an OR rule match by themselves.
                    effective_hits = hits
                    if rule.location == "body":
                        effective_hits = {
                            hit for hit in hits if hit.lower() not in _LOW_SIGNAL_BODY_KEYWORDS
                        }
                    elif rule.location == "header":
                        effective_hits = {
                            hit for hit in hits if hit.lower() not in _LOW_SIGNAL_HEADER_KEYWORDS
                        }
                    elif rule.location == "url":
                        effective_hits = {hit for hit in hits if _url_keyword_specific(hit)}
                    matched = bool(effective_hits)
                    evidence = tuple(sorted(effective_hits)[:6])
                else:
                    # AND rules need every declared keyword, including a
                    # low-signal term, otherwise filtering would loosen the
                    # rule and create false positives.
                    matched = bool(rule.keywords) and all(
                        keyword in hits for keyword in rule.keywords
                    )
                    if matched and rule.location == "header":
                        matched = any(
                            keyword.lower() not in _LOW_SIGNAL_HEADER_KEYWORDS
                            for keyword in rule.keywords
                        )
                    if matched and rule.location == "url":
                        matched = any(_url_keyword_specific(keyword) for keyword in rule.keywords)
                    evidence = rule.keywords if matched else ()
            elif rule.method == "regula":
                value = location_text[rule.location]
                hits = []
                for pattern in rule.keywords:
                    try:
                        if re.search(pattern, value, re.IGNORECASE):
                            hits.append(pattern)
                    except re.error:
                        continue
                matched = (
                    bool(hits)
                    if rule.logic == "or"
                    else bool(rule.keywords) and len(hits) == len(rule.keywords)
                )
                evidence = tuple(hits[:6])
            if not matched:
                continue
            value = location_text[rule.location]
            version = ""
            model = ""
            if rule.version_re:
                version_match = rule.version_re.search(value)
                version = version_match.group(1) if version_match and version_match.groups() else ""
            if rule.model_re:
                model_match = rule.model_re.search(value)
                model = model_match.group(0) if model_match else ""
            confidence = self._confidence(rule, len(evidence), bool(version or model), headers)
            results.append(
                RuleMatch(
                    cms=rule.cms,
                    method=rule.method,
                    location=rule.location,
                    confidence=confidence,
                    evidence=evidence,
                    version=version,
                    model=model,
                    rule_index=rule.index,
                )
            )
        return results

    @staticmethod
    def _confidence(rule: _CompiledRule, evidence_count: int, has_version: bool, headers: dict[str, str]) -> float:
        if rule.method == "faviconhash":
            confidence = 0.95
        elif rule.location == "title":
            confidence = 0.82 + min(0.1, evidence_count * 0.03)
        elif rule.location == "header":
            confidence = 0.78
        elif rule.location == "url":
            confidence = 0.76
        else:
            confidence = 0.52 + min(0.12, evidence_count * 0.02)
        if has_version:
            confidence += 0.03
        if rule.expected_server:
            server = ""
            for key, value in headers.items():
                if key.lower() == "server":
                    server = str(value).lower()
                    break
            if not any(expected in server for expected in rule.expected_server):
                confidence *= 0.72
        return max(0.05, min(0.99, confidence))


__all__ = [
    "FingerMatcher",
    "RuleMatch",
    "favicon_hashes",
    "favicon_href",
    "murmur3_32",
    "parse_title",
]
