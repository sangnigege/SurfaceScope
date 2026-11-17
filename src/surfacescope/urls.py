"""URL normalisation and scope helpers shared by every layer."""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit


def canonical_url(value: str) -> str:
    parts = urlsplit(str(value or "").strip())
    if not parts.scheme and not parts.netloc:
        return str(value or "").strip()
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path or "/", parts.query, ""))


def origin(value: str) -> str:
    parts = urlsplit(str(value or "").strip())
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), "", "", ""))


def same_origin(left: str, right: str) -> bool:
    return bool(left and right and origin(left) == origin(right))


def host_allowed(base_url: str, candidate_url: str) -> bool:
    """Allow the target host and its subdomains, never unrelated lookalikes."""

    base_host = (urlsplit(base_url).hostname or "").lower().rstrip(".")
    candidate_host = (urlsplit(candidate_url).hostname or "").lower().rstrip(".")
    if not base_host or not candidate_host:
        return False
    return candidate_host == base_host or candidate_host.endswith("." + base_host)


def is_http_url(value: str) -> bool:
    try:
        parts = urlsplit(str(value))
    except ValueError:
        return False
    return parts.scheme in {"http", "https"} and bool(parts.netloc)


__all__ = ["canonical_url", "host_allowed", "is_http_url", "origin", "same_origin"]
