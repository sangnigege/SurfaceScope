"""Small, evidence-oriented active checks for Packer endpoints.

These checks are intentionally conservative: they use one request per signal,
never upload files, never guess passwords, and only run when the caller opts
into active probing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ...models import ResponseSnapshot

CORS_PROBE_ORIGIN = "https://origin.surfacescope.invalid"
_SQL_ERROR = re.compile(
    r"(?is)(sql syntax|you have an error in your sql|unclosed quotation|"
    r"quoted string not properly terminated|syntax error at or near|"
    r"mysql_fetch|mysqli|pg_query|sqlite3?\.|ora-\d{4,5}|microsoft ole db|"
    r"odbc sql server driver|unterminated quoted string)"
)


@dataclass(frozen=True, slots=True)
class CorsDecision:
    accepted: bool
    confidence: float
    evidence: str
    technique: str = "cors-reflection"


@dataclass(frozen=True, slots=True)
class UnauthorizedDecision:
    accepted: bool
    confidence: float
    evidence: str
    technique: str = "authenticated-vs-anonymous"


def evaluate_cors(response: ResponseSnapshot, origin: str = CORS_PROBE_ORIGIN) -> CorsDecision:
    allow_origin = response.header("access-control-allow-origin").strip()
    allow_credentials = response.header("access-control-allow-credentials").strip().lower() == "true"
    if not allow_origin:
        return CorsDecision(False, 0.0, "no Access-Control-Allow-Origin header")
    if allow_origin == "*":
        reason = (
            "wildcard origin with credentials is rejected by browsers"
            if allow_credentials
            else "wildcard origin is not sufficient for a credentialed cross-origin read"
        )
        return CorsDecision(False, 0.0, reason)
    if allow_origin != origin:
        return CorsDecision(False, 0.0, f"origin not reflected: {allow_origin[:80]}")
    if not allow_credentials:
        return CorsDecision(False, 0.0, "origin reflected without credential permission")
    return CorsDecision(True, 0.9, "arbitrary origin reflected with credential permission")


def evaluate_unauthorized(
    authenticated: ResponseSnapshot,
    anonymous: ResponseSnapshot,
) -> UnauthorizedDecision:
    if authenticated.status in (401, 403) and 200 <= anonymous.status < 300:
        return UnauthorizedDecision(
            True,
            0.85,
            f"authenticated={authenticated.status}; anonymous={anonymous.status}",
        )
    if authenticated.status >= 500 or anonymous.status >= 500:
        return UnauthorizedDecision(False, 0.0, "server error prevents a reliable comparison")
    return UnauthorizedDecision(
        False,
        0.0,
        f"no status boundary: authenticated={authenticated.status}; anonymous={anonymous.status}",
    )


def sql_probe_urls(url: str, *, max_parameters: int = 2) -> list[tuple[str, str]]:
    """Create minimal quote probes for GET query parameters only."""

    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    if not pairs:
        return []
    result: list[tuple[str, str]] = []
    for index, (name, _value) in enumerate(pairs[: max(1, max_parameters)]):
        changed = list(pairs)
        changed[index] = (name, "surfacescope'")
        query = urlencode(changed, doseq=True)
        result.append((urlunsplit((parts.scheme, parts.netloc, parts.path, query, "")), name))
    return result


def looks_like_sql_error(text: str) -> bool:
    return bool(_SQL_ERROR.search(text or ""))
