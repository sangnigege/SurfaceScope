"""Low-noise secret extraction from packaged JavaScript."""

from __future__ import annotations

import re
from dataclasses import dataclass

_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_AWS_ACCESS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_GOOGLE_API_KEY = re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")
_STRIPE_LIVE_KEY = re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b")
_GENERIC_SECRET = re.compile(
    r"""(?i)\b(api[_-]?key|secret|token|password|access[_-]?token|refresh[_-]?token|client[_-]?secret)\b\s*[:=]\s*["']([^"'\s]{8,})["']"""
)


@dataclass(frozen=True, slots=True)
class SecretMatch:
    kind: str
    value: str
    offset: int
    source: str

    @property
    def preview(self) -> str:
        return redact_secret(self.value)


def find_secrets(text: str, source: str, *, limit: int = 100) -> list[SecretMatch]:
    """Return high-confidence secret candidates with stable de-duplication."""

    value = text or ""
    matches: list[SecretMatch] = []
    for kind, pattern in (
        ("private-key", _PRIVATE_KEY),
        ("aws-access-key", _AWS_ACCESS_KEY),
        ("google-api-key", _GOOGLE_API_KEY),
        ("stripe-live-key", _STRIPE_LIVE_KEY),
        ("jwt", _JWT),
    ):
        for match in pattern.finditer(value):
            matches.append(SecretMatch(kind, match.group(0), match.start(), source))
    for match in _GENERIC_SECRET.finditer(value):
        matches.append(SecretMatch(f"generic-{match.group(1).lower()}", match.group(2), match.start(), source))

    result: list[SecretMatch] = []
    seen: set[tuple[str, str]] = set()
    for match in sorted(matches, key=lambda item: item.offset):
        key = (match.kind, match.value)
        if key not in seen:
            seen.add(key)
            result.append(match)
        if len(result) >= max(1, limit):
            break
    return result


def redact_secret(value: str) -> str:
    if "PRIVATE KEY" in value:
        return "<redacted-private-key>"
    if len(value) <= 8:
        return "<redacted>"
    return f"{value[:4]}...{value[-2:]}"
