"""Browser-consistent request profile and purpose headers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from ..assets import AssetManifest
from ..errors import AssetError
from ..urls import origin

_MULTI_LABEL_PUBLIC_SUFFIXES = frozenset(
    {
        "ac.uk",
        "co.jp",
        "co.uk",
        "com.au",
        "com.br",
        "com.cn",
        "com.hk",
        "com.sg",
        "com.tw",
        "edu.cn",
        "gov.cn",
        "net.cn",
        "org.cn",
        "org.uk",
    }
)

_CLIENT_HINT_NAMES = {
    "sec-ch-ua": "Sec-CH-UA",
    "sec-ch-ua-mobile": "Sec-CH-UA-Mobile",
    "sec-ch-ua-platform": "Sec-CH-UA-Platform",
}


def _site_key(value: str) -> str:
    """Return a scheme + registrable-domain approximation for Sec-Fetch-Site."""

    parts = urlsplit(str(value or "").strip())
    host = (parts.hostname or "").lower().rstrip(".")
    if not parts.scheme or not host:
        return ""
    try:
        host.encode("ascii")
    except UnicodeEncodeError:
        # IDNA is the browser-facing form; parsing libraries accept either.
        host = host.encode("idna").decode("ascii")
    if host.replace(".", "").isdigit():
        registrable = host
    else:
        labels = host.split(".")
        if len(labels) >= 3 and ".".join(labels[-2:]) in _MULTI_LABEL_PUBLIC_SUFFIXES:
            registrable = ".".join(labels[-3:])
        else:
            registrable = ".".join(labels[-2:])
    return f"{parts.scheme.lower()}://{registrable}"


def fetch_site(target_url: str, initiator: str | None = None) -> str:
    """Compute the browser ``Sec-Fetch-Site`` value for one request."""

    if not initiator:
        return "none"
    target_origin = origin(target_url)
    initiator_origin = origin(initiator)
    if target_origin and target_origin == initiator_origin:
        return "same-origin"
    if _site_key(target_url) and _site_key(target_url) == _site_key(initiator):
        return "same-site"
    return "cross-site"


@dataclass(frozen=True, slots=True)
class RequestProfile:
    id: str
    family: str
    major: int
    platform: str
    user_agent: str
    accept_language: str
    header_order: tuple[str, ...]
    client_hints: dict[str, str]
    purposes: dict[str, dict[str, str]]
    source: str
    review_after: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RequestProfile:
        return cls(
            id=str(data["id"]),
            family=str(data["family"]),
            major=int(data["major"]),
            platform=str(data["platform"]),
            user_agent=str(data["user_agent"]),
            accept_language=str(data["accept_language"]),
            header_order=tuple(str(item) for item in data.get("header_order", [])),
            client_hints={
                _CLIENT_HINT_NAMES.get(str(k).lower(), str(k)): str(v)
                for k, v in data.get("client_hints", {}).items()
            },
            purposes={str(k): {str(k2): str(v2) for k2, v2 in v.items()} for k, v in data.get("purposes", {}).items()},
            source=str(data.get("source", "")),
            review_after=str(data.get("review_after", "")),
        )

    def build_headers(
        self,
        purpose: str = "navigation",
        *,
        overrides: dict[str, str] | None = None,
        referer: str | None = None,
        origin: str | None = None,
        direct_navigation: bool = False,
        resource_type: str | None = None,
        has_body: bool = False,
        keep_content_type: bool = False,
        site: str | None = None,
        secure: bool = True,
    ) -> dict[str, str]:
        settings = self.purposes.get(purpose, self.purposes.get("navigation", {}))
        headers: dict[str, str] = {
            "User-Agent": self.user_agent,
            "Accept": settings.get("accept", "*/*"),
            "Accept-Language": self.accept_language,
            "Accept-Encoding": settings.get("accept_encoding", "gzip, deflate"),
        }
        # Chromium only sends low-entropy client hints to secure origins.
        if secure:
            headers.update(self.client_hints)
        fetch_site = site or ("none" if direct_navigation else "same-origin")
        headers.update({
            "Sec-Fetch-Site": fetch_site,
            "Sec-Fetch-Mode": settings.get("sec_fetch_mode", "navigate"),
            "Sec-Fetch-Dest": settings.get("sec_fetch_dest", "document"),
        })
        if settings.get("sec_fetch_user"):
            headers["Sec-Fetch-User"] = settings["sec_fetch_user"]
        if settings.get("upgrade_insecure_requests"):
            headers["Upgrade-Insecure-Requests"] = settings["upgrade_insecure_requests"]
        if purpose == "asset" and resource_type:
            accept_by_type = {
                "script": "*/*",
                "style": "text/css,*/*;q=0.1",
                "image": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
            }
            headers["Accept"] = accept_by_type.get(resource_type, headers["Accept"])
            headers["Sec-Fetch-Dest"] = resource_type
        if referer:
            headers["Referer"] = referer
        if origin:
            headers["Origin"] = origin
        if overrides:
            user_agent_override = any(key.lower() == "user-agent" for key in overrides)
            for key, value in overrides.items():
                for existing in [name for name in headers if name.lower() == key.lower()]:
                    headers.pop(existing, None)
                headers[key] = value
            if user_agent_override and not any(key.lower().startswith("sec-ch-ua") for key in overrides):
                headers = {key: value for key, value in headers.items() if not key.lower().startswith("sec-ch-ua")}
        if not has_body and not keep_content_type:
            headers.pop("Content-Type", None)
            headers.pop("content-type", None)
        return _order_headers(headers, self.header_order)


class RequestProfileRegistry:
    def __init__(self, manifest: AssetManifest | None = None) -> None:
        self.manifest = manifest or AssetManifest()
        self._profiles: dict[str, RequestProfile] = {}
        self._load()

    def _load(self) -> None:
        ref = self.manifest.resolve("profile.request.chromium_desktop")
        try:
            payload = json.loads(ref.read_text())
        except json.JSONDecodeError as exc:
            raise AssetError(f"invalid request profile JSON: {exc}") from exc
        for item in payload.get("profiles", []):
            profile = RequestProfile.from_dict(item)
            self._profiles[profile.id] = profile
        if not self._profiles:
            raise AssetError("request profile asset contains no profiles")

    def get(self, profile_id: str = "chromium-desktop-stable") -> RequestProfile:
        try:
            return self._profiles[profile_id]
        except KeyError as exc:
            raise AssetError(f"unknown request profile: {profile_id}") from exc

    def ids(self) -> list[str]:
        return sorted(self._profiles)


def _order_headers(headers: dict[str, str], header_order: tuple[str, ...]) -> dict[str, str]:
    ordered: dict[str, str] = {}
    used: set[str] = set()
    for wanted in header_order:
        wanted_lower = wanted.lower()
        for actual, value in headers.items():
            if actual in used:
                continue
            if actual.lower() == wanted_lower:
                ordered[actual] = value
                used.add(actual)
                break
    for actual, value in headers.items():
        if actual not in used:
            ordered[actual] = value
    return ordered


__all__ = ["RequestProfile", "RequestProfileRegistry", "fetch_site"]
