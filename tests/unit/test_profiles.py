from __future__ import annotations

import re

from surfacescope.traffic.executor import _SUPPORTED_ACCEPT_ENCODINGS, _filter_accept_encoding
from surfacescope.traffic.profiles import RequestProfileRegistry


def test_default_request_profile_is_consistent_and_browser_like() -> None:
    profile = RequestProfileRegistry().get()
    chrome_major = int(re.search(r"Chrome/(\d+)", profile.user_agent).group(1))
    hint_major = int(re.search(r'"Chromium";v="(\d+)"', profile.client_hints["Sec-CH-UA"]).group(1))

    assert chrome_major == profile.major == hint_major
    headers = profile.build_headers("navigation")
    assert "curl" not in headers["User-Agent"].lower()
    assert "googlebot" not in headers["User-Agent"].lower()
    assert "X-Forwarded-For" not in headers
    assert "X-Original-URL" not in headers
    assert headers["Sec-Fetch-Mode"] == "navigate"
    assert headers["Sec-Fetch-Dest"] == "document"


def test_http_requests_do_not_send_secure_only_client_hints() -> None:
    profile = RequestProfileRegistry().get()

    http_headers = profile.build_headers("navigation", secure=False)
    https_headers = profile.build_headers("navigation", secure=True)

    assert not any(name.lower().startswith("sec-ch-ua") for name in http_headers)
    assert https_headers["Sec-CH-UA"] == profile.client_hints["Sec-CH-UA"]


def test_accept_encoding_only_claims_locally_decodable_codecs() -> None:
    headers = _filter_accept_encoding({"Accept-Encoding": "gzip, deflate, br, zstd"})
    tokens = {
        token.split(";", 1)[0].strip().lower()
        for token in headers["Accept-Encoding"].split(",")
        if token.strip()
    }

    assert tokens <= set(_SUPPORTED_ACCEPT_ENCODINGS)
    assert "gzip" in tokens
