from __future__ import annotations

import json

import pytest

from surfacescope.cli import _targets_from_args, build_parser
from surfacescope.errors import ConfigurationError, RequestError
from surfacescope.models import RequestSpec
from surfacescope.traffic.executor import RequestExecutor
from surfacescope.traffic.profiles import RequestProfileRegistry


def _targets(*extra: str):
    args = build_parser().parse_args([*extra, "http://127.0.0.1:8000/"])
    return _targets_from_args(args)


def test_cli_rejects_case_insensitive_duplicate_headers() -> None:
    with pytest.raises(ConfigurationError, match="duplicate request header"):
        _targets("--header", "X-Test: first", "--header", "x-test: second")


@pytest.mark.parametrize("header", ["Content-Length: 0", "transfer-encoding: chunked"])
def test_cli_rejects_framing_headers(header: str) -> None:
    with pytest.raises(ConfigurationError, match="framing header"):
        _targets("--header", header)


def test_target_file_rejects_framing_headers(tmp_path) -> None:
    target_file = tmp_path / "targets.json"
    target_file.write_text(
        json.dumps(
            {
                "targets": [
                    {
                        "url": "http://127.0.0.1:8000/",
                        "headers": {"Content-Length": "4"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError, match="framing header"):
        _targets("--target-file", str(target_file))


def test_target_file_rejects_case_insensitive_duplicate_headers(tmp_path) -> None:
    target_file = tmp_path / "targets.json"
    target_file.write_text(
        json.dumps(
            {
                "targets": [
                    {
                        "url": "http://127.0.0.1:8000/",
                        "headers": {"X-Test": "first", "x-test": "second"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError, match="duplicate request header"):
        _targets("--target-file", str(target_file))


def test_target_file_override_does_not_duplicate_cli_header(tmp_path) -> None:
    target_file = tmp_path / "targets.json"
    target_file.write_text(
        json.dumps(
            {
                "targets": [
                    {
                        "url": "http://127.0.0.1:8000/",
                        "headers": {"x-test": "target"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    targets = _targets("--header", "X-Test: cli", "--target-file", str(target_file))

    assert targets[-1].headers == {"x-test": "target"}


def _executor() -> RequestExecutor:
    profile = RequestProfileRegistry().get()
    return RequestExecutor(profile, timeout=0.1)


@pytest.mark.parametrize("header", ["Content-Length", "Transfer-Encoding"])
def test_executor_rejects_direct_request_spec_framing_headers(header: str) -> None:
    executor = _executor()
    try:
        with pytest.raises(RequestError, match="framing header"):
            executor.request(
                RequestSpec(
                    url="http://127.0.0.1:9/",
                    target_id="target-a",
                    profile_id="chromium-desktop-stable",
                    headers={header: "0"},
                )
            )
    finally:
        executor.close()


def test_executor_rejects_case_insensitive_duplicate_headers() -> None:
    executor = _executor()
    try:
        with pytest.raises(RequestError, match="duplicate request header"):
            executor.request(
                RequestSpec(
                    url="http://127.0.0.1:9/",
                    target_id="target-a",
                    profile_id="chromium-desktop-stable",
                    headers={"X-Test": "first", "x-test": "second"},
                )
            )
    finally:
        executor.close()


def test_executor_accepts_ordinary_body_headers_without_user_framing() -> None:
    executor = _executor()
    try:
        executor._validate(
            RequestSpec(
                url="http://127.0.0.1:9/",
                target_id="target-a",
                profile_id="chromium-desktop-stable",
                method="POST",
                headers={"Content-Type": "application/json"},
                json={"probe": True},
            )
        )
    finally:
        executor.close()
