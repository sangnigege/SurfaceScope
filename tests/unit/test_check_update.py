from __future__ import annotations

import json
from typing import Any

import pytest

from surfacescope import cli


class _Response:
    def __init__(self, payload: Any) -> None:
        self._body = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _Response:  # pragma: no cover - trivial stub
        return self

    def __exit__(self, *exc: object) -> bool:  # pragma: no cover - trivial stub
        return False


def _patch_urlopen(monkeypatch: pytest.MonkeyPatch, payload: Any) -> None:
    monkeypatch.setattr(cli.urllib.request, "urlopen", lambda *args, **kwargs: _Response(payload))


def test_version_key_orders_tags() -> None:
    assert cli._version_key("v0.10.0") > cli._version_key("v0.9.9")
    assert cli._version_key("0.2.0") == cli._version_key("v0.2.0")


def test_check_update_reports_up_to_date(monkeypatch, capsys) -> None:
    _patch_urlopen(monkeypatch, [{"name": "v0.2.0"}])
    monkeypatch.setattr(cli, "_installed_via", lambda: "uv")

    assert cli._check_update() == 0

    output = capsys.readouterr().out
    assert "already up to date" in output
    assert "installed via uv" in output


def test_check_update_prints_upgrade_hint_for_uv(monkeypatch, capsys) -> None:
    _patch_urlopen(monkeypatch, [{"name": "v0.1.0"}, {"name": "v0.9.0"}])
    monkeypatch.setattr(cli, "_installed_via", lambda: "uv")

    assert cli._check_update() == 0

    output = capsys.readouterr().out
    assert "v0.9.0" in output
    assert "uv tool install --force --reinstall" in output


def test_check_update_degrades_when_offline(monkeypatch, capsys) -> None:
    def boom(*args: object, **kwargs: object) -> None:
        raise OSError("network is down")

    monkeypatch.setattr(cli.urllib.request, "urlopen", boom)

    assert cli._check_update() == 0

    captured = capsys.readouterr()
    assert "update check unavailable" in captured.err


def test_check_update_handles_missing_tags(monkeypatch, capsys) -> None:
    _patch_urlopen(monkeypatch, [])

    assert cli._check_update() == 0
    assert "no published release tags" in capsys.readouterr().out
