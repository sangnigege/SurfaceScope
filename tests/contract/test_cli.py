from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

from surfacescope import cli as cli_module
from surfacescope import pipeline
from surfacescope.cli import _components_from_args, _targets_from_args, build_parser, main

ROOT = Path(__file__).resolve().parents[2]


def test_dry_run_validates_without_constructing_executor(monkeypatch, capsys) -> None:
    def fail_executor(*args, **kwargs):
        raise AssertionError("dry-run must not construct a network executor")

    monkeypatch.setattr(pipeline, "RequestExecutor", fail_executor)

    exit_code = main(["--dry-run", "--no-env", "http://127.0.0.1:8000/"])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["targets"] == ["http://127.0.0.1:8000/"]
    assert payload["profile"] == "chromium-desktop-stable"
    assert payload["asset_count"] == 11


def test_dry_run_no_env_uses_defaults(monkeypatch, capsys) -> None:
    monkeypatch.setenv("SURFACESCOPE_THREADS", "7")

    assert main(["--dry-run", "--no-env", "http://127.0.0.1:8000/"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["config"]["run"]["threads"] == 25
    assert payload["config"]["dirsearch"]["include_statuses"] == [200, 204, 301, 302, 307, 308, 401, 403]
    assert payload["config"]["dirsearch"]["exclude_statuses"] == [400]
    assert payload["config"]["reports"]["format"] == "json"
    assert payload["config"]["traffic"]["verify_tls"] is True


def test_tls_verification_is_secure_by_default_and_insecure_is_opt_in(capsys) -> None:
    assert main(["--dry-run", "--no-env", "--insecure", "https://127.0.0.1:8443/"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["config"]["traffic"]["verify_tls"] is False


def test_explicit_cli_lists_replace_defaults_without_empty_values_winning(capsys) -> None:
    assert main(
        [
            "--dry-run",
            "--no-env",
            "--include-statuses",
            "200,418",
            "--exclude-statuses",
            "404",
            "http://127.0.0.1:8000/",
        ]
    ) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["config"]["dirsearch"]["include_statuses"] == [200, 418]
    assert payload["config"]["dirsearch"]["exclude_statuses"] == [404]


def test_cli_options_have_one_typed_config_path(capsys) -> None:
    assert main(
        [
            "--dry-run",
            "--no-env",
            "--target-profile",
            "grafana",
            "--prefixes",
            "api/",
            "--suffixes",
            ".bak",
            "--max-candidates",
            "2",
            "--recursive",
            "--follow-redirects",
            "--max-redirects",
            "3",
            "http://127.0.0.1:8000/",
        ]
    ) == 0

    config = json.loads(capsys.readouterr().out)["config"]
    assert config["dirsearch"]["target_profiles"] == ["grafana"]
    assert config["dirsearch"]["prefixes"] == ["api/"]
    assert config["dirsearch"]["suffixes"] == [".bak"]
    assert config["dirsearch"]["max_candidates"] == 2
    assert config["dirsearch"]["recursive"] is True
    assert config["traffic"]["follow_redirects"] is True
    assert config["traffic"]["max_redirects"] == 3


def test_format_defaults_to_config_and_cli_override_is_resolved(capsys) -> None:
    assert main(["--dry-run", "--no-env", "http://127.0.0.1:8000/"]) == 0
    default_payload = json.loads(capsys.readouterr().out)
    assert default_payload["config"]["reports"]["format"] == "json"

    assert main(["--dry-run", "--no-env", "--format", "md,html", "http://127.0.0.1:8000/"]) == 0
    override_payload = json.loads(capsys.readouterr().out)
    assert override_payload["config"]["reports"]["format"] == "md,html"


def test_dry_run_reports_unknown_profile(capsys) -> None:
    assert main(["--dry-run", "--no-env", "--profile", "missing-profile", "http://127.0.0.1:8000/"]) == 2

    assert "unknown request profile" in capsys.readouterr().err


def test_bypass_stage_is_opt_in() -> None:
    parser = build_parser()

    default_args = parser.parse_args(["--dry-run", "http://127.0.0.1:8000/"])
    enabled_args = parser.parse_args(["--dry-run", "--bypass", "http://127.0.0.1:8000/"])

    assert "bypass403" not in _components_from_args(default_args)
    assert "bypass403" in _components_from_args(enabled_args)


def test_cli_uses_surfacescope_program_name() -> None:
    assert build_parser().prog == "surfacescope"


def test_windows_redirected_output_is_reconfigured_to_utf8(monkeypatch) -> None:
    class Stream:
        encoding = "gbk"

        def __init__(self) -> None:
            self.encoding_after = ""

        def isatty(self) -> bool:
            return False

        def reconfigure(self, *, encoding: str, errors: str) -> None:
            self.encoding_after = f"{encoding}/{errors}"

    stdout = Stream()
    stderr = Stream()
    monkeypatch.setattr(cli_module.os, "name", "nt")
    monkeypatch.delenv("PYTHONIOENCODING", raising=False)
    monkeypatch.setattr(cli_module, "sys", SimpleNamespace(stdout=stdout, stderr=stderr))

    cli_module._configure_redirected_output()

    assert stdout.encoding_after == "utf-8/backslashreplace"
    assert stderr.encoding_after == "utf-8/backslashreplace"


def test_bypass_mode_supports_explicit_full_depth() -> None:
    parser = build_parser()

    args = parser.parse_args(["--dry-run", "--bypass-mode", "full", "http://127.0.0.1:8000/"])

    assert args.bypass_mode == "full"


def test_packer_active_flags_are_explicit_and_isolated() -> None:
    parser = build_parser()
    args = parser.parse_args(
        [
            "--dry-run",
            "--packer",
            "--packer-active",
            "--packer-sqli",
            "http://127.0.0.1:8000/",
        ]
    )

    assert "packer" in _components_from_args(args)
    assert args.packer_active is True
    assert args.packer_sqli is True


def test_target_file_keeps_same_url_in_separate_auth_scopes(tmp_path) -> None:
    target_file = tmp_path / "targets.json"
    target_file.write_text(
        json.dumps(
            {
                "targets": [
                    {
                        "url": "http://127.0.0.1:8000/private",
                        "scope": "account-a",
                        "headers": {"Authorization": "Bearer a"},
                    },
                    {
                        "url": "http://127.0.0.1:8000/private",
                        "scope": "account-b",
                        "cookies": {"sid": "b"},
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    args = build_parser().parse_args(["--target-file", str(target_file)])

    targets = _targets_from_args(args)

    assert [target.auth_scope for target in targets] == ["account-a", "account-b"]
    assert targets[0].headers["Authorization"] == "Bearer a"
    assert targets[1].cookies["sid"] == "b"


def test_root_entrypoints_run_without_pythonpath() -> None:
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env["PYTHONIOENCODING"] = "utf-8"
    for entrypoint in ("dirsearch", "single_403pass", "swagger"):
        completed = subprocess.run(
            [sys.executable, str(ROOT / f"{entrypoint}.py"), "--help"],
            cwd=ROOT,
            env=env,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=30,
        )
        assert completed.returncode == 0, completed.stderr
        assert "usage: surfacescope" in completed.stdout


def test_all_enables_six_components_with_safe_scan_defaults(capsys) -> None:
    assert main(["--dry-run", "--no-env", "--all", "http://127.0.0.1:8000/"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["components"] == [
        "dirsearch",
        "jsfinder",
        "packer",
        "swagger",
        "bypass403",
        "finger",
    ]
    selection = payload["selection"]
    assert selection["preset"] == "all-safe"
    assert selection["bypass_mode"] == "fast"
    assert selection["bypass_initial_variants"] == 27
    assert selection["bypass_max_variants"] == 72
    assert selection["swagger_unsafe"] is False
    assert selection["packer_active"] is False
    assert selection["packer_sqli"] is False
    assert selection["packer_probe_endpoints"] is False


def test_all_respects_explicit_component_selection_and_negative_flags(capsys) -> None:
    assert main(
        [
            "--dry-run",
            "--no-env",
            "--all",
            "--no-bypass",
            "--no-swagger",
            "--no-packer",
            "http://127.0.0.1:8000/",
        ]
    ) == 0
    reduced = json.loads(capsys.readouterr().out)
    assert reduced["components"] == ["dirsearch", "jsfinder", "finger"]

    assert main(
        [
            "--dry-run",
            "--no-env",
            "--all",
            "--components",
            "dirsearch",
            "http://127.0.0.1:8000/",
        ]
    ) == 0
    explicit = json.loads(capsys.readouterr().out)
    assert explicit["components"] == ["dirsearch"]
