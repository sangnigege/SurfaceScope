from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_install_matrix.py"
_SPEC = importlib.util.spec_from_file_location("surfacescope_check_install_matrix", SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
install_matrix = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = install_matrix
_SPEC.loader.exec_module(install_matrix)


class FakeRunner:
    def __init__(self, fail_when=None) -> None:
        self.calls: list[tuple[list[str], Path, dict[str, str]]] = []
        self.fail_when = fail_when

    def __call__(self, argv, cwd, env, timeout):
        values = [str(item) for item in argv]
        self.calls.append((values, Path(cwd), dict(env)))
        if self.fail_when and self.fail_when(values):
            return install_matrix.CommandResult(tuple(values), 1, "failed", "simulated failure")
        if len(values) >= 3 and values[1:3] == ["-m", "venv"]:
            venv = Path(values[-1])
            for relative in ("bin/python", "Scripts/python.exe"):
                target = venv / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("", encoding="utf-8")
        return install_matrix.CommandResult(tuple(values), 0, "ok", "")


def _artifact_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "dist"
    directory.mkdir()
    (directory / "surfacescope-0.2.0-py3-none-any.whl").write_bytes(b"wheel")
    return directory


def _manifest(tmp_path: Path, *, interpreter: str | None = None) -> Path:
    path = tmp_path / "interpreters.json"
    path.write_text(
        json.dumps(
            [
                {
                    "os": "linux",
                    "python": "3.10",
                    "interpreter": interpreter or sys.executable,
                }
            ]
        ),
        encoding="utf-8",
    )
    return path


def _candidate() -> str:
    return "a" * 40


def test_offline_matrix_passes_with_clean_environment_and_outside_repo_venv(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("PYTHONPATH", str(ROOT / "src"))
    runner = FakeRunner()

    report = install_matrix.run_matrix(
        _artifact_dir(tmp_path),
        _manifest(tmp_path),
        candidate_sha=_candidate(),
        execute=runner,
    )

    assert report["summary"] == {"total": 1, "pass": 1, "fail": 0, "blocked": 0}
    assert install_matrix.report_exit_code(report) == 0
    assert report["cells"][0]["candidate_sha"] == _candidate()
    assert report["dependency_dir"] == str((tmp_path / "dist").resolve())
    assert report["dependency_artifacts"] == {}
    assert len(report["cells"][0]["commands"]) == 5
    assert all("PYTHONPATH" not in env for _, _, env in runner.calls)
    assert all(not cwd.resolve().is_relative_to(ROOT.resolve()) for _, cwd, _ in runner.calls)
    assert report["cells"][0]["status"] == "pass"


def test_post_install_asset_check_is_single_line_on_windows(tmp_path) -> None:
    runner = FakeRunner()

    install_matrix.run_matrix(_artifact_dir(tmp_path), _manifest(tmp_path), execute=runner)

    inline_commands = [call[0] for call in runner.calls if "-c" in call[0]]
    assert len(inline_commands) == 1
    source = inline_commands[0][-1]
    assert "\n" not in source
    assert "\r" not in source
    assert "assert not errors, errors" in source


def test_missing_interpreter_is_blocked_not_passed(tmp_path) -> None:
    runner = FakeRunner()

    report = install_matrix.run_matrix(
        _artifact_dir(tmp_path),
        _manifest(tmp_path, interpreter="definitely-not-a-python-3.99"),
        execute=runner,
    )

    assert runner.calls == []
    assert report["summary"] == {"total": 1, "pass": 0, "fail": 0, "blocked": 1}
    assert report["cells"][0]["status"] == "blocked"
    assert "interpreter not found" in report["cells"][0]["uncovered"][0]
    assert install_matrix.report_exit_code(report) == 1


def test_checksum_mismatch_fails_before_creating_a_venv(tmp_path) -> None:
    directory = _artifact_dir(tmp_path)
    (directory / "SHA256SUMS").write_text(
        "0" * 64 + "  surfacescope-0.2.0-py3-none-any.whl\n",
        encoding="utf-8",
    )
    runner = FakeRunner()

    report = install_matrix.run_matrix(directory, _manifest(tmp_path), execute=runner)

    assert runner.calls == []
    assert report["cells"][0]["status"] == "fail"
    assert any("SHA256 mismatch" in item for item in report["cells"][0]["uncovered"])


def test_source_checkout_cannot_be_used_as_artifact_directory(tmp_path) -> None:
    source = tmp_path / "source"
    (source / "src" / "surfacescope").mkdir(parents=True)

    with pytest.raises(install_matrix.MatrixInputError, match="source checkout"):
        install_matrix.discover_artifacts(source)


def test_safe_temp_parent_skips_repository_and_uses_writable_fallback(tmp_path, monkeypatch) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    system_temp = tmp_path / "system-temp"
    monkeypatch.setattr(install_matrix, "ROOT", repository)
    monkeypatch.setattr(install_matrix.tempfile, "gettempdir", lambda: str(repository))
    monkeypatch.setenv("LOCALAPPDATA", str(repository))
    monkeypatch.setenv("USERPROFILE", str(repository))
    monkeypatch.setenv("SYSTEMROOT", str(system_temp))

    parent = install_matrix._safe_temp_parent()

    assert parent == system_temp / "Temp"
    assert install_matrix._outside_repository(parent)


def test_non_zero_install_command_marks_cell_failed(tmp_path) -> None:
    runner = FakeRunner(
        fail_when=lambda argv: any(item == "pip" for item in argv)
    )

    report = install_matrix.run_matrix(_artifact_dir(tmp_path), _manifest(tmp_path), execute=runner)

    assert report["cells"][0]["status"] == "fail"
    assert report["summary"]["fail"] == 1
    assert install_matrix.report_exit_code(report) == 1


def test_blocked_cells_never_count_as_pass(tmp_path) -> None:
    report = {
        "total": 1,
        "pass": 0,
        "fail": 0,
        "blocked": 1,
    }

    assert install_matrix.report_exit_code({"summary": report}) == 1
    assert install_matrix.report_exit_code({"summary": {"total": 1, "pass": 0, "fail": 0, "blocked": 0}}) == 1


def test_report_validation_rejects_missing_fields(tmp_path) -> None:
    report = install_matrix.run_matrix(
        _artifact_dir(tmp_path),
        _manifest(tmp_path),
        execute=FakeRunner(),
    )
    del report["cells"][0]["artifact_sha256"]

    errors = install_matrix.validate_report(report)

    assert any("artifact_sha256" in error for error in errors)
    assert install_matrix.validate_report({})


def test_interpreter_manifest_rejects_duplicate_cells(tmp_path) -> None:
    path = tmp_path / "duplicate.json"
    path.write_text(
        json.dumps(
            [
                {"os": "linux", "python": "3.10", "interpreter": sys.executable},
                {"os": "linux", "python": "3.10", "interpreter": sys.executable},
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(install_matrix.MatrixInputError, match="duplicate interpreter cell"):
        install_matrix.load_interpreters(path)


def test_dependency_wheels_are_not_treated_as_project_artifacts(tmp_path) -> None:
    directory = _artifact_dir(tmp_path)
    (directory / "requests-2.31.0-py3-none-any.whl").write_bytes(b"dependency")
    (directory / "pyyaml-6.0.2-py3-none-any.whl").write_bytes(b"dependency-2")

    artifacts, _ = install_matrix.discover_artifacts(directory)
    dependency_hashes = install_matrix.discover_dependency_artifacts(directory)

    assert [artifact.path.name for artifact in artifacts] == [
        "surfacescope-0.2.0-py3-none-any.whl"
    ]
    assert set(dependency_hashes) == {
        "requests-2.31.0-py3-none-any.whl",
        "pyyaml-6.0.2-py3-none-any.whl",
    }


def test_sdist_installs_offline_build_requirements_before_build(tmp_path) -> None:
    directory = tmp_path / "dist"
    directory.mkdir()
    (directory / "surfacescope-0.2.0.tar.gz").write_bytes(b"sdist")
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    (wheelhouse / "requests-2.31.0-py3-none-any.whl").write_bytes(b"requests")
    (wheelhouse / "setuptools-77.0.0-py3-none-any.whl").write_bytes(b"setuptools")
    (wheelhouse / "wheel-0.45.0-py3-none-any.whl").write_bytes(b"wheel")
    runner = FakeRunner()

    report = install_matrix.run_matrix(
        directory,
        _manifest(tmp_path),
        dependency_dir=wheelhouse,
        execute=runner,
    )

    assert report["summary"] == {"total": 1, "pass": 1, "fail": 0, "blocked": 0}
    assert report["dependency_artifacts"] == {
        "requests-2.31.0-py3-none-any.whl": install_matrix._sha256_file(
            wheelhouse / "requests-2.31.0-py3-none-any.whl"
        ),
        "setuptools-77.0.0-py3-none-any.whl": install_matrix._sha256_file(
            wheelhouse / "setuptools-77.0.0-py3-none-any.whl"
        ),
        "wheel-0.45.0-py3-none-any.whl": install_matrix._sha256_file(
            wheelhouse / "wheel-0.45.0-py3-none-any.whl"
        ),
    }
    pip_commands = [call[0] for call in runner.calls if call[0][1:3] == ["-m", "pip"]]
    assert len(pip_commands) == 2
    assert "setuptools>=77" in pip_commands[0]
    assert "wheel" in pip_commands[0]
    assert "--no-build-isolation" in pip_commands[1]
    assert str(wheelhouse) in pip_commands[1]
    assert str(directory) in pip_commands[1]


def test_require_dependencies_rejects_implicit_wheelhouse(tmp_path) -> None:
    with pytest.raises(install_matrix.MatrixInputError, match="dependency-dir"):
        install_matrix.run_matrix(
            _artifact_dir(tmp_path),
            _manifest(tmp_path),
            require_dependencies=True,
            execute=FakeRunner(),
        )


def _complete_wheelhouse(tmp_path: Path, *, omit: str | None = None) -> Path:
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    names = (
        "requests-2.31.0-py3-none-any.whl",
        "beautifulsoup4-4.12.3-py3-none-any.whl",
        "pyyaml-6.0.2-py3-none-any.whl",
        "tomli-2.0.1-py3-none-any.whl",
        "setuptools-77.0.0-py3-none-any.whl",
        "wheel-0.45.0-py3-none-any.whl",
    )
    for name in names:
        if name != omit:
            (wheelhouse / name).write_bytes(name.encode("ascii"))
    return wheelhouse


def test_require_dependencies_rejects_empty_wheelhouse(tmp_path) -> None:
    wheelhouse = tmp_path / "empty-wheelhouse"
    wheelhouse.mkdir()

    with pytest.raises(install_matrix.MatrixInputError, match="empty"):
        install_matrix.run_matrix(
            _artifact_dir(tmp_path),
            _manifest(tmp_path),
            dependency_dir=wheelhouse,
            require_dependencies=True,
            execute=FakeRunner(),
        )


def test_require_dependencies_rejects_missing_runtime_distribution(tmp_path) -> None:
    wheelhouse = _complete_wheelhouse(tmp_path, omit="tomli-2.0.1-py3-none-any.whl")

    with pytest.raises(install_matrix.MatrixInputError, match="tomli"):
        install_matrix.run_matrix(
            _artifact_dir(tmp_path),
            _manifest(tmp_path),
            dependency_dir=wheelhouse,
            require_dependencies=True,
            execute=FakeRunner(),
        )


def test_require_dependencies_rejects_missing_sdist_build_distribution(tmp_path) -> None:
    directory = tmp_path / "dist"
    directory.mkdir()
    (directory / "surfacescope-0.2.0.tar.gz").write_bytes(b"sdist")
    wheelhouse = _complete_wheelhouse(tmp_path, omit="setuptools-77.0.0-py3-none-any.whl")

    with pytest.raises(install_matrix.MatrixInputError, match="setuptools"):
        install_matrix.run_matrix(
            directory,
            _manifest(tmp_path),
            dependency_dir=wheelhouse,
            require_dependencies=True,
            execute=FakeRunner(),
        )


def test_require_dependencies_accepts_complete_runtime_and_build_wheelhouse(tmp_path) -> None:
    wheelhouse = _complete_wheelhouse(tmp_path)
    runner = FakeRunner()

    report = install_matrix.run_matrix(
        _artifact_dir(tmp_path),
        _manifest(tmp_path),
        dependency_dir=wheelhouse,
        require_dependencies=True,
        execute=runner,
    )

    assert report["summary"] == {"total": 1, "pass": 1, "fail": 0, "blocked": 0}
    assert len(report["dependency_artifacts"]) == 6
    assert any("--find-links" in call[0] for call in runner.calls)
