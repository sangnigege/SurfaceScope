"""Transactional JSON, Markdown, HTML, and CSV report output."""

from __future__ import annotations

import contextlib
import csv
import html
import io
import json
import os
import re
import tempfile
import uuid
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from ..errors import ConfigurationError
from ..models import ComponentResult
from .schema import build_report

_ALLOWED_FORMATS = frozenset({"json", "md", "markdown", "html", "csv"})
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


class ReportWriter:
    def __init__(self, output_dir: str | Path) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def write(
        self,
        run_id: str,
        results: ComponentResult,
        run_meta: dict[str, Any],
        fmt: str | list[str] = "json",
    ) -> list[Path]:
        safe_run_id = _safe_run_id(run_id)
        formats = _normalise_formats(fmt)
        report = build_report(safe_run_id, results, run_meta)
        documents: list[tuple[Path, str]] = [
            (
                self.output_dir / f"{safe_run_id}.json",
                json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            )
        ]
        if "md" in formats or "markdown" in formats:
            documents.append((self.output_dir / f"{safe_run_id}.md", _markdown(safe_run_id, report)))
        if "html" in formats:
            documents.append((self.output_dir / f"{safe_run_id}.html", _html(safe_run_id, report)))
        if "csv" in formats:
            documents.append((self.output_dir / f"{safe_run_id}.csv", _csv(report)))
        return _write_batch_atomic(documents)


def _markdown(run_id: str, report: dict[str, Any]) -> str:
    lines = [
        f"# Scan report {_markdown_text(run_id)}",
        "",
        f"- schema: {report['schema_version']}",
        f"- findings: {report['summary']['findings']}",
        f"- errors: {report['summary']['errors']}",
        "",
    ]
    for finding in report["findings"]:
        lines.extend(
            [
                f"## {_markdown_text(finding.get('kind', ''))} - {_markdown_text(finding.get('target', ''))}",
                f"- module: {_markdown_text(finding.get('module', ''))}",
                f"- severity: {_markdown_text(finding.get('severity', ''))}",
                f"- confidence: {_markdown_text(finding.get('confidence', ''))}",
                f"- technique: {_markdown_text(finding.get('technique', ''))}",
                f"- auth scope: {_markdown_text(finding.get('auth_scope', ''))}",
                f"- evidence: {_markdown_text(finding.get('evidence', ''))}",
                "",
            ]
        )
    return "\n".join(lines).rstrip("\n") + "\n"


def _html(run_id: str, report: dict[str, Any]) -> str:
    rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            html.escape(str(item.get("module", ""))),
            html.escape(str(item.get("kind", ""))),
            html.escape(str(item.get("target", ""))),
            html.escape(str(item.get("severity", ""))),
            html.escape(str(item.get("evidence", ""))),
        )
        for item in report["findings"]
    )
    title = html.escape(run_id)
    body = (
        "<!doctype html><html><head><meta charset='utf-8'>"
        f"<title>{title}</title></head><body><h1>{title}</h1>"
        "<table border='1'><thead><tr><th>module</th><th>kind</th><th>target</th>"
        f"<th>severity</th><th>evidence</th></tr></thead><tbody>{rows}</tbody></table>"
        "</body></html>"
    )
    return body + "\n"


def _csv(report: dict[str, Any]) -> str:
    buffer = io.StringIO(newline="")
    fields = (
        "module",
        "kind",
        "target",
        "severity",
        "confidence",
        "technique",
        "auth_scope",
        "evidence",
    )
    writer = csv.DictWriter(buffer, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for finding in report["findings"]:
        writer.writerow({field: _csv_cell(finding.get(field, "")) for field in fields})
    return buffer.getvalue()


def _markdown_text(value: Any) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ").replace("\\", "\\\\")
    for character in ("`", "*", "_", "{", "}", "[", "]", "(", ")", "#", "+", "-", "!", "|", "<", ">"):
        text = text.replace(character, "\\" + character)
    return text


def _csv_cell(value: Any) -> str:
    text = str(value).replace("\x00", "")
    if text.startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text


def _safe_run_id(run_id: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(run_id)).strip(".-")
    return value or "run"


def _normalise_formats(fmt: str | list[str] | tuple[str, ...]) -> set[str]:
    values = [fmt] if isinstance(fmt, str) else list(fmt)
    result: set[str] = {"json"}
    for value in values:
        for item in str(value).split(","):
            item = item.strip().lower()
            if not item:
                continue
            if item not in _ALLOWED_FORMATS:
                raise ConfigurationError(f"unsupported report format: {item}")
            result.add(item)
    return result


def _write_batch_atomic(documents: Iterable[tuple[Path, str]]) -> list[Path]:
    items = list(documents)
    temporary: list[tuple[Path, Path]] = []
    backups: list[tuple[Path, Path]] = []
    committed: list[Path] = []
    try:
        for path, text in items:
            path.parent.mkdir(parents=True, exist_ok=True)
            handle, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
            temp_path = Path(temp_name)
            temporary.append((temp_path, path))
            with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(text)
                stream.flush()
                os.fsync(stream.fileno())
        for temp_path, path in temporary:
            if path.exists():
                backup = path.with_name(f".{path.name}.{uuid.uuid4().hex}.bak")
                os.replace(path, backup)
                backups.append((backup, path))
            os.replace(temp_path, path)
            committed.append(path)
        for backup, _ in backups:
            with contextlib.suppress(FileNotFoundError):
                backup.unlink()
        return [path for path, _ in items]
    except Exception:
        for path in committed:
            with contextlib.suppress(FileNotFoundError):
                path.unlink()
        for backup, path in reversed(backups):
            with contextlib.suppress(FileNotFoundError):
                os.replace(backup, path)
        raise
    finally:
        for temp_path, _ in temporary:
            with contextlib.suppress(FileNotFoundError):
                temp_path.unlink()
        for backup, _ in backups:
            with contextlib.suppress(FileNotFoundError):
                backup.unlink()
