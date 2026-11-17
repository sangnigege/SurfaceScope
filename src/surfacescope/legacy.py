"""Compatibility aliases for the historical root-level entry points.

The aliases only adjust the default component set and then call the canonical
``surfacescope.cli.main`` parser. They do not create a second argument parser,
HTTP session, report writer or scan pipeline.
"""

from __future__ import annotations

import sys


def _has_option(arguments: list[str], *names: str) -> bool:
    return any(argument == name or argument.startswith(name + "=") for argument in arguments for name in names)


def _mapped_arguments(entrypoint: str, argv: list[str] | None) -> list[str]:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if entrypoint == "single_403pass":
        if not _has_option(arguments, "--components"):
            arguments = ["--components", "bypass403", *arguments]
        if not _has_option(arguments, "--bypass"):
            arguments = ["--bypass", *arguments]
    elif entrypoint == "swagger":
        if not _has_option(arguments, "--components"):
            arguments = ["--components", "dirsearch,swagger", *arguments]
        if not _has_option(arguments, "--swagger"):
            arguments = ["--swagger", *arguments]
    return arguments


def legacy_entry(entrypoint: str, argv: list[str] | None = None) -> int:
    if entrypoint not in {"dirsearch", "single_403pass", "swagger"}:
        print(f"{entrypoint}: unsupported compatibility entry point", file=sys.stderr)
        return 2
    from .cli import main

    return int(main(_mapped_arguments(entrypoint, argv)))


__all__ = ["legacy_entry"]
