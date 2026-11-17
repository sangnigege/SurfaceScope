"""Small compatibility helpers for the supported Python range."""

from __future__ import annotations

try:  # Python 3.11+
    import tomllib  # type: ignore[import-not-found]
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib  # type: ignore[no-redef,import-not-found]


__all__ = ["tomllib"]
