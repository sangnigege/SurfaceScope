"""Unified web attack surface assessment pipeline for SurfaceScope."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("surfacescope")
except PackageNotFoundError:  # source checkout without an installed distribution
    __version__ = "0.3.0"


__all__ = ["__version__"]
