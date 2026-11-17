#!/usr/bin/env python3
"""Validate the v3 asset manifest from a source checkout or installed wheel."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from surfacescope.assets import AssetManifest  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--skip-consumer-check",
        action="store_true",
        help="only validate bytes, hashes, counts and manifest structure",
    )
    args = parser.parse_args(argv)
    errors = AssetManifest().validate(verify_consumers=not args.skip_consumer_check)
    if errors:
        for error in errors:
            print(f"asset error: {error}", file=sys.stderr)
        return 1
    print("asset manifest: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
