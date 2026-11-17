"""Run-scoped dependency container."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .artifacts import ArtifactStore
from .assets import AssetManifest, WordlistRegistry
from .capabilities import CapabilityRegistry
from .config import ConfigSnapshot
from .result_store import ResultStore
from .traffic.executor import RequestExecutor
from .traffic.profiles import RequestProfile


@dataclass
class ScanContext:
    config: ConfigSnapshot
    profile: RequestProfile
    executor: RequestExecutor
    artifacts: ArtifactStore
    results: ResultStore
    capabilities: CapabilityRegistry
    logger: logging.Logger
    manifest: AssetManifest
    wordlists: WordlistRegistry
    output_dir: Path
    options: dict[str, Any]
