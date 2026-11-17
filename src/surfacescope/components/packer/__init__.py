"""Project-owned Packer/webpack analysis core."""

from .active import (
    CORS_PROBE_ORIGIN,
    CorsDecision,
    UnauthorizedDecision,
    evaluate_cors,
    evaluate_unauthorized,
    looks_like_sql_error,
    sql_probe_urls,
)
from .analyzer import Endpoint, PackerDocument, analyse_document, extract_endpoints, extract_scripts, source_map_urls
from .secrets import SecretMatch, find_secrets, redact_secret
from .surface import SurfaceCandidate, classify_surface, upload_markers

__all__ = [
    "CORS_PROBE_ORIGIN",
    "CorsDecision",
    "Endpoint",
    "PackerDocument",
    "SecretMatch",
    "SurfaceCandidate",
    "UnauthorizedDecision",
    "analyse_document",
    "classify_surface",
    "evaluate_cors",
    "evaluate_unauthorized",
    "extract_endpoints",
    "extract_scripts",
    "find_secrets",
    "looks_like_sql_error",
    "redact_secret",
    "source_map_urls",
    "sql_probe_urls",
    "upload_markers",
]
