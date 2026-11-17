"""Pure-Python Swagger/OpenAPI document parsing and operation generation."""

from .parser import (
    DOCUMENT_PATHS,
    SwaggerOperation,
    document_links,
    iter_operations,
    parse_document,
    resolve_ref,
)

__all__ = [
    "DOCUMENT_PATHS",
    "SwaggerOperation",
    "document_links",
    "iter_operations",
    "parse_document",
    "resolve_ref",
]
