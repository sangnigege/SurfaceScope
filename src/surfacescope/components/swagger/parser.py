"""OpenAPI 2/3 parsing without a browser, UI, workbook, or global state."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup

from ...urls import host_allowed

try:
    import yaml
except ImportError:  # pragma: no cover - declared core dependency
    yaml = None


DOCUMENT_PATHS = (
    "/swagger.json",
    "/api/swagger.json",
    "/openapi.json",
    "/api/openapi.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/v3/api-docs/swagger-config",
    "/api-docs",
    "/swagger-resources",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/doc.html",
)
SAFE_METHODS = frozenset({"get", "head"})
UNSAFE_METHODS = frozenset({"post", "put", "patch", "delete"})
_DOC_HINT = re.compile(r"(?:swagger|openapi|api[-_/]?docs?)", re.IGNORECASE)
_DOC_SUFFIX = re.compile(r"(?:\.json|\.ya?ml|/api-docs|/openapi)(?:[?#].*)?$", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class SwaggerOperation:
    url: str
    method: str
    query: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    operation_id: str = ""
    summary: str = ""
    request_body: Any = None

    @property
    def safe(self) -> bool:
        return self.method.lower() in SAFE_METHODS


@dataclass(frozen=True, slots=True)
class _Parameter:
    name: str
    location: str
    sample: Any
    required: bool = False


def parse_document(text: str) -> dict[str, Any] | None:
    value_text = (text or "").strip()
    if not value_text or value_text[:1] not in ("{", "["):
        try:
            parsed = yaml.safe_load(value_text) if yaml is not None and value_text else None
        except Exception:
            return None
        return parsed if isinstance(parsed, dict) else None
    try:
        parsed = json.loads(value_text)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        pass
    if yaml is None:
        return None
    try:
        parsed = yaml.safe_load(value_text)
    except Exception:
        return None
    return parsed if isinstance(parsed, dict) else None


def resolve_ref(value: Any, root: dict[str, Any], seen: set[str] | None = None) -> Any:
    """Resolve local JSON pointers with cycle protection; remote refs stay untouched."""

    if not isinstance(value, dict) or "$ref" not in value:
        return value
    ref = str(value.get("$ref", ""))
    if not ref.startswith("#/"):
        return value
    visited = set() if seen is None else seen
    if ref in visited:
        return value
    visited.add(ref)
    node: Any = root
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or part not in node:
            return value
        node = node[part]
    resolved = resolve_ref(node, root, visited)
    if isinstance(resolved, dict):
        merged = dict(resolved)
        merged.update({key: item for key, item in value.items() if key != "$ref"})
        return merged
    return resolved


def document_links(html_text: str, page_url: str) -> list[str]:
    values: list[str] = []
    if "<" in (html_text or ""):
        soup = BeautifulSoup(html_text or "", "html.parser")
        for tag in soup.find_all(("a", "link", "script")):
            raw = tag.get("href") or tag.get("src")
            if raw:
                values.append(urljoin(page_url, str(raw)))
    for match in re.finditer(r"""["']([^"'<>\\]{1,2048})["']""", html_text or ""):
        raw = match.group(1).replace("\\/", "/")
        if _DOC_HINT.search(raw) and _DOC_SUFFIX.search(raw):
            values.append(urljoin(page_url, raw))
    return _dedupe([value for value in values if _looks_like_document(value)])


def iter_operations(
    document: dict[str, Any],
    target_url: str,
    *,
    include_unsafe: bool = False,
    max_operations: int = 2000,
    allow_external: bool = False,
) -> Iterator[SwaggerOperation]:
    paths = document.get("paths")
    if not isinstance(paths, dict):
        return
    bases = _base_urls(document, target_url)
    yielded = 0
    for path, raw_path_item in paths.items():
        if yielded >= max_operations:
            return
        if not isinstance(path, str) or not path.startswith("/"):
            continue
        path_item = resolve_ref(raw_path_item, document)
        if not isinstance(path_item, dict):
            continue
        path_parameters = _parameters(path_item.get("parameters"), document)
        for method, raw_operation in path_item.items():
            if yielded >= max_operations:
                return
            method_lower = str(method).lower()
            if method_lower not in SAFE_METHODS | UNSAFE_METHODS:
                continue
            if not include_unsafe and method_lower not in SAFE_METHODS:
                continue
            operation = resolve_ref(raw_operation, document)
            if not isinstance(operation, dict):
                continue
            parameters = _merge_parameters(path_parameters, _parameters(operation.get("parameters"), document))
            endpoint_url = _build_endpoint(bases, path, parameters)
            if endpoint_url is None:
                continue
            if not allow_external and not host_allowed(target_url, endpoint_url):
                continue
            headers = {item.name: _sample_text(item.sample) for item in parameters if item.location == "header"}
            cookies = {item.name: _sample_text(item.sample) for item in parameters if item.location == "cookie"}
            query = {item.name: _sample_text(item.sample) for item in parameters if item.location == "query"}
            body = _request_body(operation, document) if include_unsafe else None
            yield SwaggerOperation(
                url=endpoint_url,
                method=method_lower.upper(),
                query=query,
                headers=headers,
                cookies=cookies,
                operation_id=str(operation.get("operationId") or ""),
                summary=str(operation.get("summary") or ""),
                request_body=body,
            )
            yielded += 1


def _base_urls(document: dict[str, Any], target_url: str) -> list[str]:
    origin = _origin(target_url)
    swagger = document.get("swagger")
    if swagger is not None:
        schemes = document.get("schemes") if isinstance(document.get("schemes"), list) else [urlsplit(target_url).scheme]
        host = str(document.get("host") or urlsplit(target_url).netloc)
        base_path = str(document.get("basePath") or "/")
        return _dedupe(
            [urlunsplit((str(scheme).lower(), host, base_path or "/", "", "")) for scheme in schemes]
        ) or [origin]

    result: list[str] = []
    servers = document.get("servers")
    if isinstance(servers, list):
        for server in servers:
            if not isinstance(server, dict):
                continue
            candidate = str(server.get("url") or "").strip()
            variables = server.get("variables")
            if isinstance(variables, dict):
                for key, value in variables.items():
                    default = value.get("default", "") if isinstance(value, dict) else ""
                    candidate = candidate.replace("{" + str(key) + "}", str(default))
            if candidate:
                result.append(urljoin(origin + "/", candidate))
    return _dedupe(result) or [origin]


def _parameters(raw: Any, root: dict[str, Any]) -> list[_Parameter]:
    if not isinstance(raw, list):
        return []
    result: list[_Parameter] = []
    for item in raw:
        item = resolve_ref(item, root)
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        location = item.get("in")
        if not name or location not in ("path", "query", "header", "cookie"):
            continue
        schema = item.get("schema") if isinstance(item.get("schema"), dict) else item
        sample = item.get("example", item.get("default", schema.get("example", schema.get("default"))))
        if sample is None and isinstance(schema.get("enum"), list) and schema["enum"]:
            sample = schema["enum"][0]
        if sample is None:
            sample = _sample_for_schema(schema)
        result.append(_Parameter(str(name), str(location), sample, bool(item.get("required", False))))
    return result


def _sample_for_schema(schema: dict[str, Any]) -> str:
    value_type = str(schema.get("type") or "string")
    if value_type in ("integer", "number"):
        return "1"
    if value_type == "boolean":
        return "true"
    if value_type == "array":
        return "a"
    return "a"


def _merge_parameters(left: list[_Parameter], right: list[_Parameter]) -> list[_Parameter]:
    merged: dict[tuple[str, str], _Parameter] = {(item.location, item.name): item for item in left}
    merged.update({(item.location, item.name): item for item in right})
    return list(merged.values())


def _build_endpoint(bases: list[str], path: str, parameters: list[_Parameter]) -> str | None:
    rendered = path
    for parameter in parameters:
        if parameter.location == "path":
            rendered = rendered.replace("{" + parameter.name + "}", quote(_sample_text(parameter.sample), safe=""))
    for name in re.findall(r"\{([^{}]+)\}", rendered):
        rendered = rendered.replace("{" + name + "}", quote("a", safe=""))
    for base in bases:
        candidate = urljoin(base.rstrip("/") + "/", rendered.lstrip("/"))
        if urlsplit(candidate).scheme in ("http", "https"):
            return candidate
    return None


def _request_body(operation: dict[str, Any], root: dict[str, Any]) -> Any:
    request_body = resolve_ref(operation.get("requestBody"), root)
    if isinstance(request_body, dict):
        content = request_body.get("content")
        if isinstance(content, dict):
            for media_type in ("application/json", "application/x-www-form-urlencoded", "text/plain"):
                media = content.get(media_type)
                if isinstance(media, dict):
                    example = media.get("example")
                    if example is not None:
                        return example
                    schema = resolve_ref(media.get("schema"), root)
                    if isinstance(schema, dict) and schema.get("example") is not None:
                        return schema["example"]
                    return {}
    raw_body = operation.get("parameters")
    if isinstance(raw_body, list):
        for item in raw_body:
            item = resolve_ref(item, root)
            if isinstance(item, dict) and item.get("in") == "body":
                if item.get("example") is not None:
                    return item["example"]
                return {}
    return None


def _sample_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _looks_like_document(value: str) -> bool:
    parts = urlsplit(value)
    return parts.scheme in ("http", "https") and bool(_DOC_HINT.search(value)) and bool(_DOC_SUFFIX.search(parts.path))


def _origin(value: str) -> str:
    parts = urlsplit(value)
    return urlunsplit((parts.scheme.lower(), parts.netloc, "", "", ""))


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


__all__ = [
    "DOCUMENT_PATHS",
    "SAFE_METHODS",
    "SwaggerOperation",
    "document_links",
    "iter_operations",
    "parse_document",
    "resolve_ref",
]
