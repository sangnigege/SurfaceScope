from __future__ import annotations

from surfacescope.components.swagger import document_links, iter_operations, parse_document, resolve_ref

SWAGGER2 = """
swagger: "2.0"
host: example.test
basePath: /api
schemes: [https]
paths:
  /users/{id}:
    parameters:
      - $ref: "#/parameters/UserId"
    get:
      operationId: getUser
      parameters:
        - {name: verbose, in: query, type: boolean, default: true}
    post:
      operationId: createUser
  /health:
    head:
      operationId: health
parameters:
  UserId:
    name: id
    in: path
    required: true
    type: integer
"""


def test_swagger2_yaml_refs_and_methods_are_preserved() -> None:
    document = parse_document(SWAGGER2)
    assert document is not None

    safe = list(iter_operations(document, "http://example.test/"))
    unsafe = list(iter_operations(document, "http://example.test/", include_unsafe=True))

    assert [(operation.method, operation.url) for operation in safe] == [
        ("GET", "https://example.test/api/users/1"),
        ("HEAD", "https://example.test/api/health"),
    ]
    assert {(operation.method, operation.url) for operation in unsafe} >= {
        ("POST", "https://example.test/api/users/1"),
    }
    assert safe[0].query == {"verbose": "true"}
    assert safe[0].operation_id == "getUser"


def test_openapi3_server_variables_path_encoding_and_external_boundary() -> None:
    document = {
        "openapi": "3.1.0",
        "servers": [{"url": "https://{host}/{base}", "variables": {"host": {"default": "example.test"}, "base": {"default": "v1"}}}],
        "paths": {"/items/{name}": {"get": {"parameters": [{"name": "name", "in": "path", "schema": {"type": "string", "default": "a b"}}]}}},
    }

    operations = list(iter_operations(document, "http://example.test/"))
    external = list(iter_operations(document, "http://other.test/"))

    assert operations[0].url == "https://example.test/v1/items/a%20b"
    assert external == []


def test_local_ref_cycle_does_not_recurse_forever() -> None:
    root = {"components": {"schemas": {"A": {"$ref": "#/components/schemas/B"}, "B": {"$ref": "#/components/schemas/A"}}}}

    resolved = resolve_ref({"$ref": "#/components/schemas/A"}, root)

    assert isinstance(resolved, dict)
    assert "$ref" in resolved


def test_document_links_only_returns_document_candidates() -> None:
    html = '<a href="/swagger.json">API</a><script src="/app.js"></script><a href="/help">help</a>'

    assert document_links(html, "https://example.test/") == ["https://example.test/swagger.json"]
