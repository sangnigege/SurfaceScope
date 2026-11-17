from __future__ import annotations

import pytest

from surfacescope import pipeline
from surfacescope.errors import ConfigurationError
from surfacescope.models import Finding, ResponseSnapshot, Target
from surfacescope.result_store import ResultStore
from surfacescope.traffic.profiles import fetch_site


def _snapshot(
    url: str,
    *,
    target_id: str,
    auth_scope: str,
    status: int,
    method: str = "GET",
) -> ResponseSnapshot:
    return ResponseSnapshot(
        request_id=f"request-{method}-{status}",
        url=url,
        final_url=url,
        method=method,
        status=status,
        headers={},
        body=b"body",
        text="body",
        elapsed=0.0,
        target_id=target_id,
        auth_scope=auth_scope,
    )


def test_result_store_never_reuses_snapshot_across_auth_scopes() -> None:
    store = ResultStore()
    url = "https://example.test/private"
    first = _snapshot(url, target_id="account-a", auth_scope="account-a", status=200)
    second = _snapshot(url, target_id="account-b", auth_scope="account-b", status=403)
    store.add_snapshot(first)
    store.add_snapshot(second)

    assert store.get_snapshot(url) is None
    assert store.get_snapshot(url, target_id="account-a", auth_scope="account-a") is first
    assert store.get_snapshot(url, target_id="account-b", auth_scope="account-b") is second
    assert store.get_snapshot(url, target_id="account-a", auth_scope="account-b") is None


def test_result_store_separates_snapshots_by_method() -> None:
    store = ResultStore()
    url = "https://example.test/api/item"
    get = _snapshot(url, target_id="target-a", auth_scope="scope-a", status=200, method="GET")
    post = _snapshot(url, target_id="target-a", auth_scope="scope-a", status=201, method="POST")
    store.add_snapshot(get)
    store.add_snapshot(post)

    assert store.get_snapshot(url, target_id="target-a", auth_scope="scope-a", method="GET") is get
    assert store.get_snapshot(url, target_id="target-a", auth_scope="scope-a", method="POST") is post
    assert store.get_snapshot(url, target_id="target-a", auth_scope="scope-a") is None


def test_finding_semantic_key_includes_target_and_auth_scope() -> None:
    first = Finding(
        module="dirsearch",
        kind="path",
        target="https://example.test/private",
        target_id="account-a",
        auth_scope="account-a",
        evidence="status=200",
    )
    second = Finding(
        module="dirsearch",
        kind="path",
        target="https://example.test/private",
        target_id="account-b",
        auth_scope="account-b",
        evidence="status=200",
    )

    assert first.semantic_key != second.semantic_key


def test_selected_403_target_keeps_source_target_identity() -> None:
    context, executor, _, _ = pipeline.create_context(include_env=False, artifact_root=None)
    try:
        target = Target(
            url="https://example.test/",
            headers={"Authorization": "Bearer test"},
            scope="account-a",
        )
        context.options["components"] = ["dirsearch", "bypass403"]
        context.results.add_findings(
            [
                Finding(
                    module="dirsearch",
                    kind="path",
                    target="https://example.test/admin",
                    source_target=target.url,
                    auth_scope=target.auth_scope,
                    metadata={"status": 403, "auth_scope": target.auth_scope},
                )
            ]
        )

        selected = pipeline._targets_for_component("bypass403", [target], context)

        assert len(selected) == 1
        assert selected[0].target_id == target.identity
        assert selected[0].auth_scope == "account-a"
    finally:
        executor.close()


def test_403_handoff_uses_explicit_target_id_instead_of_guessing_scope() -> None:
    context, executor, _, _ = pipeline.create_context(include_env=False, artifact_root=None)
    try:
        first = Target(
            url="https://example.test/",
            target_id="account-a",
            headers={"Authorization": "Bearer A"},
            scope="shared-scope",
        )
        second = Target(
            url="https://example.test/",
            target_id="account-b",
            headers={"Authorization": "Bearer B"},
            scope="shared-scope",
        )
        context.options["components"] = ["dirsearch", "bypass403"]
        context.results.add_findings(
            [
                Finding(
                    module="dirsearch",
                    kind="endpoint",
                    target="https://example.test/one",
                    target_id="account-a",
                    source_target=first.url,
                    auth_scope=first.auth_scope,
                    metadata={"status": 403, "auth_scope": first.auth_scope},
                ),
                Finding(
                    module="dirsearch",
                    kind="endpoint",
                    target="https://example.test/two",
                    target_id="account-b",
                    source_target=second.url,
                    auth_scope=second.auth_scope,
                    metadata={"status": 403, "auth_scope": second.auth_scope},
                ),
            ]
        )

        selected = pipeline._targets_for_component("bypass403", [first, second], context)

        assert [(target.url, target.target_id) for target in selected] == [
            ("https://example.test/one", "account-a"),
            ("https://example.test/two", "account-b"),
        ]
    finally:
        executor.close()


def test_duplicate_explicit_target_id_cannot_merge_auth_contexts() -> None:
    targets = [
        Target(
            url="https://example.test/",
            target_id="shared",
            headers={"Authorization": "Bearer one"},
            scope="account-one",
        ),
        Target(
            url="https://example.test/",
            target_id="shared",
            cookies={"sid": "two"},
            scope="account-two",
        ),
    ]

    with pytest.raises(ConfigurationError, match="duplicate target_id"):
        pipeline._validate_target_identities(targets)


def test_sec_fetch_site_distinguishes_same_site_from_cross_site() -> None:
    assert fetch_site("https://app.example.test/api", "https://app.example.test/") == "same-origin"
    assert fetch_site("https://api.example.test/v1", "https://app.example.test/") == "same-site"
    assert fetch_site("https://example.test/api", "https://other.test/") == "cross-site"
    assert fetch_site("https://example.test/api", None) == "none"
