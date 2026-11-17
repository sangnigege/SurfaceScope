from __future__ import annotations

from types import SimpleNamespace
from urllib.parse import urlsplit

import surfacescope.adapters.dirsearch_adapter as dirsearch_adapter_module
from surfacescope.adapters.dirsearch_adapter import DirsearchAdapter
from surfacescope.components.dirsearch import expand_words, word_variants
from surfacescope.errors import BudgetExceeded
from surfacescope.models import ResponseSnapshot, Target
from surfacescope.result_store import ResultStore


class _Audit:
    def __init__(self) -> None:
        self.network = 0

    def counts(self) -> dict[str, int]:
        return {"network_sent": self.network}


class _Executor:
    def __init__(
        self,
        responses: dict[str, tuple[int, str, dict[str, str]]],
        wildcard_responses: list[tuple[int, str, dict[str, str]]] | None = None,
    ) -> None:
        self.responses = responses
        self.wildcard_responses = wildcard_responses or []
        self.wildcard_calls = 0
        self.audit = _Audit()
        self.urls: list[str] = []

    def get(self, url: str, **_kwargs):
        self.audit.network += 1
        self.urls.append(url)
        path = urlsplit(url).path
        if "/.surfacescope-" in path:
            if self.wildcard_responses:
                index = min(self.wildcard_calls, len(self.wildcard_responses) - 1)
                status, text, headers = self.wildcard_responses[index]
                self.wildcard_calls += 1
            else:
                status, text, headers = 404, "not found", {}
        else:
            status, text, headers = self.responses.get(path, (404, "not found", {}))
        body = text.encode()
        return ResponseSnapshot(
            request_id="test",
            url=url,
            final_url=url,
            method="GET",
            status=status,
            headers={"Content-Type": "text/plain", **headers},
            body=body,
            text=text,
            elapsed=0.0,
        )

    def run_many(self, worker, items, *, max_workers=25):
        for item in items:
            yield worker(item)

    def budget_usage(self, _scope: str) -> dict:
        return {"configured": True}


class _BudgetExecutor(_Executor):
    def __init__(self, responses, budget_limit: int, wildcard_responses=None) -> None:
        super().__init__(responses, wildcard_responses)
        self.budget_limit = budget_limit

    def get(self, url: str, **kwargs):
        if self.audit.network >= self.budget_limit:
            raise BudgetExceeded("test request budget exhausted")
        return super().get(url, **kwargs)


class _Wordlists:
    def __init__(self, words: list[str], mapping: dict[str, list[str]] | None = None) -> None:
        self.words = words
        self.mapping = mapping or {}

    def lines(self, asset_id: str) -> list[str]:
        return list(self.mapping.get(asset_id, self.words))

    def status_suffix_filters(self, _asset_id: str) -> dict[int, tuple[str, ...]]:
        return {}


class _Config:
    def __init__(self, **dirsearch) -> None:
        self.dirsearch = {
            "wordlist": "test",
            "extensions": [],
            "force_extensions": [],
            "exclude_extensions": [],
            "exclude_redirects": [],
            "exclude_statuses": [],
            "min_response_size": 0,
            "max_response_size": 0,
            "max_candidates": 0,
            "max_jobs": 200000,
            "max_time": 0,
            "recursive": False,
            "max_depth": 1,
            "max_recursive_dirs": 100,
            "include_statuses": [200, 204, 301, 302, 307, 308, 401, 403],
            **dirsearch,
        }

    def section(self, name: str):
        if name == "dirsearch":
            return self.dirsearch
        if name == "run":
            return {"threads": 2}
        return {}


def _context(executor: _Executor, words: list[str], **config) -> SimpleNamespace:
    return SimpleNamespace(
        config=_Config(**config),
        executor=executor,
        results=ResultStore(),
        wordlists=_Wordlists(words),
        profile=SimpleNamespace(id="test-profile"),
    )


def test_word_variants_cover_percent_ext_force_and_exclude() -> None:
    assert word_variants("api.%EXT%", ["json", "xml"], [], []) == ["api.json", "api.xml"]
    assert word_variants("api.%EXT%", [], [], []) == []
    assert word_variants("api.php", [], [], ["php"]) == []
    assert word_variants("admin", [], ["php"], []) == ["admin", "admin/", "admin.php"]
    assert word_variants("admin.php", [], ["php"], []) == ["admin.php"]
    assert word_variants("admin/", [], ["php"], []) == ["admin/"]
    assert word_variants("/admin", [], [], []) == ["admin"]
    assert word_variants("# comment", [], [], []) == []
    assert word_variants("secret.php?x=1", [], [], ["php"]) == []
    assert expand_words(["a.%EXT%"], ["js"], ["api/"], [".bak"]) == ["api/a.js", "a.js.bak"]


def test_target_profile_merges_asset_specific_paths() -> None:
    executor = _Executor({})
    context = _context(executor, [])
    context.wordlists = _Wordlists(
        ["base-path"],
        {"wordlist.paths.dicc": ["base-path"], "wordlist.targets.grafana": ["grafana-path"]},
    )

    result = DirsearchAdapter().scan(
        context,
        [Target(url="http://example.test/")],
        {"target_profiles": ["grafana"]},
    )

    assert "http://example.test/grafana-path" in executor.urls
    assert "http://example.test/base-path" in executor.urls
    assert result.stats["target_profiles"] == ["grafana"]


def test_scan_applies_status_redirect_size_and_wildcard_filters() -> None:
    executor = _Executor(
        {
            "/secret": (200, "secret body", {}),
            "/admin": (403, "denied", {}),
            "/moved": (301, "moved", {"Location": "/login"}),
            "/large": (200, "x" * 500, {}),
            "/small": (200, "x", {}),
        }
    )
    context = _context(
        executor,
        ["secret", "admin", "moved", "large", "small", "missing"],
        exclude_statuses=[403],
        exclude_redirects=["/login"],
        min_response_size=2,
        max_response_size=100,
    )

    result = DirsearchAdapter().scan(context, [Target(url="http://example.test/", scope="http://example.test")], {})

    assert [finding.target for finding in result.findings] == ["http://example.test/secret"]
    assert result.findings[0].method == "GET"
    assert result.findings[0].source_target == "http://example.test/"
    assert result.findings[0].metadata["auth_scope"] == "http://example.test"
    assert result.findings[0].metadata["status"] == 200


def test_scan_uses_second_wildcard_baseline_for_soft_404_variation() -> None:
    executor = _Executor(
        {
            "/soft": (200, "custom not found page", {}),
            "/secret": (200, "secret body", {}),
        },
        wildcard_responses=[
            (404, "not found", {}),
            (200, "custom not found page", {}),
        ],
    )

    result = DirsearchAdapter().scan(
        _context(executor, ["soft", "secret"]),
        [Target(url="http://example.test/")],
        {},
    )

    assert [finding.target for finding in result.findings] == ["http://example.test/secret"]
    assert executor.wildcard_calls == 2


def test_max_candidates_limits_work_before_baselines_and_probes() -> None:
    executor = _Executor({f"/p{i}": (200, "ok", {}) for i in range(5)})

    result = DirsearchAdapter().scan(
        _context(executor, [f"p{i}" for i in range(5)], max_candidates=2),
        [Target(url="http://example.test/")],
        {},
    )

    assert result.stats["candidates"] == 2
    assert result.stats["tested"] == 2
    assert len(result.findings) == 2
    assert len(executor.urls) == 4


def test_scan_marks_blocked_paths_for_403_handoff() -> None:
    executor = _Executor({"/admin": (403, "denied", {})})
    context = _context(executor, ["admin", "missing"])
    adapter = DirsearchAdapter()

    result = adapter.scan(context, [Target(url="http://example.test/", scope="http://example.test")], {})

    assert [finding.target for finding in result.findings] == ["http://example.test/admin"]
    assert result.findings[0].metadata["status"] == 403
    assert result.stats["blocked"] == 1


def test_scan_preserves_iis_alternate_data_stream_paths() -> None:
    executor = _Executor({"/index.php::$DATA": (200, "source", {})})

    result = DirsearchAdapter().scan(
        _context(executor, ["index.php::$DATA"]),
        [Target(url="http://example.test/")],
        {},
    )

    assert executor.urls[-1] == "http://example.test/index.php::$DATA"
    assert [finding.target for finding in result.findings] == [
        "http://example.test/index.php::$DATA"
    ]
    assert result.errors == []


def test_scan_honors_job_budget_and_reports_truncation() -> None:
    executor = _Executor({f"/p{i}": (200, "ok", {}) for i in range(10)})
    context = _context(executor, [f"p{i}" for i in range(10)], max_jobs=3)

    result = DirsearchAdapter().scan(context, [Target(url="http://example.test/")], {})

    assert len(result.findings) == 3
    assert result.stats["job_limit_reached"] is True
    assert result.stats["tested"] == 3


def test_duplicate_targets_share_baseline_and_do_not_duplicate_probes() -> None:
    executor = _Executor({"/one": (200, "ok", {})})
    target = Target(url="http://example.test/", scope="account-a")

    result = DirsearchAdapter().scan(_context(executor, ["one"]), [target, target], {})

    assert len(result.findings) == 1
    assert len(executor.urls) == 3
    assert result.stats["targets"] == 2
    assert result.stats["network_requests"] == 3


def test_recursive_scan_is_bounded_by_depth() -> None:
    executor = _Executor(
        {
            "/dir/": (200, "directory", {}),
            "/dir/child/": (200, "child directory", {}),
        }
    )
    context = _context(executor, ["dir/", "child/"])

    result = DirsearchAdapter().scan(
        context,
        [Target(url="http://example.test/")],
        {"recursive": True, "max_depth": 2},
    )

    assert any(finding.target == "http://example.test/dir/" for finding in result.findings)
    assert result.stats["recursive_directories"] == 2


def test_recursive_scan_uses_two_soft_404_baselines_per_directory() -> None:
    executor = _Executor(
        {
            "/dir/": (200, "directory", {}),
            "/dir/secret": (200, "custom not found page", {}),
        },
        wildcard_responses=[
            (200, "custom not found page", {}),
            (200, "custom not found page", {}),
        ],
    )

    result = DirsearchAdapter().scan(
        _context(executor, ["dir/", "secret"]),
        [Target(url="http://example.test/")],
        {"recursive": True, "max_depth": 2},
    )

    assert executor.wildcard_calls == 4
    assert [finding.target for finding in result.findings] == ["http://example.test/dir/"]


def test_scan_stops_when_shared_request_budget_is_exhausted() -> None:
    executor = _BudgetExecutor({"/one": (200, "ok", {})}, budget_limit=1)

    result = DirsearchAdapter().scan(
        _context(executor, ["one", "two"]),
        [Target(url="http://example.test/")],
        {},
    )

    assert result.stats["budget_stopped"] is True
    assert result.stats["tested"] == 0
    assert executor.audit.network == 1


def test_scan_marks_time_limit_between_probe_batches(monkeypatch) -> None:
    executor = _Executor({f"/p{i}": (200, "ok", {}) for i in range(5)})
    clock = iter([0.0, 0.0, 100.0])
    monkeypatch.setattr(
        dirsearch_adapter_module,
        "time",
        SimpleNamespace(monotonic=lambda: next(clock)),
    )

    result = DirsearchAdapter().scan(
        _context(executor, [f"p{i}" for i in range(5)], max_time=5.0),
        [Target(url="http://example.test/")],
        {},
    )

    assert result.stats["time_limit_reached"] is True
    assert result.stats["tested"] <= 2
