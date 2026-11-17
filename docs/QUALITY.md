# Quality baseline

SurfaceScope uses three quality signals: unit/contract/integration tests, branch coverage,
and observable request budgets for the 403 pipeline. The local baseline is not a claim of
real-target effectiveness or production SLA.

## Test suite

The default test suite covers:

- CLI parsing and compatibility entry points;
- configuration and asset manifest validation;
- directory word expansion, status filtering and recursion budgets;
- soft-404 and response-difference classification;
- 403 candidate generation and loopback request budgets;
- JS, fingerprint, Swagger and Packer parsers;
- JSON/Markdown/HTML/CSV report writing;
- repository hygiene and Windows path handling.

Run it with:

```powershell
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\python -m pytest -q -p no:cacheprovider
```

The current source tree collects 255 tests and passes on Windows Python 3.10–3.14 and
Ubuntu/WSL Python 3.10.12. CI runs the required checks on Ubuntu with Python 3.12; the
wider Windows/Linux multi-version matrix is executed locally when needed, and a local
pass is not a substitute for the first successful Actions run.

## Coverage

The repository keeps a reproducible local baseline in `docs/QUALITY_BASELINE.json`:

- environment: Linux, Python 3.10.12;
- branch coverage: 79.53%;
- statements: 4,848; branches: 1,732;
- measured with `coverage[toml]` and branch coverage enabled.

Generate a new report with:

```powershell
.\.venv\Scripts\python -m coverage run -m pytest -q -p no:cacheprovider
.\.venv\Scripts\python -m coverage json -o artifacts/coverage.json
.\.venv\Scripts\python scripts/check_quality.py --coverage-json artifacts/coverage.json --baseline docs/QUALITY_BASELINE.json --json-out artifacts/quality-report.json
```

The checker allows 0.5 percentage points of test noise for the overall result and for
modules with at least 40 statements. A real change to the baseline must be reviewed and
recorded explicitly with `--record`; CI must not update the baseline automatically.

## 403 request budgets

The 403 loopback fixtures bind candidate generation to actual network requests. The
current baseline is:

| Scenario | Baseline requests |
|---|---:|
| uniform 403 denial | 29 |
| trailing-slash variant | 4 |
| X-Forwarded-For variant | 3 |

The checker compares `RequestExecutor.audit.counts()["network_sent"]` with the loopback
server's hit count. A change in either direction is a regression until reviewed.

## Performance baseline

The baseline also records local loopback latency for the same scenarios. It is used only
to detect a large regression in the same OS/Python environment; it is not a real-target
throughput claim. Cross-platform and real-target performance must be measured separately.

## Quality gate

Before a release candidate:

1. run the full test suite with warnings treated as errors;
2. regenerate coverage and compare it with `docs/QUALITY_BASELINE.json`;
3. verify 403 request counts with the loopback fixtures;
4. build wheel and sdist and run the package smoke tests;
5. run `scripts/check_docs.py`, `scripts/validate_assets.py`,
   `scripts/check_release_hygiene.py` and `git diff --check`;
6. confirm GitHub Actions is green on the target commit.

Do not commit `.coverage`, `artifacts/`, coverage JSON, quality reports, local virtual
environments or test caches.
