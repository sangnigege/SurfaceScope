# Compatibility

SurfaceScope `0.2.0` is a pure-Python package. It does not require a compiler, a Rust
toolchain, a browser driver or a component-local virtual environment.

## Python

| Item | Value |
|---|---|
| Declared minimum | Python `3.10` |
| Verified locally | Windows Python `3.10`–`3.14`; Linux/WSL Python `3.10` and `3.14` |
| CI matrix | Ubuntu Linux, Python `3.12` (required release checks; current `main` is green) |
| Package type | `py3-none-any` wheel |
| Extensions | No C/Rust extension modules |

Python 3.10 is in its upstream end-of-life window. It remains supported in 0.2 for
existing users, but future releases may raise the minimum after a documented migration
window. Support for 3.8 and 3.9 is not provided.

## Operating systems

| Environment | Status | Notes |
|---|---|---|
| Windows 11 | Verified locally | Python 3.10–3.14, 256 tests on each version |
| Linux/WSL | Verified locally | Ubuntu/WSL Python 3.10.12 and 3.14.10, 256 tests; CI runs the required checks on Python 3.12 |
| macOS | Not verified | Code is platform-neutral, but no native macOS validation is claimed |

Platform code uses `pathlib`, explicit UTF-8, `sys.executable` and temporary directories.
Network tests use loopback fixtures only. System proxy variables are not read implicitly;
use an explicit `--proxy` when required.

## Runtime dependencies

| Package | Purpose |
|---|---|
| `requests` | HTTP transport |
| `beautifulsoup4` | HTML/JS extraction |
| `PyYAML` | OpenAPI YAML |
| `tomli` | TOML parser on Python < 3.11 |

Build-time dependencies are `setuptools>=77` and `wheel`. Development dependencies are
installed with `.[dev]` and include `pytest`, `coverage`, `ruff`, `build` and `twine`.

The runtime does not use `pkg_resources`, `distutils`, Selenium, ChromeDriver,
`docx2pdf`, Deno, Node, Rust or component venvs.

## Public compatibility surfaces

| Surface | Compatibility rule |
|---|---|
| Python import | `surfacescope` is the only package namespace; the old `dirsearch_bypass403` import is not aliased |
| CLI | `surfacescope`, `sscope` and transitional `dsbp` share the same `surfacescope.cli:main` |
| JSON report | Readers must tolerate unknown fields; removing or changing a field requires a new `schema_version` |
| Config | New optional keys are compatible; deleting keys or changing defaults requires a migration note |
| Environment | New variables use `SURFACESCOPE_*`; `DSBP_*` is fallback-only |

### Versioning

- Releases use PEP 440 versions; Git release tags use `vMAJOR.MINOR.PATCH`.
- During `0.x`, minor releases may contain breaking changes if `CHANGELOG.md` and
  `docs/MIGRATION.md` document the migration.
- Patch releases must not intentionally break a public surface.
- Deprecations must name the replacement, the first affected version and the removal
  condition. Removing an alias or changing a public default requires a migration test.
- Aliases must reuse the same parser, executor, report writer and configuration loader;
  compatibility must not create a second implementation.

## Packaging

- Distribution name: `surfacescope`
- Import name: `surfacescope`
- Commands: `surfacescope`, `sscope`, `dsbp`
- Default artifact: pure-Python wheel and sdist
- Package data: configuration, request profiles, wordlists, fingerprints and payloads
- No browser driver, external scanner binary, component checkout or nested `.git` is
  included in the wheel

Build and smoke checks:

```powershell
python -m build
python scripts/check_artifacts.py dist
python -m twine check dist/*
python -m venv .wheel-smoke
.\.wheel-smoke\Scripts\python -m pip install dist\*.whl
.\.wheel-smoke\Scripts\surfacescope --dry-run --no-env http://127.0.0.1:8000/
```

Linux/WSL uses `.wheel-smoke/bin/python` and `.wheel-smoke/bin/surfacescope`.

## Request identity

The default request profile models a modern desktop Chromium application-layer request:

- fixed User-Agent and Client Hints;
- purpose-specific `Accept` headers;
- generated `Sec-Fetch-*` headers;
- authentication headers removed on cross-origin redirects;
- no random User-Agent or header shuffling;
- no implicit proxy discovery.

This is not a claim of TLS or HTTP/2 fingerprint equivalence. A higher-fidelity transport
must be a separately documented and tested backend.

## Known limitations

- dirsearch compatibility is the documented subset in `docs/DIRSEARCH_PARITY.md`, not
  every upstream CLI option or output mode;
- Packer analysis is not a full dynamic equivalent of every upstream vulnerability type;
- real-target 403 hit rates and false-positive rates require target-specific validation;
- macOS is not verified; GitHub Actions currently covers Ubuntu Linux Python 3.12,
  while the wider version matrix is verified locally;
- Raw absolute-URI requests, duplicate request headers, CL/TE desynchronization and
  HTTP/1.0 downgrade are outside the default executor boundary;
- reproducible byte-for-byte builds and SBOM/signature publication are not yet claimed.
