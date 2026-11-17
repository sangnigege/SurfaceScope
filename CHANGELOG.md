# Changelog

All notable user-facing changes to SurfaceScope are recorded here. The format follows
the spirit of Keep a Changelog, and versions use PEP 440.

## Unreleased

### Added

- Streaming terminal output: the banner and each stage's results are printed as soon as the
  stage finishes instead of appearing all at once at the end.
- `finger` findings render as an aligned table (`STATUS / CONF / TECHNOLOGY / SOURCES /
  EVIDENCE / TARGET`); `dirsearch` findings print paths relative to their target.
- Live progress heartbeat on stderr, enabled by default on a TTY (`--no-progress`,
  `--progress-interval`).
- `--check-update` reports the newest published tag and the upgrade command for the detected
  install method; it never installs anything.
### Changed

- Consolidated `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` and the security policy under
  `.github/`; the repository root now keeps only `README.md`, `CHANGELOG.md` and
  `NOTICE.md`.
- Dropped the third-party license file in favour of the attribution table in `NOTICE.md`.
- Removed the optional container build and the CodeQL workflow from the public delivery
  surface.
- Rewrote the README with a capability map, scenario table, configuration summary and a
  documentation index.
- Dropped the README version marker; `pyproject.toml` is the single source of truth and
  `check_docs` only cross-checks the marker when a README still declares one.
- Merged the code of conduct into `.github/SECURITY.md` and the pull request template into
  `.github/CONTRIBUTING.md`, leaving four community files under `.github/`.
- Made the `Path.cwd().parent` temporary fallback opt-in via
  `SURFACESCOPE_ALLOW_CWD_PARENT_TMP=1`, so restricted environments no longer scatter
  `surfacescope-*` directories beside the project by default.

### Fixed

- `--list-components` now prints only the six canonical components in pipeline order; the
  historical `bypass` alias no longer appears as a separate entry.
- `--components` help points at the one-command recipes in `docs/MIGRATION.md`, which now
  maps each removed root script to a single invocation.

- README upgrade instructions now separate `git+https://` installs (need
  `--force --reinstall` / `pipx reinstall`) from index-based installs.
### Removed

- Removed the root compatibility shims `dirsearch.py`, `single_403pass.py` and
  `swagger.py` together with the `surfacescope.legacy` module; `surfacescope`, `sscope`
  and `dsbp` are the only supported entry points.
## 0.2.0 - 2026-11-16

### Added

- Unified `surfacescope`, `sscope` and transitional `dsbp` command entry points.
- Single `RequestExecutor` with shared request budgets, caching, authentication scope,
  redirect handling and a browser-like request profile.
- Unified `Finding` model and JSON, Markdown, HTML and CSV report writers.
- 403/401 review modes: `quick`, `fast`, `balanced` and `full`.
- Pure-Python Swagger/OpenAPI discovery and safe request generation.
- Passive-first Packer/webpack surface, secret and CORS analysis.
- `--all` for enabling every stage with safe defaults.
- Package-owned asset manifest for wordlists, fingerprints, profiles and configuration.

### Changed

- Renamed the project from `dirsearch_bypass403` to **SurfaceScope**.
- Replaced component-specific environments and runtime directories with one Python
  package and one project environment.
- Moved reports to `~/.surfacescope/reports` unless `--output` is supplied.
- Default 403 review uses `fast` and only expands after a meaningful response difference.
- Default request identity is a fixed Chrome-for-Testing application-layer profile rather
  than per-component random or tool-specific headers.

### Fixed

- Removed runtime dependencies on ChromeDriver, EHole, Selenium, `docx2pdf`, Deno/Node
  and component-local virtual environments.
- Removed fixed working-directory queues, SQLite stage files and generated report files.
- Added explicit soft-404, authentication-scope, redirect, budget and cross-origin controls.

## 0.1.0 - 2026-11-16

### Added

- Initial Python package layout under `src/surfacescope`.
- Directory discovery, JS extraction and fingerprint matching.
- Compatibility shims for the old `dirsearch.py`, `single_403pass.py` and `swagger.py`
  entry points.
- Windows/Linux packaging and test foundation.
