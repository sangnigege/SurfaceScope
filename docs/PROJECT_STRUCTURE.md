# Project structure

SurfaceScope uses one Python package, one HTTP boundary and one report layer. This
document describes the files distributed in the public repository.

## Repository layout

```text
README.md
CHANGELOG.md
CONTRIBUTING.md
CODE_OF_CONDUCT.md
SECURITY.md
NOTICE.md
THIRD_PARTY_LICENSES.txt
pyproject.toml
.editorconfig
.gitattributes
.gitignore
src/
tests/
scripts/
docs/
.github/
dirsearch.py
single_403pass.py
swagger.py
```

## Package layout

```text
src/surfacescope/
  __init__.py __main__.py cli.py pipeline.py context.py
  models.py config.py assets.py artifacts.py result_store.py
  errors.py logging.py capabilities.py urls.py legacy.py _compat.py console.py
  adapters/
    base.py
    dirsearch_adapter.py jsfinder_adapter.py finger_adapter.py
    bypass403_adapter.py swagger_adapter.py packer_adapter.py
  components/
    dirsearch/      # dictionary expansion
    jsfinder/       # static URL and HTML extraction
    finger/         # rule matching and favicon hashing
    bypass403/      # candidate catalog and mode policies
    swagger/        # Swagger 2 / OpenAPI 3 parsing
    packer/         # analyzer, secrets, surface and active checks
  traffic/
    profiles.py executor.py cache.py snapshots.py audit.py
  quality/qc.py
  reporting/schema.py reporting/writer.py
  assets/
    manifest.json
    config/ profiles/ fingerprints/ blacklists/ wordlists/ bypass403/
```

Boundaries:

- `adapters/` translates component behavior into the shared pipeline; it does not read
  `sys.argv`, create a private session or write reports;
- `components/` contains parsing, matching and candidate algorithms; it does not send
  network requests;
- `traffic/` is the only HTTP boundary and owns request profiles, redirects, cache and
  audit counts;
- `reporting/` is the only report writer;
- `quality/` owns shared response-difference and soft-404 decisions;
- `assets/` is read-only at runtime and is validated through `assets/manifest.json`.

## Public documentation

Public documentation lives directly under `docs/`. It covers installation, CLI, config,
components, compatibility, quality, assets, migration, naming, troubleshooting, security
and development.

Planning notes, evidence logs, candidate records and workspace-specific paths are not
part of the distributed documentation. They are excluded from the public tree by
`.gitignore` and must not be committed.

## Tests

```text
tests/
  unit/           # models, parsers, matching, QC, reporting, executor, 403
  contract/       # CLI, config, legacy entry points, transport boundaries
  integration/    # loopback 403 and Swagger safety
  hygiene/        # one .git, no retired binaries, ignore rules, entry-point shims
```

Network tests use loopback servers. Do not scan real targets in tests or CI. The suite
collects 255 tests at the time of this release.

## Assets

`src/surfacescope/assets/manifest.json` is the source of truth for packaged data. Each
active asset records its path, hash, size, line/item count, consumer and source metadata.

Asset rules:

- general paths, product-specific paths, HTTP status noise, credentials, fingerprints and
  configuration are different asset classes and must not be combined merely to reduce
  file count;
- duplicate physical lines are removed only for wordlist assets;
- JSON rule sets and fingerprints are deduplicated by structure and logical identity;
- the wheel must include all declared assets and no undeclared binaries;
- `python scripts/validate_assets.py` must pass before a build.

## Hygiene

Generated files and local workspaces are ignored:

- `.venv/`, `venv/` and `env/`;
- `build/`, `dist/`, `sdist/`, `*.egg-info/` and wheels;
- `__pycache__/`, `.pytest_cache/`, `.ruff_cache/`, `.mypy_cache/` and coverage files;
- `artifacts/`, reports, SQLite files, logs and temporary downloads;
- private maintenance docs, agent scratch and editor metadata.

The repository should have exactly one root `.git`. Do not add nested checkouts, component
repositories, browser drivers, scanner binaries or vendored upstream trees.

## Git history and releases

Use a clean snapshot or a new repository for the public release. Do not publish historical
ChromeDriver, EHole, report, document or cache objects, and do not reuse old repository
tags such as `v`, `v0.2`, `v3.1` or `中秋特别版`. Public release tags should use
`vMAJOR.MINOR.PATCH` and point to a reviewed commit with a clean working tree.

`.gitignore` only prevents new files from being tracked; it cannot remove existing objects
from Git history. A new repository with one reviewed initial commit is the lowest-risk
publication path. If the legacy history must be preserved, rewrite it only in a separate
clone after taking a complete backup and revalidate every tag and release artifact.
