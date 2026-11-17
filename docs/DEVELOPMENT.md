# Development

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\python -m pytest -q
```

Linux/WSL uses `.venv/bin/python`. Network tests use loopback fixtures only; never point a
test or CI run at a real target.

## Architecture

```text
CLI (argparse once)
  -> pipeline (composition root)
    -> adapter (protocol translation)
      -> component (parsing, matching and candidate logic)
        -> traffic executor (single HTTP boundary)
          -> requests.Session per target/auth scope/origin
```

Rules:

- parse command-line arguments once in `surfacescope.cli`;
- do not read `sys.argv` inside adapters or components;
- do not create a private `requests.Session` outside `traffic/`;
- do not write files into the current working directory;
- do not create component-specific reports, queues or budgets;
- keep `source_target` and `auth_scope` on findings;
- route all ordinary requests through `RequestExecutor`, including redirects and cache;
- keep optional active behavior explicit and fail closed.

## Code style

- Python `3.10` syntax and standard library where practical;
- `ruff` with the configuration in `pyproject.toml`;
- explicit UTF-8 and `pathlib` for file paths;
- no broad exception swallowing around network or parsing boundaries;
- tests and fixtures must state their evidence limits; a local loopback pass is not a
  real-target claim.

## Checks

```powershell
.\.venv\Scripts\python -W error -m compileall -q src scripts tests
.\.venv\Scripts\python -m pytest -q -p no:cacheprovider
.\.venv\Scripts\python -m ruff check src tests scripts
.\.venv\Scripts\python scripts/validate_assets.py
.\.venv\Scripts\python scripts/check_docs.py
.\.venv\Scripts\python scripts/check_worktree.py --json-out artifacts/worktree.json
git diff --check
```

Coverage and request-budget checks:

```powershell
.\.venv\Scripts\python -m coverage run -m pytest -q -p no:cacheprovider
.\.venv\Scripts\python -m coverage json -o artifacts/coverage.json
.\.venv\Scripts\python scripts/check_quality.py --coverage-json artifacts/coverage.json --baseline docs/QUALITY_BASELINE.json --json-out artifacts/quality-report.json
```

The quality baseline is environment-scoped. Do not compare Windows system Python results
with a Linux virtual environment without recording the environment change.

## Adding a component or option

1. define the public CLI/API behavior and its default;
2. add or update the shared model and report schema;
3. implement parsing in `components/` and protocol translation in `adapters/`;
4. route network work through `traffic/executor.py`;
5. add positive, negative and budget tests;
6. update the relevant public document and `CHANGELOG.md`;
7. run all checks and build the wheel/sdist.

Do not add a second parser, executor, report writer or configuration loader. Compatibility
entry points must delegate to the same CLI implementation.

## Packaging

```powershell
.\.venv\Scripts\python -m build
.\.venv\Scripts\python scripts/check_artifacts.py dist
.\.venv\Scripts\python -m twine check dist/*
```

Install the wheel and sdist outside the repository and verify:

```powershell
surfacescope --version
surfacescope --all --dry-run --no-env http://127.0.0.1:8000/
```

## Release flow

1. choose the release version and update `pyproject.toml` and `CHANGELOG.md`;
2. ensure the working tree is clean and all public docs reflect the actual behavior;
3. run the full local matrix, tests, coverage, asset validation and package smoke tests;
4. create a reviewed commit in a clean repository;
5. push to GitHub and wait for all Actions jobs to pass;
6. tag `vMAJOR.MINOR.PATCH` from that commit and attach wheel/sdist checksums.

Do not publish a tag from a dirty worktree or reuse a historical tag.

## First public repository

When the project is published under a new repository name, create a clean snapshot instead
of pushing the legacy history. `.gitignore` prevents new private or generated files from
being tracked, but it does not remove objects that already exist in Git history.

1. Copy only the reviewed public tree into a new directory, excluding `.git/`,
   private maintenance docs, local agent instruction files, virtual environments, caches,
   build outputs and reports.
2. Run the full checks from that snapshot, then create the first commit on `main`.
3. Add the new GitHub repository as `origin`, push `main`, and wait for all Actions jobs.
4. Create `v0.2.0` only after the first green CI run, then attach the wheel, sdist and
   SHA-256 checksums to the GitHub release.

Do not rewrite the only copy of an existing repository with `git filter-repo`, BFG or a
destructive garbage collection. Keep the old repository as a private/local backup if its
history still has value.
