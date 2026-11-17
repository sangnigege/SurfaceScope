# Contributing to SurfaceScope

Thanks for improving SurfaceScope. Please keep changes focused, testable and safe for
authorized security testing.

## Before opening a change

- Use SurfaceScope only against systems you own or are explicitly authorized to test.
- Search existing issues and pull requests before opening a duplicate.
- For a security vulnerability in SurfaceScope itself, do not open a public issue; use
  the private reporting channel in `SECURITY.md`.
- For a behavior change, describe the user-visible effect and the compatibility impact.

## Development setup

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\python -m pytest -q
```

Linux/WSL uses `.venv/bin/python`.

## Pull requests

1. Keep one logical change per pull request.
2. Add or update tests for behavior changes and failure paths.
3. Update public documentation when CLI, config, report schema or defaults change.
4. Add a `CHANGELOG.md` entry for user-visible changes.
5. Run the checks in `docs/DEVELOPMENT.md` before requesting review.
6. Do not add component virtual environments, runtime clones, browser drivers, scanner
   binaries, generated reports or private maintenance files.

Compatibility aliases must delegate to the existing parser, executor, report writer and
configuration loader. Do not create a second implementation for compatibility.

## Review expectations

- Network tests use loopback fixtures only.
- Tests must not scan public or third-party targets.
- Findings from real targets must never be committed as fixtures or reports.
- Changes that alter request volume, headers, authentication scope or redirect behavior
  need an explicit test and a short risk note.

By contributing, you agree that your contribution can be distributed with the project
under its repository terms and that you have the right to submit it.
