# Naming and compatibility

## Canonical names

| Surface | Canonical value | Notes |
|---|---|---|
| Brand | **SurfaceScope** | Use in prose, titles and reports |
| Distribution | `surfacescope` | PyPI/wheel/sdist name |
| Python import | `surfacescope` | No second namespace |
| Primary CLI | `surfacescope` | `surfacescope.cli:main` |
| Short CLI | `sscope` | Same entry point |
| Transitional CLI | `dsbp` | Deprecated; same entry point |
| Environment | `SURFACESCOPE_*` | `DSBP_*` is fallback only |
| Reports | `~/.surfacescope/reports` | Override with `--output` |

## Compatibility policy

- Components, scripts, CI and documentation must use the canonical names.
- `dsbp` and `DSBP_*` exist only to ease migration from version `0.1.x`.
- The complete public surface, SemVer rules, deprecation window and migration test
  requirements are defined in `docs/COMPATIBILITY.md`; this file only fixes the
  canonical names and the alias direction.
- Compatibility aliases must never fork behavior or maintain a second parser,
  executor, report writer or configuration loader.
- Remove `dsbp` and `DSBP_*` before `1.0`, in a dedicated breaking-change commit
  with changelog and migration notes.
- The old import `dirsearch_bypass403` is not aliased. Embedded callers must
  import `surfacescope`; keeping both import trees would hide stale dependencies.
- A deprecated name must state its first deprecated version, removal version or
  trigger, replacement and migration fixture in `CHANGELOG.md` and
  `docs/MIGRATION.md`. A warning without a migration path is not a deprecation.

## Repository identity

The local directory and GitHub remote may temporarily retain the historical
repository name. They are deployment metadata, not runtime API. If the remote
is renamed, update the local remote and clone instructions in one dedicated
change; do not rewrite commit history solely for branding.

The public repository should use the SurfaceScope name in its README, package
metadata and clone instructions. Old names may appear only in migration notes.

## Release tags and history

- Current release tags use `vMAJOR.MINOR.PATCH`; release candidates use
  `vMAJOR.MINOR.PATCH-rc.N` only after the release policy is explicitly extended.
- Old repository tags are not reused, moved or published as SurfaceScope releases.
- Do not rewrite the only local history in place. Keep the old repository as a
  backup and create a clean public snapshot or new repository when a lightweight
  public history is required.
- If a clean public history is required, prefer a reviewed mirror/new repository
  with a documented provenance mapping over an in-place destructive rewrite.
