# dirsearch 0.4.3 compatibility

SurfaceScope keeps the high-value discovery behavior of dirsearch 0.4.3 without
vendoring its source, private scheduler, queue files or console reporter. The correct
description is **dirsearch 0.4.3-compatible subset**, not byte-for-byte vendoring.

Upstream reference:

| Item | Value |
|---|---|
| Repository | `https://github.com/maurosoria/dirsearch` |
| Tag | `v0.4.3` |
| Commit | `7e3f64bcbaf7b5abcc41601d318acf637951b2de` |

The upstream source was used for behavior comparison and fixture design. The runtime does
not import, clone or read an upstream checkout.

## Supported discovery behavior

The default wordlist is a curated union of high-value dirsearch 0.4.3 paths, a small
0.5.0 delta and SurfaceScope-maintained modern entries. It is normalized to LF, stripped
of empty lines, deduplicated and checked by `tests/unit/test_assets.py`.

| Behavior | SurfaceScope behavior |
|---|---|
| Leading slash | remove one leading `/` |
| Empty lines and comments | skip empty values and lines starting with `#` after path cleanup |
| `%EXT%` | case-insensitive replacement for each selected extension |
| Force extensions | append `line/` and `line.ext` for extensionless, non-directory entries |
| Exclude extensions | check suffix after query/fragment cleanup; case-insensitive |
| Prefix/suffix expansion | generate separate sets, not a Cartesian product |
| Ordering | preserve first occurrence and deduplicate |
| Whitespace | trim wordlist entries by default |

## Adapter behavior

| Behavior | SurfaceScope behavior |
|---|---|
| Status filtering | include/exclude lists and ranges such as `200-204` |
| Response length | minimum and maximum filters |
| Soft-404 | two randomized baselines per target/recursive root, including recursive roots |
| Recursion | only directory findings, bounded by depth, directory count and job budget |
| Budgets | candidate limit, job limit and shared request budget; explicit `budget_stopped` result |
| 403 handoff | typed finding handoff through `ResultStore`, not a CWD queue file |
| HTTP | one executor with profile, auth scope, redirects, cache and audit counts |
| Reports | one reporting schema for JSON, Markdown, HTML and CSV |
| Path handling | explicit base/path joining; IIS ADS paths such as `index.php::$DATA` are preserved |

Status range example:

```powershell
surfacescope --include-statuses 200-204,301,304 --exclude-statuses 400,404-410 https://example.com/
```

## Known differences

Unregistered options are rejected by argparse. They are not silently accepted as
placeholders.

| Upstream option or behavior | Status | Reason |
|---|---|---|
| `-f/--force-extensions` boolean with `-e` | Different | SurfaceScope uses `--force-extensions LIST`; `-e` remains the extension set |
| `--overwrite-extensions` | Not supported | Requires a separate extension replacement policy and fixtures |
| `--remove-extensions` | Not supported | Original wordlist suffixes are preserved |
| `--lowercase`, `--uppercase`, `--capitalization` | Not supported | Original casing is preserved |
| `--recursion-status-codes` | Not supported | Recursion is based on directory findings and depth |
| `--deep-recursive`, `--force-recursive` | Not supported | Different recursion and budget model |
| `--subdirs`, `--exclude-subdirs` | Not supported | Explicit wordlist/profile selection is used instead |
| `--crawl` | Not supported | JS/Packer static extraction is used; no browser crawler |
| `--skip-on-status` | Not supported | Status filtering exists, but not upstream short-circuit semantics |
| `--exclude-sizes` | Not supported | Minimum/maximum response length is provided instead |
| Multiple `-w` wordlists | Not supported | One wordlist asset plus target profiles keeps inputs bounded |
| Upstream session/resume/pickle | Not supported | The shared executor/store owns run state |
| Upstream output/terminal progress | Not supported | The shared reporting layer owns all outputs |
| Raw absolute-URI, duplicate headers, HTTP/1.0, CL/TE | Outside this compatibility boundary | Rejected by the default transport; no silent emulation |

## Local comparison

On a loopback server that returns 404 for every path, a local Windows 11 / Python 3.12.2
comparison used the same 9,522-line wordlist, `php,aspx,jsp,html,js` extensions and 25
threads:

| Implementation | Requests | Time | Throughput |
|---|---:|---:|---:|
| SurfaceScope | 11,611 | 11.429 s | about 1,015.9 req/s |
| dirsearch 0.4.3 | 11,620 | 21.938 s | about 529.7 req/s |

This measures local scheduling and connection reuse only. It is not a real-target speed
claim and does not imply full upstream feature parity.
