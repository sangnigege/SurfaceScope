"""Command-line entry point.

Argument parsing happens exactly once here. The resulting typed values are
translated into one ``ScanContext`` by the pipeline; adapters never inspect
``argv``.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from . import __version__
from .assets import AssetManifest
from .components.bypass403.catalog import MODE_POLICIES
from .console import write_scan_result
from .errors import AssetError, ConfigurationError, RequestError
from .models import Target, validate_request_headers
from .pipeline import ADAPTERS, run_scan, validate_runtime
from .traffic.profiles import RequestProfileRegistry

DEFAULT_COMPONENTS = "dirsearch,jsfinder,finger"
ALL_COMPONENTS = "dirsearch,jsfinder,finger,bypass403,swagger,packer"


def _configure_redirected_output() -> None:
    """Use UTF-8 for Windows pipes/files so non-ASCII report paths survive."""

    if os.name != "nt" or os.environ.get("PYTHONIOENCODING"):
        return
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None or bool(getattr(stream, "isatty", lambda: False)()):
            continue
        encoding = str(getattr(stream, "encoding", "")).lower().replace("-", "")
        if encoding == "utf8":
            continue
        with contextlib.suppress(OSError, ValueError):
            reconfigure(encoding="utf-8", errors="backslashreplace")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="surfacescope",
        description="SurfaceScope: unified web attack surface discovery, fingerprint, JS, 403, Swagger and Packer analysis.",
    )
    parser.add_argument("targets", nargs="*", help="target URL(s)")
    parser.add_argument("-u", "--url", action="append", default=[], help="target URL; repeatable")
    parser.add_argument("-U", "--url-file", help="file containing one target URL per line")
    parser.add_argument(
        "-T",
        "--target-file",
        help="JSON file with target objects (url, scope, headers, cookies)",
    )
    parser.add_argument(
        "--components",
        default=None,
        help=(
            f"comma-separated components; default: {DEFAULT_COMPONENTS}; "
            f"explicit value overrides --all"
        ),
    )
    parser.add_argument(
        "-a",
        "--all",
        action="store_true",
        help=(
            "enable every stage with safe defaults: dirsearch,jsfinder,finger,bypass403,swagger,packer; "
            "403 uses the bounded fast mode; unsafe writes, SQLi, source maps and active Packer probes remain opt-in"
        ),
    )
    parser.add_argument("--bypass", action="store_true", help="force-enable the 403 review stage (also included by --all)")
    parser.add_argument("--no-bypass", action="store_true", help="disable the 403 stage")
    parser.add_argument("--swagger", action="store_true", help="enable Swagger/OpenAPI discovery")
    parser.add_argument("--swagger-unsafe", action="store_true", help="allow declared POST/PUT/PATCH/DELETE operations")
    parser.add_argument("--swagger-external", action="store_true", help="allow OpenAPI servers on external hosts")
    parser.add_argument("--packer", action="store_true", help="enable Packer/webpack analysis")
    parser.add_argument("--packer-probe", action="store_true", help="GET-probe extracted API paths")
    parser.add_argument(
        "--packer-context-probes",
        action="store_true",
        help="also GET-probe methods inferred from nearby source context",
    )
    parser.add_argument(
        "--packer-active",
        action="store_true",
        help="enable CORS checks and authenticated-versus-anonymous probes",
    )
    parser.add_argument("--packer-sqli", action="store_true", help="send conservative SQL quote probes to GET parameters")
    parser.add_argument("--packer-sourcemaps", action="store_true", help="fetch and inspect source maps")
    parser.add_argument("--no-packer", action="store_true", help="disable the Packer stage")
    parser.add_argument("--no-swagger", action="store_true", help="disable the Swagger stage")
    parser.add_argument("--wordlist", help="asset ID for the path wordlist")
    parser.add_argument(
        "--target-profile",
        action="append",
        default=[],
        help="target-specific path profile(s): grafana, spring-boot, actuator",
    )
    parser.add_argument("-e", "--extensions", default="", help="comma-separated extensions")
    parser.add_argument("--force-extensions", default="", help="append these extensions to every word")
    parser.add_argument("--exclude-extensions", default="", help="drop words ending in these extensions")
    parser.add_argument("--exclude-redirects", default="", help="comma-separated redirect Location regexes")
    parser.add_argument("--include-statuses", default="", help="comma-separated accepted HTTP statuses")
    parser.add_argument("--exclude-statuses", default="", help="comma-separated rejected HTTP statuses")
    parser.add_argument("--min-response-size", type=int, default=None)
    parser.add_argument("--max-response-size", type=int, default=None)
    parser.add_argument("--max-candidates", type=int, default=None)
    parser.add_argument("--max-jobs", type=int, default=None)
    parser.add_argument("--max-time", type=float, default=None, help="dirsearch stage time budget in seconds")
    parser.add_argument("--prefixes", default="", help="comma-separated path prefixes")
    parser.add_argument("--suffixes", default="", help="comma-separated path suffixes")
    parser.add_argument("--recursive", action="store_true", help="enable directory recursion")
    parser.add_argument("--max-depth", type=int, default=None)
    parser.add_argument("--threads", type=int, default=None)
    parser.add_argument("--timeout", type=float, default=None)
    parser.add_argument("--max-response-bytes", type=int, default=None)
    parser.add_argument("--profile", help="request profile ID")
    parser.add_argument("--proxy", help="HTTP(S) proxy URL")
    parser.add_argument("--header", action="append", default=[], help="extra header: 'Name: value'")
    parser.add_argument("--cookie", default="", help="cookie header value, e.g. 'a=b; c=d'")
    tls = parser.add_mutually_exclusive_group()
    tls.add_argument(
        "--insecure",
        action="store_true",
        help="disable TLS certificate verification (explicit opt-in for authorized self-signed targets)",
    )
    tls.add_argument(
        "--verify-tls",
        action="store_true",
        default=None,
        help="verify TLS certificates (default; kept for script compatibility)",
    )
    parser.add_argument("--follow-redirects", action="store_true", default=None)
    parser.add_argument("--max-redirects", type=int, default=None)
    parser.add_argument("--bypass-mode", choices=("quick", "fast", "balanced", "full"), default=None)
    parser.add_argument("--max-variants-per-url", type=int, default=None)
    parser.add_argument("--max-requests-per-host", type=int, default=None)
    parser.add_argument("--max-total-requests", type=int, default=None)
    parser.add_argument("--max-assets", type=int, default=None)
    parser.add_argument("--max-endpoints", type=int, default=None)
    parser.add_argument("--max-documents", type=int, default=None)
    parser.add_argument("--max-swagger-requests", type=int, default=None)
    parser.add_argument("--config", "--user-config", dest="user_config", help="user TOML config")
    parser.add_argument("--output", "--output-dir", dest="output_dir", help="explicit report directory")
    parser.add_argument("--artifact-root", help="explicit artifact root; otherwise use a run temp directory")
    parser.add_argument(
        "--format",
        default=None,
        help="report formats: json,md,html,csv (comma-separated); defaults to config",
    )
    parser.add_argument(
        "--no-env",
        action="store_true",
        help="ignore SURFACESCOPE_* environment overrides (legacy DSBP_* is also ignored)",
    )
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI color in terminal output")
    parser.add_argument("--dry-run", action="store_true", help="validate and print the resolved plan without scanning")
    parser.add_argument("--list-components", action="store_true")
    parser.add_argument("--list-profiles", action="store_true")
    parser.add_argument("--list-assets", action="store_true")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    _configure_redirected_output()
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.list_components:
        print("\n".join(sorted(set(ADAPTERS))))
        return 0
    if args.list_profiles:
        try:
            print("\n".join(RequestProfileRegistry().ids()))
        except (AssetError, ConfigurationError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        return 0
    if args.list_assets:
        try:
            for asset in AssetManifest().all():
                print(f"{asset.id}\t{asset.package}\t{asset.status}\t{asset.path}")
        except (AssetError, ConfigurationError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        return 0

    try:
        targets = _targets_from_args(args)
        components = _components_from_args(args)
        overrides = _overrides_from_args(args)
        if args.dry_run:
            config, manifest, profile = validate_runtime(
                user_config=args.user_config,
                overrides=overrides,
                include_env=not args.no_env,
                profile_id=args.profile,
            )
            payload = {
                "targets": [target.url for target in targets],
                "components": components,
                "config": config.to_dict(),
                "profile": profile.id,
                "asset_count": len(tuple(manifest.all())),
            }
            bypass_mode = str(config.section("bypass").get("mode", "fast"))
            bypass_policy = MODE_POLICIES.get(bypass_mode, MODE_POLICIES["fast"])
            payload["selection"] = {
                "preset": "all-safe" if args.all else "explicit" if args.components is not None else "default",
                "components": components,
                "bypass_mode": bypass_mode,
                "bypass_initial_variants": bypass_policy.initial_variants,
                "bypass_max_variants": bypass_policy.max_variants,
                "swagger_unsafe": bool(config.section("swagger").get("include_unsafe", False)),
                "packer_active": bool(config.section("packer").get("active", False)),
                "packer_sqli": bool(config.section("packer").get("active_sqli", False)),
                "packer_probe_endpoints": bool(config.section("packer").get("probe_endpoints", False)),
            }
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            return 0
        result = run_scan(
            targets,
            components=components,
            output_dir=args.output_dir,
            report_format=args.format,
            user_config=args.user_config,
            overrides=overrides,
            include_env=not args.no_env,
            profile_id=args.profile,
            proxy=args.proxy,
            verbose=args.verbose,
            artifact_root=args.artifact_root,
        )
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except (ConfigurationError, AssetError, RequestError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    write_scan_result(result, color=None if not args.no_color else False)
    return 0 if result.component_result.ok else 1


def _targets_from_args(args: argparse.Namespace) -> list[Target]:
    raw = list(args.targets) + list(args.url)
    if args.url_file:
        path = Path(args.url_file).expanduser()
        if not path.exists():
            raise ConfigurationError(f"URL file does not exist: {path}")
        for line in path.read_text(encoding="utf-8").splitlines():
            value = line.strip()
            if value and not value.startswith("#"):
                raw.append(value)
    if not raw and not args.target_file:
        raise ConfigurationError(
            "provide a target with positional URL, -u/--url, -U/--url-file, or -T/--target-file"
        )
    headers = _parse_headers(args.header)
    cookies = _parse_cookies(args.cookie)
    target_specs = _target_specs_from_file(args.target_file) if args.target_file else []
    for spec in target_specs:
        url = _normalise_url(str(spec["url"]))
        spec_headers = _merge_headers(headers, spec.get("headers"), context=f"target file entry {spec['url']}")
        spec_cookies = dict(cookies)
        spec_cookies.update({str(key): str(value) for key, value in dict(spec.get("cookies") or {}).items()})
        scope = str(spec.get("scope") or _origin(url))
        raw.append(
            {
                "url": url,
                "headers": spec_headers,
                "cookies": spec_cookies,
                "scope": scope,
                "proxy": spec.get("proxy"),
                "target_id": str(spec.get("target_id") or "").strip(),
            }
        )
    targets: list[Target] = []
    seen: set[tuple[object, ...]] = set()
    for value in raw:
        if isinstance(value, dict):
            url = str(value["url"])
            target_headers = _validated_headers(dict(value.get("headers") or {}), context="target headers")
            target_cookies = dict(value.get("cookies") or {})
            target_scope = str(value.get("scope") or _origin(url))
            target_proxy = value.get("proxy")
            target_id = str(value.get("target_id") or "").strip()
        else:
            url = _normalise_url(str(value))
            target_headers = dict(headers)
            target_cookies = dict(cookies)
            target_scope = _origin(url)
            target_proxy = args.proxy
            target_id = ""
        identity = (
            url,
            target_id,
            target_scope,
            tuple(sorted(target_headers.items())),
            tuple(sorted(target_cookies.items())),
            str(target_proxy or ""),
        )
        if identity in seen:
            continue
        seen.add(identity)
        targets.append(
            Target(
                url=url,
                target_id=target_id,
                headers=target_headers,
                cookies=target_cookies,
                scope=target_scope,
                proxy=str(target_proxy) if target_proxy else None,
            )
        )
    return targets


def _target_specs_from_file(value: str) -> list[dict[str, object]]:
    path = Path(value).expanduser()
    if not path.exists():
        raise ConfigurationError(f"target file does not exist: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"invalid target file: {exc}") from exc
    items = payload.get("targets") if isinstance(payload, dict) else payload
    if not isinstance(items, list) or not items:
        raise ConfigurationError("target file must contain a non-empty array or a 'targets' array")
    specs: list[dict[str, object]] = []
    for index, item in enumerate(items, start=1):
        if not isinstance(item, dict) or not str(item.get("url") or "").strip():
            raise ConfigurationError(f"target file entry {index} must be an object with a URL")
        for key in ("headers", "cookies"):
            if key in item and not isinstance(item[key], dict):
                raise ConfigurationError(f"target file entry {index} has invalid {key}")
        if item.get("headers"):
            _validated_headers(
                {str(key): str(value) for key, value in dict(item["headers"]).items()},
                context=f"target file entry {index} headers",
            )
        specs.append(dict(item))
    return specs


def _components_from_args(args: argparse.Namespace) -> list[str]:
    if args.components is not None:
        values = [item for item in str(args.components).split(",") if item.strip()]
    elif args.all:
        values = [item for item in ALL_COMPONENTS.split(",") if item.strip()]
    else:
        values = [item for item in DEFAULT_COMPONENTS.split(",") if item.strip()]
    if args.bypass:
        values.append("bypass")
    if args.no_bypass:
        values = [item for item in values if item.strip().lower() not in ("bypass", "bypass403")]
    if args.swagger:
        values.append("swagger")
    if args.no_swagger:
        values = [item for item in values if item.strip().lower() != "swagger"]
    if args.packer:
        values.append("packer")
    if args.no_packer:
        values = [item for item in values if item.strip().lower() != "packer"]
    from .pipeline import _normalise_components, _ordered_components

    return _ordered_components(_normalise_components(values))


def _overrides_from_args(args: argparse.Namespace) -> dict[str, dict[str, object]]:
    overrides: dict[str, dict[str, object]] = {}

    def set_value(section: str, key: str, value: object) -> None:
        if value is not None:
            overrides.setdefault(section, {})[key] = value

    def set_csv(section: str, key: str, value: str, *, integers: bool = False) -> None:
        parsed = _int_csv(value) if integers else _csv(value)
        if parsed:
            set_value(section, key, parsed)

    set_value("run", "threads", args.threads)
    set_value("run", "timeout", args.timeout)
    set_value("run", "max_response_bytes", args.max_response_bytes)
    set_value("run", "profile", args.profile)
    set_value("traffic", "verify_tls", False if args.insecure else args.verify_tls)
    set_value("traffic", "follow_redirects", args.follow_redirects)
    set_value("traffic", "max_redirects", args.max_redirects)
    set_value("dirsearch", "wordlist", args.wordlist)
    set_value("dirsearch", "target_profiles", args.target_profile or None)
    set_csv("dirsearch", "extensions", args.extensions)
    set_csv("dirsearch", "prefixes", args.prefixes)
    set_csv("dirsearch", "suffixes", args.suffixes)
    set_csv("dirsearch", "force_extensions", args.force_extensions)
    set_csv("dirsearch", "exclude_extensions", args.exclude_extensions)
    set_csv("dirsearch", "exclude_redirects", args.exclude_redirects)
    set_csv("dirsearch", "include_statuses", args.include_statuses, integers=True)
    set_csv("dirsearch", "exclude_statuses", args.exclude_statuses, integers=True)
    set_value("dirsearch", "min_response_size", args.min_response_size)
    set_value("dirsearch", "max_response_size", args.max_response_size)
    set_value("dirsearch", "max_candidates", args.max_candidates)
    set_value("dirsearch", "max_jobs", args.max_jobs)
    set_value("dirsearch", "max_time", args.max_time)
    set_value("dirsearch", "recursive", args.recursive or None)
    set_value("dirsearch", "max_depth", args.max_depth)
    set_value("bypass", "mode", args.bypass_mode)
    set_value("bypass", "max_variants_per_url", args.max_variants_per_url)
    set_value("bypass", "max_requests_per_host", args.max_requests_per_host)
    set_value("bypass", "max_total_requests", args.max_total_requests)
    set_value("swagger", "max_documents", args.max_documents)
    set_value("swagger", "max_requests", args.max_swagger_requests)
    set_value("swagger", "include_unsafe", args.swagger_unsafe or None)
    set_value("swagger", "allow_external", args.swagger_external or None)
    set_value("packer", "max_assets", args.max_assets)
    set_value("packer", "max_endpoints", args.max_endpoints)
    set_value("packer", "probe_endpoints", args.packer_probe or None)
    set_value("packer", "probe_context_methods", args.packer_context_probes or None)
    set_value("packer", "active", args.packer_active or None)
    set_value("packer", "active_sqli", args.packer_sqli or None)
    set_value("packer", "fetch_sourcemaps", args.packer_sourcemaps or None)
    set_value("reports", "format", args.format)
    return overrides


def _parse_headers(values: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    seen: set[str] = set()
    for value in values:
        if ":" not in value:
            raise ConfigurationError(f"invalid header (expected 'Name: value'): {value!r}")
        key, item = value.split(":", 1)
        key = key.strip()
        if not key:
            raise ConfigurationError(f"invalid header name: {value!r}")
        normalized = key.lower()
        if normalized in seen:
            raise ConfigurationError(f"duplicate request header (case-insensitive): {key}")
        seen.add(normalized)
        headers[key] = item.strip()
    return _validated_headers(headers, context="CLI headers")


def _validated_headers(headers: dict[str, object], *, context: str) -> dict[str, str]:
    result = {str(key): str(value) for key, value in headers.items()}
    try:
        validate_request_headers(result)
    except ValueError as exc:
        raise ConfigurationError(f"{context}: {exc}") from exc
    return result


def _merge_headers(base: dict[str, str], overlay: object, *, context: str) -> dict[str, str]:
    merged = dict(base)
    for key, value in dict(overlay or {}).items():
        name = str(key)
        for existing in [item for item in merged if item.lower() == name.lower()]:
            merged.pop(existing, None)
        merged[name] = str(value)
    return _validated_headers(merged, context=context)


def _parse_cookies(value: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for item in value.split(";"):
        if "=" not in item:
            continue
        key, cookie_value = item.split("=", 1)
        if key.strip():
            cookies[key.strip()] = cookie_value.strip()
    return cookies


def _csv(value: str) -> list[str]:
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def _int_csv(value: str) -> list[int]:
    parsed: list[int] = []
    for item in _csv(value):
        try:
            if "-" in item:
                start_text, end_text = item.split("-", 1)
                if not start_text or not end_text:
                    raise ValueError
                start, end = int(start_text), int(end_text)
                if start > end:
                    raise ValueError
                parsed.extend(range(start, end + 1))
            else:
                parsed.append(int(item))
        except ValueError as exc:
            raise ConfigurationError(f"invalid status code list item: {item!r}") from exc
    return sorted(set(parsed))


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "/", "", ""))


def _normalise_url(value: str) -> str:
    value = value.strip()
    if not value:
        raise ConfigurationError("empty target URL")
    if "://" not in value:
        host = urlsplit("//" + value).hostname or ""
        scheme = "http" if host in ("localhost", "127.0.0.1", "::1") else "https"
        value = f"{scheme}://{value}"
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ConfigurationError(f"unsupported target URL: {value}")
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))


if __name__ == "__main__":
    raise SystemExit(main())
