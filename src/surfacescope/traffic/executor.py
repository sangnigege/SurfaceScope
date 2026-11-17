"""One request executor and one bounded worker pool for every component."""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
import threading
import time
import uuid
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field, replace
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests
from requests.adapters import HTTPAdapter

from ..errors import BudgetExceeded, CancelledError, RequestError
from ..models import RequestSpec, ResponseSnapshot, validate_request_headers
from ..urls import canonical_url, origin
from .audit import RequestAudit
from .cache import ResponseCache
from .profiles import RequestProfile, RequestProfileRegistry, fetch_site

_METHOD_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_PURPOSES = frozenset({"navigation", "xhr", "asset", "api"})
_CACHE_POLICIES = frozenset({"default", "no-store", "reload", "bypass"})
_AUTH_HEADERS = frozenset(
    {
        "authorization",
        "cookie",
        "proxy-authorization",
        "x-api-key",
        "x-auth-token",
        "x-access-token",
        "x-session-token",
        "x-csrf-token",
        "x-xsrf-token",
    }
)
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


def _supported_accept_encodings() -> frozenset[str]:
    """Return encodings the local urllib3 stack can actually decode."""

    supported = {"gzip", "deflate"}
    try:
        import urllib3.response as urllib3_response

        if getattr(urllib3_response, "brotli", None) is not None:
            supported.add("br")
        if getattr(urllib3_response, "HAS_ZSTD", False):
            supported.add("zstd")
    except (ImportError, AttributeError):
        pass
    return frozenset(supported)


_SUPPORTED_ACCEPT_ENCODINGS = _supported_accept_encodings()


def _filter_accept_encoding(headers: dict[str, str]) -> dict[str, str]:
    """Keep modern browser encodings only when the transport can decode them."""

    for key in list(headers):
        if key.lower() != "accept-encoding":
            continue
        values = []
        for token in str(headers[key]).split(","):
            name = token.split(";", 1)[0].strip().lower()
            if name in _SUPPORTED_ACCEPT_ENCODINGS:
                values.append(token.strip())
        headers[key] = ", ".join(values) or "identity"
    return headers


def _send_prepared_wire_url(session: requests.Session, kwargs: dict[str, Any]) -> requests.Response:
    """Send an attack URL without requests normalising harmless percent escapes."""

    request = requests.Request(
        method=kwargs["method"],
        url=kwargs["url"],
        headers=kwargs["headers"],
        params=kwargs["params"],
        data=kwargs["data"],
        json=kwargs["json"],
        cookies=kwargs["cookies"],
    )
    prepared = session.prepare_request(request)
    # requests decodes %2e/%61 while preparing a URL. Reinstating the caller's
    # exact path is required for path-normalisation bypass tests; the catalog
    # only marks syntactically valid ASCII URLs for this mode.
    original = urlsplit(str(kwargs["url"]))
    prepared_parts = urlsplit(prepared.url)
    prepared.url = urlunsplit(
        (original.scheme, original.netloc, original.path or "/", prepared_parts.query, prepared_parts.fragment)
    )
    return session.send(
        prepared,
        stream=True,
        timeout=kwargs["timeout"],
        verify=kwargs["verify"],
        proxies=kwargs["proxies"],
        allow_redirects=False,
    )


@dataclass
class _BudgetState:
    max_total: int | None = None
    max_per_host: int | None = None
    total: int = 0
    by_host: dict[str, int] = field(default_factory=dict)


def _cache_key(
    spec: RequestSpec,
    profile: RequestProfile,
    *,
    follow_redirects: bool,
    proxy: dict[str, str] | None = None,
    cookie_state: str = "",
) -> str:
    body = spec.json if spec.json is not None else spec.data
    raw = "|".join(
        (
            spec.method.upper(),
            canonical_url(spec.url),
            _stable_digest(spec.params),
            _stable_digest(body),
            _stable_digest({key.lower(): value for key, value in spec.headers.items()}),
            _stable_digest(spec.cookies),
            spec.target_id,
            spec.auth_scope,
            spec.auth_origin,
            spec.profile_id,
            profile.id,
            spec.purpose,
            "attack" if spec.attack else "safe",
            spec.dedupe_key or "",
            _stable_digest(spec.metadata),
            cookie_state,
            "follow" if follow_redirects else "no-follow",
            _stable_digest(proxy),
        )
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _stable_digest(value: Any) -> str:
    if value is None:
        return ""
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, default=str, ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def _session_cookie_state(session: requests.Session) -> str:
    """Hash the cookie jar without putting secret values in the cache key."""

    return _stable_digest(sorted(session.cookies.get_dict().items()))


def _budget_host(url: str) -> str:
    """Normalise the host key so default ports share one host budget."""

    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if not host:
        return parts.netloc.lower()
    try:
        port = parts.port
    except ValueError:
        return parts.netloc.lower()
    scheme = parts.scheme.lower()
    default_port = 443 if scheme == "https" else 80
    if port is None or port == default_port:
        return host
    if ":" in host:
        host = f"[{host}]"
    return f"{host}:{port}"


class RequestExecutor:
    def __init__(
        self,
        profile: RequestProfile,
        *,
        profiles: RequestProfileRegistry | None = None,
        timeout: float = 10.0,
        verify_tls: bool = True,
        follow_redirects: bool = False,
        max_redirects: int = 10,
        max_response_bytes: int = 8 * 1024 * 1024,
        cache: ResponseCache | None = None,
        audit: RequestAudit | None = None,
        proxies: dict[str, str] | None = None,
        rate_limit_per_second: float = 0.0,
        cancel_event: threading.Event | None = None,
        max_workers: int | None = None,
    ) -> None:
        if timeout <= 0:
            raise RequestError("request timeout must be positive")
        if max_response_bytes <= 0:
            raise RequestError("max_response_bytes must be positive")
        if max_redirects < 0:
            raise RequestError("max_redirects must be non-negative")
        self.profile = profile
        self._profiles = {profile.id: profile}
        if profiles is not None:
            self._profiles.update({profile_id: profiles.get(profile_id) for profile_id in profiles.ids()})
        self.timeout = float(timeout)
        self.verify_tls = verify_tls
        self.follow_redirects = follow_redirects
        self.max_redirects = int(max_redirects)
        self.max_response_bytes = int(max_response_bytes)
        self.cache = cache or ResponseCache()
        self.audit = audit or RequestAudit()
        self.proxies = proxies or {}
        self._target_proxies: dict[str, dict[str, str]] = {}
        self._target_origins: dict[str, str] = {}
        self.rate_limit_per_second = max(0.0, float(rate_limit_per_second))
        self.cancel_event = cancel_event or threading.Event()
        self._max_workers = max(1, min(int(max_workers or 32), 128))
        self._local = threading.local()
        self._sessions: list[requests.Session] = []
        self._sessions_lock = threading.Lock()
        self._pool: ThreadPoolExecutor | None = None
        self._pool_lock = threading.Lock()
        self._pool_workers = 0
        self._closed = False
        self._inflight: dict[str, threading.Event] = {}
        self._inflight_lock = threading.Lock()
        self._budgets: dict[str, _BudgetState] = {}
        self._budget_lock = threading.Lock()
        self._rate_lock = threading.Lock()
        self._next_send_at = 0.0

    @property
    def closed(self) -> bool:
        return self._closed

    def register_target_proxy(self, target_id: str, proxy: str | None) -> None:
        """Bind an optional proxy to one target identity before scanning."""

        if not target_id or not proxy:
            return
        self._target_proxies[target_id] = {"http": str(proxy), "https": str(proxy)}

    def register_target(self, target_id: str, *, url: str, proxy: str | None = None) -> None:
        """Bind an authenticated identity to its origin and optional proxy."""

        if not target_id or not url:
            return
        target_origin = origin(url)
        if target_origin:
            self._target_origins[target_id] = target_origin
        self.register_target_proxy(target_id, proxy)

    def configure_budget(self, scope: str, *, max_total: int | None = None, max_per_host: int | None = None) -> None:
        with self._budget_lock:
            self._budgets[scope] = _BudgetState(
                max_total=max_total if max_total and max_total > 0 else None,
                max_per_host=max_per_host if max_per_host and max_per_host > 0 else None,
            )

    def budget_usage(self, scope: str) -> dict[str, Any]:
        with self._budget_lock:
            state = self._budgets.get(scope)
            if state is None:
                return {"configured": False, "total": 0, "by_host": {}}
            return {
                "configured": True,
                "max_total": state.max_total,
                "max_per_host": state.max_per_host,
                "total": state.total,
                "by_host": dict(state.by_host),
            }

    def cancel(self) -> None:
        self.cancel_event.set()

    def _session(self, target_id: str, auth_scope: str, request_origin: str) -> requests.Session:
        sessions = getattr(self._local, "sessions", None)
        if sessions is None:
            sessions = {}
            self._local.sessions = sessions
        key = (target_id, auth_scope, request_origin)
        session = sessions.get(key)
        if session is None:
            session = requests.Session()
            session.trust_env = False
            session.headers.clear()
            session.mount("http://", HTTPAdapter(pool_connections=10, pool_maxsize=64, max_retries=0))
            session.mount("https://", HTTPAdapter(pool_connections=10, pool_maxsize=64, max_retries=0))
            sessions[key] = session
            with self._sessions_lock:
                self._sessions.append(session)
        return session

    def close(self) -> None:
        with self._pool_lock:
            if self._closed and self._pool is None:
                return
            self._closed = True
            pool, self._pool = self._pool, None
        if pool is not None:
            pool.shutdown(wait=True, cancel_futures=True)
        with self._sessions_lock:
            sessions, self._sessions = self._sessions, []
        for session in sessions:
            with contextlib.suppress(Exception):
                session.close()

    def __enter__(self) -> RequestExecutor:
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def _ensure_pool(self, requested_workers: int) -> ThreadPoolExecutor:
        with self._pool_lock:
            if self._closed:
                raise RequestError("request executor is closed")
            if self._pool is None:
                workers = max(1, min(int(requested_workers), self._max_workers))
                self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="surfacescope")
                self._pool_workers = workers
            return self._pool

    def run_many(
        self,
        worker: Callable[[Any], Any],
        items: Iterable[Any],
        *,
        max_workers: int = 25,
    ) -> Iterator[Any]:
        """Run work on the executor-owned pool with bounded in-flight futures."""

        self._raise_if_closed()
        self._raise_if_cancelled()
        pool = self._ensure_pool(max_workers)
        iterator = iter(items)
        in_flight: set[Future[Any]] = set()
        window = max(2, self._pool_workers * 2)

        def fill() -> None:
            while len(in_flight) < window:
                try:
                    item = next(iterator)
                except StopIteration:
                    return
                try:
                    in_flight.add(pool.submit(worker, item))
                except RuntimeError as exc:
                    raise RequestError("request executor is closed") from exc

        try:
            fill()
            while in_flight:
                if self.cancel_event.is_set():
                    for future in in_flight:
                        future.cancel()
                    self._raise_if_cancelled()
                done, _ = wait(in_flight, timeout=0.2, return_when=FIRST_COMPLETED)
                if not done:
                    continue
                for future in done:
                    in_flight.remove(future)
                    yield future.result()
                fill()
        finally:
            for future in in_flight:
                future.cancel()

    def request(self, spec: RequestSpec) -> ResponseSnapshot:
        self._raise_if_closed()
        self._validate(spec)
        profile = self._profiles.get(spec.profile_id)
        if profile is None:
            raise RequestError(f"unknown request profile: {spec.profile_id}")
        method = spec.method.upper()
        if method in ("GET", "HEAD") and (spec.data is not None or spec.json is not None):
            self.audit.increment("body_dropped")
            spec = replace(spec, data=None, json=None)
        effective_redirects = self.follow_redirects if spec.allow_redirects is None else spec.allow_redirects
        effective_proxy = self._target_proxies.get(spec.target_id, self.proxies)
        cacheable = (
            spec.side_effect_free
            and not spec.attack
            and method in ("GET", "HEAD")
            and spec.cache_policy == "default"
        )
        cookie_state = ""
        if cacheable:
            request_origin = origin(spec.url)
            session = self._session(
                spec.target_id,
                spec.auth_scope or request_origin,
                request_origin,
            )
            cookie_state = _session_cookie_state(session)
        key = _cache_key(
            spec,
            profile,
            follow_redirects=bool(effective_redirects),
            proxy=effective_proxy,
            cookie_state=cookie_state,
        )
        event: threading.Event | None = None
        if cacheable:
            cached = self.cache.get(key)
            if cached is not None:
                self.audit.increment("cache_hit")
                self.audit.record(
                    request_id=cached.request_id,
                    url=cached.url,
                    method=method,
                    target_id=spec.target_id,
                    profile_id=spec.profile_id,
                    purpose=spec.purpose,
                    attack=spec.attack,
                    from_cache=True,
                )
                return replace(cached, from_cache=True)
            with self._inflight_lock:
                event = self._inflight.get(key)
                owner = event is None
                if owner:
                    event = threading.Event()
                    self._inflight[key] = event
            if not owner:
                self.audit.increment("in_flight_join")
                event.wait(self.timeout + 5)
                cached = self.cache.get(key)
                if cached is not None:
                    return replace(cached, from_cache=True)
                raise RequestError(f"in-flight request failed for {spec.url}")
        try:
            self._raise_if_cancelled()
            budget_scopes = ("default", spec.budget_scope) if spec.budget_scope != "default" else ("default",)
            snapshot = self._send(spec, profile, budget_scopes)
            if cacheable and _response_cacheable(snapshot):
                self.cache.put(key, snapshot)
            return snapshot
        finally:
            if cacheable and event is not None:
                with self._inflight_lock:
                    self._inflight.pop(key, None)
                event.set()

    def get(self, url: str, *, target_id: str, profile_id: str, **kwargs: Any) -> ResponseSnapshot:
        return self.request(RequestSpec(url=url, target_id=target_id, profile_id=profile_id, **kwargs))

    def _validate(self, spec: RequestSpec) -> None:
        if not spec.target_id:
            raise RequestError("RequestSpec.target_id is required")
        if not spec.profile_id:
            raise RequestError("RequestSpec.profile_id is required")
        if not spec.purpose or spec.purpose not in _PURPOSES:
            raise RequestError(f"unsupported request purpose: {spec.purpose}")
        if spec.cache_policy not in _CACHE_POLICIES:
            raise RequestError(f"unsupported cache policy: {spec.cache_policy}")
        if not _METHOD_RE.fullmatch(spec.method):
            raise RequestError(f"invalid HTTP method: {spec.method!r}")
        try:
            validate_request_headers(spec.headers)
        except ValueError as exc:
            raise RequestError(str(exc)) from exc
        try:
            parts = urlsplit(spec.url)
        except ValueError as exc:
            raise RequestError(f"invalid request URL: {spec.url}") from exc
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise RequestError(f"invalid request URL: {spec.url}")

    def _raise_if_closed(self) -> None:
        if self._closed:
            raise RequestError("request executor is closed")

    def _raise_if_cancelled(self) -> None:
        if self.cancel_event.is_set():
            self.audit.increment("cancelled")
            raise CancelledError("scan cancelled")

    def _reserve_budgets(self, scopes: tuple[str, ...], host: str) -> None:
        """Reserve every configured parent/child budget atomically."""

        with self._budget_lock:
            states = [(scope, self._budgets.get(scope)) for scope in dict.fromkeys(scopes)]
            for scope, state in states:
                if state is None:
                    continue
                if state.max_total is not None and state.total >= state.max_total:
                    self.audit.increment("budget_exceeded")
                    raise BudgetExceeded(f"request budget exhausted for scope {scope}")
                if state.max_per_host is not None and state.by_host.get(host, 0) >= state.max_per_host:
                    self.audit.increment("budget_exceeded")
                    raise BudgetExceeded(f"per-host request budget exhausted for {host} in scope {scope}")
            for _scope, state in states:
                if state is None:
                    continue
                state.total += 1
                state.by_host[host] = state.by_host.get(host, 0) + 1

    def _respect_rate_limit(self) -> None:
        if self.rate_limit_per_second <= 0:
            return
        interval = 1.0 / self.rate_limit_per_second
        with self._rate_lock:
            now = time.monotonic()
            if self._next_send_at <= now:
                self._next_send_at = now + interval
                return
            wait_time = self._next_send_at - now
            self._next_send_at += interval
        if wait_time > 0:
            time.sleep(wait_time)
            self._raise_if_cancelled()

    def _send(
        self,
        spec: RequestSpec,
        profile: RequestProfile,
        budget_scopes: tuple[str, ...],
    ) -> ResponseSnapshot:
        request_id = uuid.uuid4().hex
        auth_origin = (
            origin(spec.auth_origin)
            if spec.auth_origin
            else self._target_origins.get(spec.target_id)
            or (origin(spec.auth_scope) if "://" in spec.auth_scope else "")
            or origin(spec.url)
        )
        follow_redirects = self.follow_redirects if spec.allow_redirects is None else spec.allow_redirects
        max_redirects = self.max_redirects if follow_redirects else 0
        explicit_referer = str(spec.metadata.get("referer") or "") or None
        explicit_initiator = str(spec.metadata.get("initiator") or "") or explicit_referer
        explicit_site = spec.metadata.get("site")
        current_url = spec.url
        current_method = spec.method.upper()
        current_data = spec.data
        current_json = spec.json
        current_params = spec.params
        previous_url: str | None = None
        history: list[str] = []
        response: requests.Response | None = None
        headers: dict[str, str] = {}
        any_cross_origin = False
        started = time.monotonic()
        try:
            while True:
                request_origin = origin(current_url)
                cross_origin = bool(auth_origin and request_origin and auth_origin != request_origin)
                any_cross_origin = any_cross_origin or cross_origin
                if previous_url is None:
                    referer = explicit_referer
                    initiator = explicit_initiator
                    site = explicit_site
                else:
                    referer = _redirect_referer(previous_url, current_url)
                    initiator = previous_url
                    site = None
                if site is None:
                    if initiator:
                        site = fetch_site(current_url, str(initiator))
                    elif spec.metadata.get("direct_navigation", spec.purpose == "navigation"):
                        site = "none"
                    else:
                        site = "same-origin"
                if cross_origin and site in {"none", "same-origin"} and not initiator:
                    # A caller cannot claim same-origin while sending credentials to a
                    # different origin. Keep the wire image internally consistent.
                    site = "cross-site"
                overrides = dict(spec.headers)
                if previous_url is not None:
                    # Redirect hops recompute these headers from the actual chain.
                    overrides = {
                        key: value
                        for key, value in overrides.items()
                        if key.lower() not in {"referer", "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest"}
                    }
                has_body = any(value is not None for value in (current_data, current_json))
                keep_content_type = bool(spec.metadata.get("keep_content_type"))
                headers = profile.build_headers(
                    spec.purpose,
                    overrides=overrides,
                    referer=referer,
                    origin=spec.metadata.get("origin"),
                    direct_navigation=spec.metadata.get("direct_navigation", spec.purpose == "navigation"),
                    resource_type=spec.metadata.get("resource_type"),
                    has_body=has_body,
                    keep_content_type=keep_content_type,
                    site=site,
                    secure=urlsplit(current_url).scheme == "https",
                )
                headers = _filter_accept_encoding(headers)
                if cross_origin:
                    headers = {key: value for key, value in headers.items() if key.lower() not in _AUTH_HEADERS}
                if current_method in ("GET", "HEAD") and not keep_content_type:
                    headers = {key: value for key, value in headers.items() if key.lower() != "content-type"}

                self._reserve_budgets(budget_scopes, _budget_host(current_url))
                self._respect_rate_limit()
                kwargs: dict[str, Any] = {
                    "method": current_method,
                    "url": current_url,
                    "headers": headers,
                    "params": current_params,
                    "data": current_data,
                    "json": current_json,
                    "cookies": None if cross_origin else (spec.cookies or None),
                    "timeout": spec.timeout or self.timeout,
                    # Redirects are handled here so every hop can re-evaluate
                    # credentials, sessions, headers, budgets and audit counters.
                    "allow_redirects": False,
                    "verify": self.verify_tls,
                    "proxies": self._target_proxies.get(spec.target_id, self.proxies) or None,
                    "stream": True,
                }
                self.audit.increment("network_sent")
                if cross_origin:
                    self.audit.increment("cross_origin_sent")
                session_scope = "" if cross_origin else spec.auth_scope
                session = self._session(spec.target_id, session_scope, request_origin)
                if cross_origin:
                    # Do not replay third-party cookies from an earlier request
                    # on the same destination session.
                    session.cookies.clear()
                if spec.metadata.get("preserve_path_encoding"):
                    response = _send_prepared_wire_url(session, kwargs)
                else:
                    response = session.request(**kwargs)

                if not follow_redirects or response.status_code not in _REDIRECT_STATUSES:
                    break
                location = response.headers.get("Location")
                if not location:
                    break
                next_url = urljoin(response.url, location)
                next_parts = urlsplit(next_url)
                if next_parts.scheme not in ("http", "https") or not next_parts.netloc:
                    self.audit.increment("redirect_rejected")
                    break
                if max_redirects <= 0:
                    self.audit.increment("redirect_rejected")
                    break
                if len(history) >= max_redirects:
                    self.audit.increment("redirect_rejected")
                    raise RequestError(f"too many redirects for {spec.url}")

                history.append(response.url)
                previous_url = response.url
                current_method, current_data, current_json = _redirect_method(
                    response.status_code,
                    current_method,
                    current_data,
                    current_json,
                )
                current_url = next_url
                current_params = None
                self.audit.increment("redirects_followed")
                response.close()
                response = None

            assert response is not None
            chunks: list[bytes] = []
            total = 0
            truncated = False
            for chunk in response.iter_content(chunk_size=64 * 1024):
                if not chunk:
                    continue
                remaining = self.max_response_bytes - total
                if len(chunk) >= remaining:
                    chunks.append(chunk[:remaining])
                    truncated = True
                    break
                chunks.append(chunk)
                total += len(chunk)
            body = b"".join(chunks)
            encoding = response.encoding or "utf-8"
            text = body.decode(encoding, errors="replace")
            elapsed = time.monotonic() - started
            snapshot = ResponseSnapshot(
                request_id=request_id,
                url=spec.url,
                final_url=response.url,
                method=current_method,
                status=response.status_code,
                headers={str(key): str(value) for key, value in response.headers.items()},
                body=body,
                text=text,
                elapsed=elapsed,
                history=history,
                truncated=truncated,
                request_headers=dict(response.request.headers) if response.request is not None else headers,
                target_id=spec.target_id,
                auth_scope=spec.auth_scope or request_origin,
            )
            self.audit.record(
                request_id=request_id,
                url=response.url,
                method=current_method,
                target_id=spec.target_id,
                profile_id=spec.profile_id,
                purpose=spec.purpose,
                attack=spec.attack,
                budget_scope=spec.budget_scope,
                status=snapshot.status,
                from_cache=False,
                cross_origin=any_cross_origin,
                redirects=len(history),
            )
            return snapshot
        except requests.RequestException as exc:
            self.audit.increment("errors")
            self.audit.record(
                request_id=request_id,
                url=spec.url,
                method=spec.method.upper(),
                target_id=spec.target_id,
                profile_id=spec.profile_id,
                purpose=spec.purpose,
                attack=spec.attack,
                error=type(exc).__name__,
            )
            raise RequestError(f"{spec.method.upper()} {spec.url}: {exc}") from exc
        finally:
            if response is not None:
                response.close()


def _redirect_method(
    status: int,
    method: str,
    data: Any,
    json_body: Any,
) -> tuple[str, Any, Any]:
    """Apply browser/requests-compatible method rewriting for a redirect hop."""

    if status == 303 and method != "HEAD":
        return "GET", None, None
    if status in (301, 302) and method not in ("GET", "HEAD"):
        return "GET", None, None
    return method, data, json_body


def _redirect_referer(previous_url: str, next_url: str) -> str | None:
    """Build a conservative strict-origin-when-cross-origin Referer."""

    previous = urlsplit(previous_url)
    target = urlsplit(next_url)
    if previous.scheme == "https" and target.scheme == "http":
        return None
    previous_origin = origin(previous_url)
    if not previous_origin:
        return None
    if previous_origin == origin(next_url):
        return previous_url
    return previous_origin + "/"


def _response_cacheable(snapshot: ResponseSnapshot) -> bool:
    """Return whether a response is safe to share between scan stages."""

    if snapshot.error or snapshot.status >= 500:
        return False
    if snapshot.header("set-cookie"):
        return False
    cache_control = snapshot.header("cache-control").lower()
    directives = {item.strip() for item in cache_control.split(",") if item.strip()}
    if directives & {"no-store", "private", "no-cache"}:
        return False
    if "max-age=0" in cache_control:
        return False
    if snapshot.header("vary").strip() == "*":
        return False
    return snapshot.header("pragma").lower() != "no-cache"
