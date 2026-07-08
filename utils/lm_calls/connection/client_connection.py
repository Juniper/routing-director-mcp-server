import os
import sys
import functools
import json
import time
import threading
import contextlib
import contextvars
from datetime import datetime, timedelta
import requests
import logging
import httpx

logger = logging.getLogger(__name__)
USE_EXTERNAL_API = os.getenv("USE_EXTERNAL_API", "false").lower() == "true"

# Per-request Routing Director client. Stored in a contextvar so each query
# (and each org_id) gets its own client, isolated across threads/async tasks.
_con_context = contextvars.ContextVar("routing_director_con", default=None)


def set_con(con):
    """Store the per-request Routing Director client in the current context."""
    _con_context.set(con)
    return con


def get_con():
    """Return the per-request Routing Director client, or ``None`` if unset."""
    return _con_context.get()


@contextlib.contextmanager
def use_con(con):
    """
    Scope a per-request Routing Director client to the current context.

    Sets ``con`` on entry and, on exit, resets the contextvar to its previous
    value (using the ``Token`` returned by ``set``) and closes the client if it
    exposes a ``close()`` method. This prevents the contextvar from holding a
    dangling reference to the client and ensures any underlying session/socket
    (e.g. ``SyncHttpxClient``) is released deterministically rather than relying
    on garbage collection.

    Clients that set ``shared = True`` (e.g. the process-wide external
    ``SyncHttpxClient`` singleton) are *not* closed here, since they are reused
    across requests; only the contextvar reference is dropped.
    """
    token = _con_context.set(con)
    try:
        yield con
    finally:
        _con_context.reset(token)
        if getattr(con, "shared", False):
            return
        close = getattr(con, "close", None)
        if callable(close):
            try:
                close()
            except Exception as ex:  # pragma: no cover - best-effort cleanup
                logger.warning("Error closing Routing Director client: %s", ex)


class BaseClient:
    # Whether a single instance is reused across requests. Per-request clients
    # leave this False so ``use_con`` closes them on exit; shared singletons
    # (external ``SyncHttpxClient``) set it True to survive for reuse.
    shared = False

    def request(self, **kwargs):
        raise NotImplementedError


class InternalSyncClient(BaseClient):
    def __init__(self, org_id):
        self.org_id = org_id

    def request(self, **kwargs):
        return requests.request(**kwargs)

    def close(self):
        """No persistent resources to release."""
        return None


def reAuth(func):
    """
    Decorator that re-authenticates before a request when cookies are locally
    expired, and retries once on 401/403 to recover from server-side idle
    session invalidation.
    """
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        if self.is_expired():
            self.authenticate()
        resp = func(self, *args, **kwargs)
        if resp.status_code in (401, 403):
            logger.info(
                "Received %s; session may have been invalidated server-side. "
                "Re-authenticating and retrying.",
                resp.status_code,
            )
            self.cookies.clear()
            if self.authenticate():
                resp = func(self, *args, **kwargs)
        return resp
    return wrapper


class HttpxClient:
    """Shared logic for sync and async httpx clients."""

    def _load_config(self, config_path):
        with open(config_path) as f:
            config = json.load(f)
        self.base_url = config["http_url"]
        self.auth_type = config["auth"]["type"]

        if self.auth_type == "basic":
            self.username = config["auth"]["username"]
            self.password = config["auth"]["password"]
            self.auth_token = None
        elif self.auth_type == "token":
            self.auth_token = config["auth"]["token"]
            self.username = None
            self.password = None
        else:
            raise ValueError(f"Unsupported auth type: {self.auth_type}. Supported types: 'basic', 'token'")

        self.org_id = config.get("org_id", "")
        self.cookies = dict()
        self.token = None
        self.token_expiry = 0

    def _get_headers(self):
        headers = {}
        if self.auth_type == "basic":
            if "csrftoken" in self.cookies:
                headers["X-csrftoken"] = self.cookies["csrftoken"].value
        elif self.auth_type == "token":
            if self.token:
                headers["Authorization"] = f"Token {self.token}"
        return headers

    def _get_cookies(self):
        return {name: cookie.value for name, cookie in self.cookies.items()}

    def is_expired(self):
        if self.auth_type == "basic":
            compare_time = datetime.now() + timedelta(minutes=15)
            for name, cookie in self.cookies.items():
                if cookie.is_expired(now=compare_time.timestamp()):
                    logger.info("Cookie %s is expired.", name)
                    return True
        return False

    def _process_auth_response(self, resp):
        for cookie in resp.cookies.jar:
            if cookie.name in ["sessionid", "csrftoken"]:
                self.cookies[cookie.name] = cookie
                logger.debug("Received cookie: %s", cookie.name)
        logger.info("Password-based authentication successful")

    def _build_request(self, request):
        new_headers = dict(request.headers)
        if self.auth_type == "basic":
            cookies = self._get_cookies()
            if "cookie" not in new_headers:
                new_headers["cookie"] = "; ".join([f"{k}={v}" for k, v in cookies.items()])
        new_headers.update(self._get_headers())
        return httpx.Request(
            method=request.method,
            url=request.url,
            headers=new_headers,
            content=request.content,
        )

    def _prepare_request_kwargs(self, kwargs):
        if self.auth_type == "basic":
            cookies = self._get_cookies()
            if kwargs.get("cookies") is None:
                kwargs["cookies"] = cookies
            else:
                kwargs["cookies"].update(cookies)

        extra_headers = self._get_headers()
        if kwargs.get("headers") is None:
            kwargs["headers"] = {}
        kwargs["headers"].update(extra_headers)
        kwargs["url"] = self.base_url + kwargs["url"]
        return kwargs


class SyncHttpxClient(HttpxClient, BaseClient):
    """
    Process-wide, ``config_path``-keyed singleton used for the *external* case.

    All external requests target the same Routing Director (same config / org),
    so a single authenticated ``httpx`` session is created once and reused. This
    avoids paying a login round-trip on every request. The instance is shared
    across threads, so the auth-refresh path is guarded by a lock.
    """

    shared = True
    _instances = {}
    _instances_lock = threading.Lock()

    def __new__(cls, config_path):
        with cls._instances_lock:
            inst = cls._instances.get(config_path)
            if inst is None:
                inst = super().__new__(cls)
                inst._initialized = False
                inst._init_lock = threading.Lock()
                inst._auth_lock = threading.Lock()
                cls._instances[config_path] = inst
            return inst

    def __init__(self, config_path):
        # Fast path: instance already built and authenticated by another caller.
        if self._initialized:
            return
        # Double-checked locking so only one thread loads config + logs in.
        with self._init_lock:
            if self._initialized:
                return
            self._load_config(config_path)
            logger.info("Initializing SyncHttpxClient for %s with %s authentication", self.base_url, self.auth_type)
            # coverity[BAD_CERT_VERIFICATION]
            self.session = httpx.Client(base_url=self.base_url, timeout=60.0, verify=False)  # nosec B501
            self.authenticate()
            self._initialized = True

    def __enter__(self):
        if self.session is None:
            # coverity[BAD_CERT_VERIFICATION]
            self.session = httpx.Client(base_url=self.base_url, timeout=60.0, verify=False)  # nosec B501
        self.authenticate()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Intentionally a no-op: this is a reused singleton. Use ``shutdown()``
        # for explicit, process-level teardown instead of closing per-``with``.
        return None

    def authenticate(self):
        with self._auth_lock:
            # Another thread may have refreshed the session while we waited.
            if self.auth_type == "token" and self.token:
                return True
            if self.auth_type == "basic" and self.cookies and not self.is_expired():
                return True
            if self.auth_type == "basic":
                body = {"email": self.username, "password": self.password}
                logger.info("Authenticating with Routing Director at %s using password", self.base_url)
                try:
                    resp = self.session.post(f"{self.base_url}/api/v1/login", json=body)
                    resp.raise_for_status()
                except httpx.RequestError as e:
                    logger.error("Failed to connect to Routing Director: %s", e)
                    return False
                except httpx.HTTPStatusError as e:
                    logger.error("Failed to authenticate: %s", e)
                    logger.error("Response: %s", e.response.text)
                    return False
                self._process_auth_response(resp)
            elif self.auth_type == "token":
                logger.info("Using token-based authentication for %s", self.base_url)
                self.token = self.auth_token
                logger.info("Token-based authentication configured")
            else:
                logger.error("Unsupported auth type: %s", self.auth_type)
                raise NotImplementedError(f"Auth type '{self.auth_type}' is not supported.")
            return True

    def get_token(self):
        if not self.token or time.time() >= self.token_expiry:
            logger.info("Token missing or expired, re-authenticating")
            self.authenticate()
        return self.token

    @reAuth
    def request(self, **kwargs):
        kwargs = self._prepare_request_kwargs(kwargs)
        return self.session.request(**kwargs)

    def close(self):
        """
        No-op for the shared singleton: the session is reused across requests,
        so per-request callers must not close it. Use ``shutdown()`` for
        explicit, process-level teardown.
        """
        return None

    @classmethod
    def shutdown(cls):
        """Close all singleton sessions and clear the registry (process exit)."""
        with cls._instances_lock:
            for inst in cls._instances.values():
                if getattr(inst, "session", None):
                    inst.session.close()
                    inst.session = None
            cls._instances.clear()


class AsyncHttpxClient(HttpxClient):
    _instance = None

    def __new__(cls, config_path):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, config_path):
        if self._initialized:
            return
        self._load_config(config_path)
        self.session = None
        self._initialized = True

    async def __aenter__(self):
        if self.session is None:
            self.session = httpx.AsyncClient(base_url=self.base_url, timeout=60.0, verify=False)
        await self.authenticate()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.aclose()
            self.session = None

    async def authenticate(self):
        if self.auth_type == "basic":
            body = {"email": self.username, "password": self.password}
            logger.info("Authenticating with Routing Director at %s using password", self.base_url)
            try:
                resp = await self.session.post(f"{self.base_url}/api/v1/login", json=body)
                resp.raise_for_status()
            except httpx.RequestError as e:
                logger.error("Failed to connect to Routing Director: %s", e)
                return False
            except httpx.HTTPStatusError as e:
                logger.error("Failed to authenticate: %s", e)
                logger.error("Response: %s", e.response.text)
                return False
            self._process_auth_response(resp)
        elif self.auth_type == "token":
            logger.info("Using token-based authentication for %s", self.base_url)
            self.token = self.auth_token
            logger.info("Token-based authentication configured")
        else:
            logger.error("Unsupported auth type: %s", self.auth_type)
            raise NotImplementedError(f"Auth type '{self.auth_type}' is not supported.")
        return True

    async def request(self, **kwargs):
        if self.is_expired():
            await self.authenticate()
        original_kwargs = dict(kwargs)
        prepared = self._prepare_request_kwargs(kwargs)
        resp = await self.session.request(**prepared)
        if resp.status_code in (401, 403):
            logger.info(
                "Received %s; session may have been invalidated server-side. "
                "Re-authenticating and retrying.",
                resp.status_code,
            )
            self.cookies.clear()
            if await self.authenticate():
                prepared = self._prepare_request_kwargs(original_kwargs)
                resp = await self.session.request(**prepared)
        return resp

    async def verify_authentication(self):
        """
        Validate credentials up-front (e.g. at MCP server startup).

        Opens a temporary session, attempts to authenticate, and then resets the
        session so the real session is created later within the server's own
        event loop. Returns True only when authentication succeeds.
        """
        # coverity[BAD_CERT_VERIFICATION]
        self.session = httpx.AsyncClient(base_url=self.base_url, timeout=60.0, verify=False)  # nosec B501
        try:
            authenticated = await self.authenticate()
        finally:
            await self.session.aclose()
            self.session = None
            self.cookies = dict()
            self.token = None
            self.token_expiry = 0
        return authenticated

    async def send(self, request, **kwargs):
        """Send a prepared request."""
        if self.session is None:
            self.session = httpx.AsyncClient(base_url=self.base_url, timeout=60.0, verify=False)
            await self.authenticate()

        if self.is_expired():
            await self.authenticate()

        resp = await self.session.send(self._build_request(request), **kwargs)
        if resp.status_code in (401, 403):
            logger.info(
                "Received %s; session may have been invalidated server-side. "
                "Re-authenticating and retrying.",
                resp.status_code,
            )
            self.cookies.clear()
            if await self.authenticate():
                resp = await self.session.send(self._build_request(request), **kwargs)
        return resp


# Used by LLM Connector
def create_routing_director_client(org_id):
    config_path = os.getenv("MCP_CONFIG", "NO_CONFIG")
    if USE_EXTERNAL_API:
        # Used by mcp custom tools 
        return SyncHttpxClient(config_path=config_path)
    return InternalSyncClient(org_id=org_id)


# Used by MCP openapi spec tools
def create_routing_director_async_client():
    config_path = os.getenv("MCP_CONFIG", "NO_CONFIG")
    if USE_EXTERNAL_API:
        return AsyncHttpxClient(config_path=config_path)
    else:
        logger.debug("Cannot create AsyncHttpxClient because USE_EXTERNAL_API is false. Exiting")
        return None
