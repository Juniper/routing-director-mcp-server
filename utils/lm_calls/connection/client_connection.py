import os
import sys
import functools
import json
import time
from datetime import datetime, timedelta
import requests
import logging
import httpx

logger = logging.getLogger(__name__)
USE_EXTERNAL_API = os.getenv("USE_EXTERNAL_API", "false").lower() == "true"


class BaseClient:
    def request(self, **kwargs):
        raise NotImplementedError


class InternalClient(BaseClient):
    _instance = None

    def __new__(cls, config_path):
        if cls._instance is None:
            cls._instance = super(InternalClient, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, config_path):
        if self._initialized:
            return
        self._initialized = True
        self.org_id = ""

    def request(self, **kwargs):
        client = httpx.Client(base_url=kwargs["url"], timeout=30.0, verify=False)
        return client.request(**kwargs)


class InternalSyncClient(BaseClient):
    _instance = None

    def __new__(cls, config_path):
        if cls._instance is None:
            cls._instance = super(InternalSyncClient, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, config_path):
        if self._initialized:
            return
        self._initialized = True
        self.org_id = ""

    def request(self, **kwargs):
        return requests.request(**kwargs)

def reAuth(func):
    """
    A decorator that runs a specific function before the decorated function.
    """
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        if self.is_expired():
            self.authenticate()
        return func(self, *args, **kwargs)
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
    _instance = None

    def __new__(cls, config_path):
        if cls._instance is None:
            cls._instance = super(SyncHttpxClient, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, config_path):
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
        if self.session:
            self.session.close()
            self.session = None

    def authenticate(self):
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
        kwargs = self._prepare_request_kwargs(kwargs)
        return await self.session.request(**kwargs)

    async def send(self, request, **kwargs):
        """Send a prepared request."""
        if self.session is None:
            self.session = httpx.AsyncClient(base_url=self.base_url, timeout=60.0, verify=False)
            await self.authenticate()

        if self.is_expired():
            await self.authenticate()

        new_headers = dict(request.headers)
        if self.auth_type == "basic":
            cookies = self._get_cookies()
            if "cookie" not in new_headers:
                new_headers["cookie"] = "; ".join([f"{k}={v}" for k, v in cookies.items()])

        new_headers.update(self._get_headers())
        new_request = httpx.Request(
            method=request.method,
            url=request.url,
            headers=new_headers,
            content=request.content,
        )
        return await self.session.send(new_request, **kwargs)


def create_routing_director_client():
    config_path = os.getenv("MCP_CONFIG", "NO_CONFIG")
    if USE_EXTERNAL_API:
        return SyncHttpxClient(config_path=config_path)
    return InternalSyncClient(config_path=config_path)
    #return InternalClient(config_path=config_path)


def create_routing_director_async_client():
    config_path = os.getenv("MCP_CONFIG", "NO_CONFIG")
    if USE_EXTERNAL_API:
        return AsyncHttpxClient(config_path=config_path)
    else:
        logger.debug("Cannot create AsyncHttpxClient because USE_EXTERNAL_API is false. Exiting")
        return None
