"""Region-aware Sentry API client."""

from __future__ import annotations

import re
import time
from typing import Any

import httpx

_LINK_PART = re.compile(r"<([^>]+)>\s*;\s*([^,]*)")
_RETRY_STATUSES = {429}
_MAX_ATTEMPTS = 6


class ApiError(Exception):
    def __init__(self, method: str, path: str, status: int, body: Any):
        self.method = method
        self.path = path
        self.status = status
        self.body = body
        super().__init__(f"{method} {path} -> {status}: {body}")


def next_link(header: str | None) -> str | None:
    """Return the URL for rel=next when that page has results."""
    if not header:
        return None
    for match in _LINK_PART.finditer(header):
        url, rest = match.group(1), match.group(2)
        attrs: dict[str, str] = {}
        for piece in rest.split(";"):
            if "=" not in piece:
                continue
            key, value = piece.split("=", 1)
            attrs[key.strip()] = value.strip().strip('"')
        if attrs.get("rel") != "next":
            continue
        if attrs.get("results") == "false":
            continue
        return url
    return None


def _retry_delay(response: httpx.Response, attempt: int) -> float:
    header = response.headers.get("Retry-After")
    if header:
        try:
            return max(float(header), 0.0)
        except ValueError:
            pass
    return min(2**attempt, 30)


class SentryClient:
    def __init__(
        self,
        host: str,
        token: str,
        org: str,
        *,
        transport: httpx.BaseTransport | None = None,
    ):
        self.org = org
        self.base_url = _normalize_base(host)
        kwargs: dict[str, Any] = {
            "headers": {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            "timeout": 60.0,
            "follow_redirects": True,
        }
        if transport is not None:
            kwargs["transport"] = transport
        self._http = httpx.Client(**kwargs)

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> SentryClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
    ) -> httpx.Response:
        url = self._url(path)
        last: httpx.Response | None = None
        for attempt in range(_MAX_ATTEMPTS):
            response = self._http.request(method, url, params=params, json=json)
            last = response
            if response.status_code not in _RETRY_STATUSES or attempt == _MAX_ATTEMPTS - 1:
                break
            time.sleep(_retry_delay(response, attempt))
            params = None
        assert last is not None
        if last.status_code >= 400:
            raise ApiError(method, path, last.status_code, _error_body(last))
        return last

    def get_json(self, path: str, params: dict[str, Any] | None = None) -> Any:
        response = self.request("GET", path, params=params)
        if response.status_code == 204 or not response.content:
            return None
        return response.json()

    def get_all(self, path: str, params: dict[str, Any] | None = None) -> list[Any]:
        items: list[Any] = []
        url: str | None = path
        query = params
        while url:
            response = self.request("GET", url, params=query)
            query = None
            data = response.json() if response.content else []
            items.extend(_unwrap_list(data, path))
            url = next_link(response.headers.get("Link"))
        return items

    def get_optional(
        self, path: str, params: dict[str, Any] | None = None
    ) -> tuple[Any, ApiError | None]:
        try:
            return self.get_json(path, params=params), None
        except ApiError as exc:
            if exc.status in (400, 403, 404):
                return None, exc
            raise

    def get_optional_list(
        self, path: str, params: dict[str, Any] | None = None
    ) -> tuple[list[Any], ApiError | None]:
        try:
            return self.get_all(path, params=params), None
        except ApiError as exc:
            if exc.status in (400, 403, 404):
                return [], exc
            raise

    def post(self, path: str, json: Any) -> Any:
        response = self.request("POST", path, json=json)
        if response.status_code == 204 or not response.content:
            return None
        return response.json()

    def put(self, path: str, json: Any) -> Any:
        response = self.request("PUT", path, json=json)
        if response.status_code == 204 or not response.content:
            return None
        return response.json()

    def _url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if not path.startswith("/"):
            path = "/" + path
        return self.base_url + path


def _normalize_base(host: str) -> str:
    base = host.rstrip("/")
    if base.endswith("/api/0"):
        return base
    return base + "/api/0"


def _unwrap_list(data: Any, path: str) -> list[Any]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("results", "data"):
            value = data.get(key)
            if isinstance(value, list):
                return value
    raise ApiError("GET", path, 200, "expected a list response")


def _error_body(response: httpx.Response) -> Any:
    try:
        return response.json()
    except Exception:
        text = response.text[:500]
        return text or response.status_code
