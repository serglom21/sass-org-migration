"""Remove credential fields before anything is printed or written to the checklist."""

from __future__ import annotations

from typing import Any

SECRET_KEYS = {
    "access_key",
    "accesskey",
    "authorization",
    "password",
    "secret",
    "secret_key",
    "secretkey",
    "token",
    "write_key",
    "writekey",
}


def is_secret_key(key: str) -> bool:
    return key.lower().replace("-", "_") in SECRET_KEYS


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: "***" if is_secret_key(key) else redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def error_text(exc: BaseException) -> str:
    body = getattr(exc, "body", None)
    status = getattr(exc, "status", None)
    path = getattr(exc, "path", None)
    detail = redact(body if body is not None else str(exc))
    text = str(detail)
    if len(text) > 400:
        text = text[:400] + "..."
    if status is None:
        return text
    return f"{status} {path}: {text}"
