#!/usr/bin/env python3
"""Stateful provider-neutral MDM Cloud integration lab over real HTTP."""

from __future__ import annotations

import http.client as http_client
import json
import math
import os
import uuid
from collections.abc import Mapping
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from codex_plugin_scanner.guard.mdm.cloud_control import ContractError

MAX_BODY_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 24
MAX_JSON_NODES = 4096
MAX_JSON_COLLECTION_ITEMS = 512
MAX_JSON_STRING_BYTES = 64 * 1024
ADMIN_HEADER = "x-hol-mdm-lab-admin"
NATIVE_CERTIFICATION_GATES = [
    "apple-apns-enrollment",
    "apple-automated-device-enrollment",
    "apple-supervision",
    "apple-signing-notarization",
    "windows-csp-enrollment",
    "windows-system-context",
    "windows-authenticode-wdac",
    "real-vendor-command-delivery",
]


def json_bytes(value: object) -> bytes:
    """Return the deterministic JSON representation used on the lab wire."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _strict_object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("duplicate_json_key")
        result[key] = value
    return result


def _validate_json_limits(value: object) -> None:
    stack: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise ContractError("json_node_limit_exceeded", 413)
        if depth > MAX_JSON_DEPTH:
            raise ContractError("json_depth_limit_exceeded", 413)
        if current is None or isinstance(current, bool):
            continue
        if isinstance(current, int):
            continue
        if isinstance(current, float):
            if not math.isfinite(current):
                raise ContractError("invalid_json_number")
            continue
        if isinstance(current, str):
            if len(current.encode("utf-8")) > MAX_JSON_STRING_BYTES:
                raise ContractError("json_string_limit_exceeded", 413)
            continue
        if isinstance(current, list):
            if len(current) > MAX_JSON_COLLECTION_ITEMS:
                raise ContractError("json_collection_limit_exceeded", 413)
            stack.extend((item, depth + 1) for item in current)
            continue
        if isinstance(current, dict):
            if len(current) > MAX_JSON_COLLECTION_ITEMS:
                raise ContractError("json_collection_limit_exceeded", 413)
            stack.extend((item, depth + 1) for item in current.values())
            continue
        raise ContractError("invalid_json_value")


def decode_json_object(body: bytes) -> dict[str, object]:
    if len(body) > MAX_BODY_BYTES:
        raise ContractError("request_too_large", 413)
    try:
        value = json.loads(body or b"{}", object_pairs_hook=_strict_object_pairs)
    except UnicodeDecodeError as error:
        raise ContractError("invalid_utf8") from error
    except json.JSONDecodeError as error:
        raise ContractError("invalid_json") from error
    if not isinstance(value, dict):
        raise ContractError("invalid_json_object")
    _validate_json_limits(value)
    return value


def read_json(request: BaseHTTPRequestHandler) -> dict[str, object]:
    raw_length = request.headers.get("content-length", "0")
    try:
        length = int(raw_length)
    except ValueError as error:
        raise ContractError("invalid_content_length") from error
    if length < 0 or length > MAX_BODY_BYTES:
        raise ContractError("request_too_large", 413)
    return decode_json_object(request.rfile.read(length))


def http_request(
    method: str,
    url: str,
    payload: object | None = None,
    headers: Mapping[str, str] | None = None,
    timeout: float = 10,
) -> tuple[int, dict[str, str], object | None]:
    body = None if payload is None else json_bytes(payload)
    request = Request(
        url,
        data=body,
        method=method,
        headers={"content-type": "application/json", **dict(headers or {})},
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read(MAX_BODY_BYTES + 1)
            if len(raw) > MAX_BODY_BYTES:
                return 502, {}, {"error": "response_too_large"}
            if not raw:
                decoded: object | None = None
            else:
                try:
                    decoded = json.loads(raw)
                except json.JSONDecodeError:
                    decoded = {"error": "invalid_response_body"}
            return (
                response.status,
                {key.lower(): value for key, value in response.headers.items()},
                decoded,
            )
    except HTTPError as error:
        raw = error.read(MAX_BODY_BYTES + 1)
        try:
            data: object | None = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            data = {"error": "invalid_error_body"}
        return error.code, {key.lower(): value for key, value in error.headers.items()}, data
    except (URLError, TimeoutError, http_client.HTTPException, ConnectionError) as error:
        reason = getattr(error, "reason", error)
        return 599, {}, {"error": "network_unavailable", "detail": type(reason).__name__}


# Backwards-compatible names imported by the existing lab modules.
jbytes = json_bytes
http = http_request
ADMIN = ADMIN_HEADER
NATIVE = NATIVE_CERTIFICATION_GATES
MAX = MAX_BODY_BYTES


def _assert_safe_parent(path: Path) -> None:
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    if parent.is_symlink():
        raise ContractError("unsafe_parent_symlink")
    if not parent.is_dir():
        raise ContractError("unsafe_parent_type")


def atomic(path: Path, data: bytes) -> None:
    """Atomically write a machine-owned lab file without following symlinks."""

    _assert_safe_parent(path)
    if path.is_symlink():
        raise ContractError("unsafe_destination_symlink")
    if path.exists() and not path.is_file():
        raise ContractError("unsafe_destination_type")
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short atomic write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        directory_descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if temporary.exists():
            temporary.unlink()


def _safe_identifier(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 128
        or not value[0].isalnum()
        or any(
            character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-" for character in value
        )
    ):
        raise ContractError(f"{name}_invalid")
    return value


def _same_json(left: object, right: object) -> bool:
    return json_bytes(left) == json_bytes(right)


def _redact_detail(value: object, depth: int = 0) -> object:
    if depth > 12:
        return "[truncated]"
    if isinstance(value, dict):
        output: dict[str, object] = {}
        for key, item in value.items():
            lowered = key.lower()
            if any(
                token in lowered
                for token in (
                    "token",
                    "secret",
                    "password",
                    "private",
                    "authorization",
                    "cookie",
                    "command",
                    "script",
                    "shell",
                )
            ):
                output[key] = "[redacted]"
            else:
                output[key] = _redact_detail(item, depth + 1)
        return output
    if isinstance(value, list):
        return [_redact_detail(item, depth + 1) for item in value[:128]]
    if isinstance(value, str):
        return value[:512]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:128]
