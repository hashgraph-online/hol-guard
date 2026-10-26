"""Bounded authenticated hook transport sharing one caller deadline."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse


def post_hook_json(
    endpoint: str,
    token: str,
    data: bytes,
    *,
    opener: urllib.request.OpenerDirector,
    deadline: float,
    max_bytes: int,
) -> dict[str, object] | None:
    from .bounded_cli_hook_daemon import _assert_loopback_http_url

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    request = urllib.request.Request(
        endpoint,
        data=data,
        headers={"Content-Type": "application/json", "X-Guard-Token": token},
        method="POST",
    )
    try:
        _assert_loopback_http_url(endpoint)
        with opener.open(request, timeout=remaining) as response:
            final_url = response.geturl()
            if final_url:
                _assert_loopback_http_url(final_url)
            if response.status != 200:
                return None
            body = response.read(max_bytes + 1)
    except (OSError, urllib.error.URLError, TimeoutError, ValueError):
        return None
    if time.monotonic() >= deadline or len(body) > max_bytes:
        return None
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


def prepare_grok_prompt(
    endpoint: str,
    token: str,
    input_text: str,
    *,
    opener: urllib.request.OpenerDirector,
    deadline: float,
    max_bytes: int,
) -> str | None:
    from .bounded_cli_hook_envelope import _json_object

    payload = _json_object(input_text)
    if payload is None:
        return None
    workspace = payload.get("cwd")
    if not isinstance(workspace, str) or not workspace.strip():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        payload.pop("guard_remaining_seconds", None)
        payload["guard_remaining_ms"] = max(1, int(remaining * 1000))
        return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
    request = {"cwd": workspace} if isinstance(workspace, str) else {}
    url = urlparse(endpoint)
    ready = post_hook_json(
        url._replace(path=url.path.rstrip("/") + "/readiness").geturl(),
        token,
        json.dumps(request, separators=(",", ":")).encode("utf-8"),
        opener=opener,
        deadline=deadline,
        max_bytes=max_bytes,
    )
    if ready is None or ready.get("ready") is not True:
        return None
    if ready.get("native_required") is not False and (
        ready.get("workspace_acknowledged") is not True or ready.get("worker_ready") is not True
    ):
        return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    payload.pop("guard_remaining_seconds", None)
    payload["guard_remaining_ms"] = max(1, int(remaining * 1000))
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
