"""Bind workspace-audit requests to the trusted sync origin before adding credentials."""

from __future__ import annotations

import json
from collections.abc import Callable
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request

from .cli.oauth_client import validate_guard_sync_endpoint


def build_cloud_workspace_audit_request(
    *,
    auth_context: dict[str, object],
    request_url: str,
    method: str,
    payload: dict[str, object] | None,
    build_headers: Callable[..., dict[str, str]],
) -> Request:
    sync_url = auth_context.get("sync_url")
    if not isinstance(sync_url, str):
        raise ValueError("Guard workspace audit requires a trusted sync URL.")
    sync = urlsplit(validate_guard_sync_endpoint(sync_url))
    issuer = urlunsplit((sync.scheme, sync.netloc, "", "", ""))
    request_url = validate_guard_sync_endpoint(request_url, issuer=issuer)
    # Local development origins never receive reusable credentials.
    headers = build_headers(auth_context, request_url=request_url, method=method) if sync.scheme == "https" else {}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    return Request(
        request_url,
        data=json.dumps(payload).encode("utf-8") if payload is not None else None,
        headers=headers,
        method=method,
    )
