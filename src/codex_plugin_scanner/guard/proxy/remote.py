"""Remote MCP proxy helpers."""

from __future__ import annotations

import json
import urllib.request
from typing import Any
from urllib.parse import urljoin, urlsplit

from .stdio import _redact_json


class RemoteGuardProxy:
    """Forward remote MCP requests while enforcing basic Guard transport policy."""

    def __init__(
        self,
        base_url: str,
        allow_insecure_localhost: bool = False,
    ) -> None:
        parsed = urlsplit(base_url)
        is_localhost = parsed.hostname in {"127.0.0.1", "localhost"}
        if parsed.scheme != "https" and not (allow_insecure_localhost and is_localhost):
            raise ValueError("Guard remote proxy requires HTTPS unless localhost mode is explicitly enabled.")
        self.base_url = base_url.rstrip("/") + "/"
        self.events: list[dict[str, Any]] = []

    def forward(
        self,
        path: str,
        payload: dict[str, Any],
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        request_headers = {"Content-Type": "application/json", **(headers or {})}
        request = urllib.request.Request(
            urljoin(self.base_url, path.lstrip("/")),
            data=json.dumps(payload).encode("utf-8"),
            headers=request_headers,
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            response_payload = json.loads(response.read().decode("utf-8"))
        self.events.append(
            {
                "path": path,
                "headers": _redact_json(request_headers),
                "payload": _redact_json(payload),
            }
        )
        return response_payload
