"""HTTP transport security regressions for the local Guard daemon."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon.manager import load_guard_daemon_auth_token
from codex_plugin_scanner.guard.local_dashboard_session import LOCAL_DASHBOARD_SESSION_AUDIENCE
from codex_plugin_scanner.guard.store import GuardStore


def _dashboard_token(store: GuardStore) -> str:
    auth_token = load_guard_daemon_auth_token(store.guard_home)
    assert auth_token is not None
    payload_json = json.dumps(
        {
            "aud": LOCAL_DASHBOARD_SESSION_AUDIENCE,
            "version": "guard-local-daemon-session.v1",
            "expires_at": datetime(2099, 1, 1, tzinfo=timezone.utc).isoformat(),
            "surface": "approval-center",
        },
        separators=(",", ":"),
    )
    payload = base64.urlsafe_b64encode(payload_json.encode("utf-8")).decode("ascii").rstrip("=")
    signature = hmac.new(auth_token.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    return f"gld1.{payload}.{encoded_signature}"


def test_json_response_escapes_html_metacharacters_without_changing_values(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    hostile_surface = "</script><script>alert(1)</script>&"
    daemon.start()
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{daemon.port}/v1/apps/connect",
            data=json.dumps({"harness": "cursor", "surface": hostile_surface}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Origin": "http://127.0.0.1:6174",
                "X-Guard-Dashboard-Session": _dashboard_token(store),
            },
            method="POST",
        )
        with pytest.raises(urllib.error.HTTPError) as raised:
            urllib.request.urlopen(request, timeout=5)
        raw_body = raised.value.read()
        response_headers = raised.value.headers
    finally:
        daemon.stop()

    assert raised.value.code == 400
    assert json.loads(raw_body)["error"]["surface"] == hostile_surface
    assert b"<" not in raw_body
    assert b">" not in raw_body
    assert b"&" not in raw_body
    assert b"\\u003cscript\\u003e" in raw_body
    assert response_headers.get("Content-Type") == "application/json; charset=utf-8"
    assert response_headers.get("X-Content-Type-Options") == "nosniff"
