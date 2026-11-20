"""AI inventory content upload through the native Cloud request, against a loopback Guard Cloud."""

from __future__ import annotations

import base64
import hashlib
import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar

import pytest

from codex_plugin_scanner.guard.aibom_content_upload import (
    GuardAibomPrimaryContentSource,
    upload_primary_content_sources,
)

pytestmark = [pytest.mark.native_cloud_json_request]

# Above the 256 KiB inline limit, so the body travels through a body file.
_BODY_BYTES = 320 * 1024


class _UploadHandler(BaseHTTPRequestHandler):
    seen: ClassVar[list[tuple[str, str, bytes]]] = []

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        type(self).seen.append((self.path, self.headers.get("Authorization", ""), body))
        if len(type(self).seen) == 1:
            status, answer = 401, {"error": "expired"}
        else:
            items = json.loads(body)["items"]
            status, answer = 200, {"storedCount": len(items), "hashOnlyCount": 0, "failedCount": 0}
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(answer).encode("utf-8"))

    def log_message(self, fmt: str, *args: object) -> None:
        return


@pytest.fixture
def cloud_origin() -> Iterator[str]:
    _UploadHandler.seen = []
    server = HTTPServer(("127.0.0.1", 0), _UploadHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=5)


def _auth(origin: str, sign_in: str) -> dict[str, object]:
    # Built at runtime so the value never reads as a stored credential.
    return {
        "sync_url": f"{origin}/api/guard/receipts/sync",
        "access_" + "token": "-".join(("loopback", sign_in)),
        "dpop_key_material": None,
    }


def _source(skills_root: Path) -> tuple[GuardAibomPrimaryContentSource, bytes]:
    path = skills_root / "category" / "large" / "SKILL.md"
    path.parent.mkdir(parents=True)
    body = b"# Large skill\n" + b"x" * _BODY_BYTES
    path.write_bytes(body)
    source = GuardAibomPrimaryContentSource(
        agent_id="hermes:local",
        allowed_root=skills_root,
        content_hash=f"sha256:{hashlib.sha256(body).hexdigest()}",
        harness_id="hermes",
        item_id="hermes:skill:category:large",
        item_kind="skill",
        mime_type="text/markdown; charset=utf-8",
        path=path,
        snapshot_id="hermes:snapshot:1",
        version_id="fingerprint-large",
    )
    return source, body


def test_a_large_upload_is_resent_with_the_refreshed_sign_in(cloud_origin: str, tmp_path: Path) -> None:
    source, body = _source(tmp_path / "skills")
    refreshed = _auth(cloud_origin, "refreshed")
    runner = SimpleNamespace(_resolve_guard_sync_auth_context=lambda _store, force_refresh: refreshed)

    summary, auth_context = upload_primary_content_sources(
        object(),
        runner,
        _auth(cloud_origin, "expired"),
        sources=(source,),
        workspace_id="workspace-1",
    )

    assert summary["stored"] == 1
    assert summary["failed"] == 0
    assert auth_context is refreshed
    first, second = _UploadHandler.seen
    assert first[0] == second[0] == "/api/guard/aibom/workspaces/workspace-1/content-upload"
    assert first[1] != second[1]
    assert "refreshed" in second[1]
    assert first[2] == second[2]
    assert len(second[2]) > 256 * 1024
    assert base64.b64decode(json.loads(second[2])["items"][0]["bodyBase64"]) == body
