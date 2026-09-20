from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import cast

import pytest
from typing_extensions import override

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli import commands as guard_commands
from codex_plugin_scanner.guard.cli.commands_sync_output import sync_failure_payload, sync_success_payload
from codex_plugin_scanner.guard.runtime.runner import GuardSyncAuthorizationExpiredError


@pytest.mark.parametrize("status", [401, 403, 409])
def test_sync_cli_retains_real_http_status_without_reading_response_body(
    status: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    body = b"private-fixture-response-body"
    failures: list[urllib.error.HTTPError] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            _ = self.wfile.write(body)

        @override
        def log_message(self, format: str, *_args: object) -> None:
            return None

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()

        def auth_context(_store: object) -> dict[str, object]:
            return {"access_token": "synthetic-token", "sync_url": "http://127.0.0.1"}

        def sync(_store: object, **_kwargs: object) -> dict[str, object]:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            try:
                _ = cast(object, opener.open(f"http://127.0.0.1:{server.server_port}/sync", timeout=2))
            except urllib.error.HTTPError as error:
                failures.append(error)
                kind = GuardSyncAuthorizationExpiredError if status == 401 else RuntimeError
                raise kind("Synchronization request was rejected.") from error
            raise AssertionError("Negative HTTP fixture unexpectedly succeeded")

        monkeypatch.setattr(guard_commands, "_resolve_guard_sync_auth_context", auth_context)
        monkeypatch.setattr(guard_commands, "sync_local_guard_cloud_proof", sync)
        try:
            result = main(["guard", "sync", "--home", str(tmp_path / "home"), "--json"])
            payload = cast(dict[str, object], json.loads(capsys.readouterr().out))
        finally:
            server.shutdown()
            thread.join(timeout=2)
    assert result == 1
    assert payload == {"synced": False, "error": "Synchronization request was rejected.", "http_status": status}
    assert len(failures) == 1
    assert failures[0].read() == body
    failures[0].close()


@pytest.mark.parametrize("status", [True, "403", 403.0, 399, 600, None])
def test_sync_failure_ignores_non_error_http_codes(status: object) -> None:
    error = urllib.error.HTTPError("https://fixture.invalid", cast(int, status), "fixture", Message(), None)
    assert sync_failure_payload(error, message="bounded message") == {
        "synced": False,
        "error": "bounded message",
    }


def test_sync_failure_uses_only_actual_http_error_in_explicit_cause_chain() -> None:
    class UnrelatedError(RuntimeError):
        code: int = 403
        http_status: int = 409

    outer = UnrelatedError("outer failure")
    outer.__context__ = urllib.error.HTTPError("https://fixture.invalid", 401, "fixture", Message(), None)
    assert sync_failure_payload(outer) == {"synced": False, "error": "outer failure"}
    outer.__cause__ = RuntimeError("intermediate failure")
    outer.__cause__.__cause__ = urllib.error.HTTPError("https://fixture.invalid", 409, "fixture", Message(), None)
    assert sync_failure_payload(outer) == {"synced": False, "error": "outer failure", "http_status": 409}


def test_sync_failure_bounds_explicit_cause_cycles_and_depth() -> None:
    outer = RuntimeError("outer failure")
    current = outer
    for _ in range(7):
        current.__cause__ = RuntimeError("intermediate failure")
        current = current.__cause__
    current.__cause__ = urllib.error.HTTPError("https://fixture.invalid", 409, "fixture", Message(), None)
    assert sync_failure_payload(outer) == {"synced": False, "error": "outer failure"}
    outer.__cause__ = outer
    assert sync_failure_payload(outer) == {"synced": False, "error": "outer failure"}


def test_sync_summary_preserves_explicit_outer_values() -> None:
    payload: dict[str, object] = {
        "synced": True,
        "receipt_upload_status": "explicit",
        "policy_rejection_reason": None,
        "receipts": {
            "receipt_upload_status": "uploaded",
            "policy_validation_status": "verified",
            "policy_application_status": "applied",
            "policy_rejection_reason": "inner",
            "unrelated": "excluded",
        },
    }
    assert sync_success_payload(payload) is payload
    assert payload["receipt_upload_status"] == "explicit"
    assert payload["policy_validation_status"] == "verified"
    assert payload["policy_application_status"] == "applied"
    assert payload["policy_rejection_reason"] is None
    assert "unrelated" not in payload


@pytest.mark.parametrize("receipts", [None, [], "invalid"])
def test_sync_summary_preserves_non_object_receipts(receipts: object) -> None:
    payload = {"synced": True, "receipts": receipts}
    assert sync_success_payload(payload) == {"synced": True, "receipts": receipts}
