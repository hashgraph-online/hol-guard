"""Probe producer-owned disposable state through real resident/Core transport.

This creates no snapshots, account grants or provider operations. The caller
owns the fixture and supplies an explicitly selected source artifact.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon.manager import load_guard_daemon_auth_token
from codex_plugin_scanner.guard.native_resident_client import native_resident_client_request
from codex_plugin_scanner.guard.native_runtime import _isolated_environment, native_runtime_status
from codex_plugin_scanner.guard.store import GuardStore


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--guard-home", type=Path, required=True)
    parser.add_argument("--request-id", required=True)
    parser.add_argument("--runtime-sha256", required=True)
    args = parser.parse_args()
    status = native_runtime_status()
    assert status.available and status.compatible and status.identity and status.capabilities, status.reason
    assert status.identity.sha256 == args.runtime_sha256
    assert "native-local-business-review-queue-v1" in status.capabilities.features
    store = GuardStore(guard_home=args.guard_home)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        policy_request = sys.stdin.buffer.read(1024 * 1024 + 1)
        assert 0 < len(policy_request) <= 1024 * 1024
        reply = native_resident_client_request(
            executable=status.identity.path, guard_home=args.guard_home,
            environment=_isolated_environment(), payload=policy_request, timeout_seconds=3.0,
        )
        assert reply is not None
        acknowledgment = json.loads(reply)
        if "error" in acknowledgment:
            print(json.dumps({"policy_push_error_code": acknowledgment["error"]}))
        assert acknowledgment.get("generation") == 1 and "error" not in acknowledgment
        base = f"http://127.0.0.1:{daemon.port}"
        # The Core-local token stays within this disposable process and is never
        # returned in evidence. No account/provider credential is consulted.
        token = load_guard_daemon_auth_token(args.guard_home)
        assert token is not None
        headers = {"X-Guard-Token": token}
        def read(path):
            request = urllib.request.Request(base + path, headers=headers)
            try:
                response = urllib.request.urlopen(request, timeout=10)
            except urllib.error.HTTPError:
                encoded = native_resident_client_request(
                    executable=status.identity.path, guard_home=args.guard_home,
                    environment=_isolated_environment(),
                    payload=b'{"operation":"workspace_review_local_queue","request":{}}',
                    timeout_seconds=2.0,
                )
                native_reply = json.loads(encoded) if encoded else {}
                code = native_reply.get("error")
                print(json.dumps({"native_error_code": code if isinstance(code, str)
                    and code.startswith("native_") and len(code) < 128 else "no_finite_error_reply"}))
                raise
            with response:
                assert response.headers["Cache-Control"] == "no-store"
                body = response.read()
                assert b"CORE_TRANSPORT_PRIVATE_BODY_CANARY" not in body
                assert b"example.test" not in body
                return json.loads(body)
        page = read("/v1/requests?limit=1&status=pending")
        assert page["total_pending_count"] == 1 and page["next_cursor"] is None
        assert page["items"][0]["request_id"] == args.request_id
        detail = read(f"/v1/requests/{args.request_id}")
        assert detail["native_business_review_display_only"] is True
        assert detail["allowed_scopes"] == []
        summary = read(f"/v1/requests/{args.request_id}/business-summary")
        assert summary["request_id"] == args.request_id
        assert summary["service"] == "google_gmail" and summary["operation"] == "mail_send"
        assert summary["account_currentness"] == "not_asserted"
        assert summary["execution_state"] == "not_checked"
        assert store.get_approval_request(args.request_id) is None
        print(json.dumps({"kind": "native_producer_resident_core_http_source_integration",
            "passed": True, "runtime_sha256": args.runtime_sha256,
            "source_sha": status.capabilities.build_sha,
            "provider_journey": "NOT_RUN", "installed_auto_mode": "NOT_RUN"}))
    finally:
        daemon.stop()
        subprocess.run((str(status.identity.path), "resident-stop", "--state-dir",
            str(args.guard_home / "native-runtime")), capture_output=True, timeout=10, check=True)


if __name__ == "__main__":
    main()
