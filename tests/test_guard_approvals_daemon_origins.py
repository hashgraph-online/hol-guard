"""Daemon request parsing, event tokens and origin checks."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_approvals_support import (
    _disable_real_desktop_notification_setup as _disable_real_desktop_notification_setup,
)
from tests.guard_approvals_support import (
    _guard_json_headers,
)


class TestGuardApprovals:
    def test_guard_daemon_event_stream_rejects_query_token_and_records_audit(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/events/stream?token={daemon._server.auth_token}",
                method="GET",
            )
            try:
                with urllib.request.urlopen(request, timeout=5):
                    raise AssertionError("expected HTTPError for query-token event stream auth")
            except urllib.error.HTTPError as error:
                payload = json.loads(error.read().decode("utf-8"))
                status = error.code
        finally:
            daemon.stop()

        assert status == 401
        assert payload["error"] == "unauthorized"
        auth_events = store.list_events(event_name="daemon.auth.unauthorized")
        assert auth_events[-1]["payload"]["path"] == "/v1/events/stream"
        url_token_events = store.list_events(event_name="daemon.auth.query_token_rejected")
        assert url_token_events[-1]["payload"]["path"] == "/v1/events/stream"
        assert url_token_events[-1]["payload"]["has_query_token"] is True

    def test_guard_daemon_event_stream_rejects_non_ascii_query_token(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/events/stream?token={urllib.parse.quote('ñ')}",
                method="GET",
            )
            try:
                with urllib.request.urlopen(request, timeout=5):
                    raise AssertionError("expected HTTPError for non-ASCII query-token event stream auth")
            except urllib.error.HTTPError as error:
                payload = json.loads(error.read().decode("utf-8"))
                status = error.code
        finally:
            daemon.stop()

        assert status == 401
        assert payload["error"] == "unauthorized"

    def test_guard_daemon_ignores_invalid_json_body(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/approvals/missing/decision",
                data=b"{not-json",
                headers=_guard_json_headers(daemon._server.auth_token),
                method="POST",
            )
            try:
                urllib.request.urlopen(request, timeout=5)
            except urllib.error.HTTPError as error:
                payload = json.loads(error.read().decode("utf-8"))
                status = error.code
            else:
                raise AssertionError("expected HTTPError for invalid JSON body")
        finally:
            daemon.stop()

        assert status == 400
        assert payload["error"] == "invalid_request_body"

    def test_guard_daemon_escapes_html_values_in_approval_center(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        store.add_approval_request(
            GuardApprovalRequest(
                request_id='req-escape" onclick="alert(1)',
                harness="codex<script>",
                artifact_id="codex:project:workspace_skill",
                artifact_name="<img src=x onerror=alert(1)>",
                artifact_hash="hash-escape",
                policy_action="require-reapproval",
                recommended_scope="artifact",
                changed_fields=("<script>",),
                source_scope="project",
                config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
                review_command="hol-guard approvals approve req-escape",
                approval_url="http://127.0.0.1/pending",
            ),
            "2026-04-11T00:00:00+00:00",
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{daemon.port}/", timeout=5) as response:
                body = response.read().decode("utf-8")
        finally:
            daemon.stop()

        assert "<img src=x onerror=alert(1)>" not in body
        assert "codex<script>" not in body
        assert "guard-dashboard-root" in body
        assert "Local approval center" in body
        assert "Hashgraph Online" in body

    def test_guard_daemon_rejects_cross_origin_post_requests(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/policy/decisions",
                data=json.dumps(
                    {
                        "harness": "codex",
                        "scope": "harness",
                        "action": "allow",
                    }
                ).encode("utf-8"),
                headers={
                    **_guard_json_headers(daemon._server.auth_token),
                    "Origin": "https://evil.example",
                },
                method="POST",
            )
            try:
                urllib.request.urlopen(request, timeout=5)
            except urllib.error.HTTPError as error:
                payload = json.loads(error.read().decode("utf-8"))
                status = error.code
            else:
                raise AssertionError("expected HTTPError for disallowed origin")
        finally:
            daemon.stop()

        assert status == 403
        assert payload["error"] == "forbidden_origin"

    def test_guard_daemon_rejects_cross_origin_options_requests(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/requests/missing/approve",
                headers={"Origin": "https://evil.example"},
                method="OPTIONS",
            )
            try:
                urllib.request.urlopen(request, timeout=5)
            except urllib.error.HTTPError as error:
                status = error.code
            else:
                raise AssertionError("expected HTTPError for disallowed preflight origin")
        finally:
            daemon.stop()

        assert status == 403

    def test_guard_daemon_allows_local_options_requests_with_guard_headers(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/requests/missing/approve",
                headers={"Origin": f"http://127.0.0.1:{daemon.port}"},
                method="OPTIONS",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                allow_headers = response.headers.get("Access-Control-Allow-Headers")
                status = response.status
        finally:
            daemon.stop()

        assert status == 200
        assert allow_headers == ("Authorization, Content-Type, Last-Event-ID, X-Guard-Dashboard-Session, X-Guard-Token")

    def test_guard_daemon_blocks_hosted_origin_on_nondashboard_posts(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            options_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/initialize",
                headers={"Origin": "https://hol.org"},
                method="OPTIONS",
            )
            try:
                urllib.request.urlopen(options_request, timeout=5)
            except urllib.error.HTTPError as error:
                options_status = error.code
            else:
                options_status = 200

            post_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/initialize",
                data=json.dumps({"client_name": "browser"}).encode("utf-8"),
                headers={
                    **_guard_json_headers(daemon._server.auth_token),
                    "Origin": "https://hol.org",
                },
                method="POST",
            )
            try:
                urllib.request.urlopen(post_request, timeout=5)
            except urllib.error.HTTPError as error:
                post_status = error.code
            else:
                post_status = 200
        finally:
            daemon.stop()

        assert options_status == 403
        assert post_status == 403

    def test_guard_daemon_includes_cors_headers_on_unauthorized_local_post(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/requests/missing/approve",
                data=json.dumps({"scope": "artifact"}).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Origin": f"http://127.0.0.1:{daemon.port}",
                },
                method="POST",
            )
            try:
                urllib.request.urlopen(request, timeout=5)
            except urllib.error.HTTPError as error:
                status = error.code
                payload = json.loads(error.read().decode("utf-8"))
                allow_origin = error.headers.get("Access-Control-Allow-Origin")
            else:
                raise AssertionError("expected HTTPError for missing auth token")
        finally:
            daemon.stop()

        assert status == 401
        assert payload["error"] == "unauthorized"
        assert allow_origin == f"http://127.0.0.1:{daemon.port}"

    def test_guard_daemon_rejects_spoofed_localhost_origin_post_requests(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/policy/decisions",
                data=json.dumps(
                    {
                        "harness": "codex",
                        "scope": "harness",
                        "action": "allow",
                    }
                ).encode("utf-8"),
                headers={
                    **_guard_json_headers(daemon._server.auth_token),
                    "Origin": "http://127.0.0.1.evil.example",
                },
                method="POST",
            )
            try:
                urllib.request.urlopen(request, timeout=5)
            except urllib.error.HTTPError as error:
                payload = json.loads(error.read().decode("utf-8"))
                status = error.code
            else:
                raise AssertionError("expected HTTPError for spoofed localhost origin")
        finally:
            daemon.stop()

        assert status == 403
        assert payload["error"] == "forbidden_origin"

    def test_guard_daemon_rejects_malformed_origin_post_requests(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/policy/decisions",
                data=json.dumps(
                    {
                        "harness": "codex",
                        "scope": "harness",
                        "action": "allow",
                    }
                ).encode("utf-8"),
                headers={
                    **_guard_json_headers(daemon._server.auth_token),
                    "Origin": "http://localhost:abc",
                },
                method="POST",
            )
            try:
                urllib.request.urlopen(request, timeout=5)
            except urllib.error.HTTPError as error:
                payload = json.loads(error.read().decode("utf-8"))
                status = error.code
            else:
                raise AssertionError("expected HTTPError for malformed origin")
        finally:
            daemon.stop()

        assert status == 403
        assert payload["error"] == "forbidden_origin"
