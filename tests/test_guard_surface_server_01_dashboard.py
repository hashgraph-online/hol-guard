from __future__ import annotations

from tests.test_guard_surface_server import (
    LOCAL_DASHBOARD_SESSION_AUDIENCE,
    LOCAL_DASHBOARD_SESSION_VERSION,
    GuardApprovalRequest,
    GuardDaemonServer,
    GuardStore,
    _decode_dashboard_session_claims,
    build_local_dashboard_session_token,
    daemon_server_module,
    json,
    urllib,
)


class TestGuardSurfaceServer:
    def test_local_dashboard_session_preserves_reserved_claims(self) -> None:
        token = build_local_dashboard_session_token(
            auth_token="daemon-auth-token",
            surface="approval-center",
            expires_in_seconds=60,
            extra_claims={
                "surface": "cli",
                "version": "override-version",
                "expires_at": "1970-01-01T00:00:00+00:00",
                "custom": "value",
            },
        )

        claims = _decode_dashboard_session_claims(token)

        assert claims["version"] == LOCAL_DASHBOARD_SESSION_VERSION
        assert claims["aud"] == LOCAL_DASHBOARD_SESSION_AUDIENCE
        assert claims["surface"] == "approval-center"
        assert claims["expires_at"] != "1970-01-01T00:00:00+00:00"
        assert claims["custom"] == "value"

    def test_guard_daemon_serves_dashboard_shell_for_home_and_section_routes(self, tmp_path) -> None:
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            for route in (
                "/",
                "/home",
                "/inbox",
                "/protect",
                "/evidence",
                "/extensions",
                "/supply-chain",
                "/audit",
                "/policy",
                "/feed-health",
                "/settings",
            ):
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{daemon.port}{route}",
                    timeout=5,
                ) as response:
                    body = response.read().decode("utf-8")

                assert response.status == 200
                assert "text/html" in response.headers.get("Content-Type", "")
                assert response.headers.get("Content-Security-Policy") == (
                    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                    "img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; "
                    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
                )
                assert response.headers.get("Referrer-Policy") == "no-referrer"
                assert response.headers.get("X-Content-Type-Options") == "nosniff"
                assert "Loading Local approval center" in body
                assert "fonts.googleapis.com" not in body
                assert "sessionStorage.setItem" not in body
                assert "guard-token" not in body
                assert daemon._server.auth_token not in body
        finally:
            daemon.stop()

    def test_guard_daemon_static_dashboard_assets_disable_browser_cache(self, tmp_path) -> None:
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{daemon.port}/assets/guard-dashboard.js",
                timeout=5,
            ) as response:
                response.read()
            with urllib.request.urlopen(
                f"http://127.0.0.1:{daemon.port}/assets/index.css",
                timeout=5,
            ) as css_response:
                css_body = css_response.read().decode("utf-8")
            with urllib.request.urlopen(
                f"http://127.0.0.1:{daemon.port}/favicon.ico",
                timeout=5,
            ) as favicon_response:
                favicon_response.read()
        finally:
            daemon.stop()

        assert response.status == 200
        assert response.headers.get("Cache-Control") == "no-store, max-age=0"
        assert response.headers.get("Pragma") == "no-cache"
        assert response.headers.get("Expires") == "0"
        assert response.headers.get("Referrer-Policy") == "no-referrer"
        assert response.headers.get("X-Content-Type-Options") == "nosniff"
        assert css_response.status == 200
        assert css_response.headers.get("Referrer-Policy") == "no-referrer"
        assert css_response.headers.get("X-Content-Type-Options") == "nosniff"
        assert "fonts.googleapis.com" not in css_body
        assert favicon_response.status == 200
        assert favicon_response.headers.get("Cache-Control") == "no-store, max-age=0"

    def test_guard_daemon_dashboard_assets_use_oauth_connect_copy(self, tmp_path) -> None:
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{daemon.port}/assets/guard-dashboard.js",
                timeout=5,
            ) as response:
                dashboard_bundle = response.read().decode("utf-8")
        finally:
            daemon.stop()

        runtime_overview_chunk = dashboard_bundle
        feed_health_chunk = (
            daemon_server_module._STATIC_DIR / "assets" / "chunks" / "feed-health-workspace.js"
        ).read_text(encoding="utf-8")

        assert "Open Guard Cloud" in dashboard_bundle
        assert "Open pairing flow" not in dashboard_bundle
        assert "Open Guard connect" not in dashboard_bundle
        assert (
            "Browser pairing finished. Local Guard will retry the first proof sync automatically "
            "while the daemon is running, or you can run hol-guard sync now."
        ) in dashboard_bundle
        assert "Browser pairing finished. First proof sync has not completed yet." not in dashboard_bundle
        assert 'label: "First sync in progress"' in runtime_overview_chunk
        assert "Connected to Guard Cloud. Local Guard is sending the first shared proof now." in runtime_overview_chunk
        assert '"Sync pending"' not in runtime_overview_chunk
        assert "Guard Cloud is connected. Local Guard is finishing the first shared proof automatically." in (
            feed_health_chunk
        )
        assert "Cloud pairing is complete. Feed sync is in progress. First proof will arrive shortly." not in (
            feed_health_chunk
        )

    def test_guard_daemon_dashboard_shell_omits_local_auth_token(self, tmp_path) -> None:
        store = GuardStore(tmp_path / "guard-home")
        store.add_approval_request(
            GuardApprovalRequest(
                request_id="example-request",
                harness="codex",
                artifact_id="codex:project:dangerous-shell",
                artifact_name="Bash destructive shell command",
                artifact_hash="hash-123",
                policy_action="require-reapproval",
                recommended_scope="artifact",
                changed_fields=("tool_action_request",),
                source_scope="project",
                config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
                workspace=str(tmp_path / "workspace"),
                review_command="hol-guard approvals approve example-request",
                approval_url="http://127.0.0.1:4455/approvals/example-request",
            ),
            "2026-04-25T00:00:00+00:00",
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{daemon.port}/approvals/example-request",
                timeout=5,
            ) as response:
                body = response.read().decode("utf-8")
            approval_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/requests/example-request/approve",
                data=json.dumps({"scope": "artifact", "reason": "approved in test"}).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": daemon._server.auth_token,
                },
                method="POST",
            )
            with urllib.request.urlopen(approval_request, timeout=5) as approval_response:
                approval_payload = json.loads(approval_response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert response.status == 200
        assert "sessionStorage.setItem" not in body
        assert "guard-token" not in body
        assert daemon._server.auth_token not in body
        assert approval_response.status == 200
        assert approval_payload["resolved"] is True
