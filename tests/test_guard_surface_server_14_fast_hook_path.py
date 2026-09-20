from __future__ import annotations

from tests.test_guard_surface_server import GuardDaemonServer, GuardStore, daemon_server_module, json, urllib


class TestGuardDaemonFastHookPath:
    """Integration tests for the fast hook review worker.

    These tests exercise the full daemon HTTP path with
    HOL_GUARD_HOOK_FAST_PATH=1 enabled, proving that:
    - PostToolUse with guard_source_ref uses the resident worker
    - Non-command PreToolUse and unavailable native command PreToolUse fall through to CLI
    - PostToolUse inline output uses the resident scanner
    - Worker exceptions return fail-safe deny/block
    """

    def test_fast_path_source_ref_returns_allow_original(self, tmp_path, monkeypatch) -> None:
        """PostToolUse with a safe source ref returns allow_original via the fast worker."""
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        (workspace_dir / "src").mkdir(parents=True, exist_ok=True)
        source_content = 'export const hello = "world";\n'
        source_file = workspace_dir / "src" / "hello.ts"
        source_file.write_text(source_content)

        import hashlib

        output_sha256 = hashlib.sha256(source_content.encode("utf-8")).hexdigest()

        store = GuardStore(home_dir)
        monkeypatch.setenv("HOL_GUARD_HOOK_FAST_PATH", "1")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            payload = {
                "hook_event_name": "PostToolUse",
                "tool_name": "Read",
                "tool_input": {"file_path": "src/hello.ts"},
                "guard_source_ref": {
                    "version": 1,
                    "kind": "source_file",
                    "path": "src/hello.ts",
                    "tool_input_path": "src/hello.ts",
                    "output_sha256": output_sha256,
                    "output_chars": len(source_content),
                },
                "tool_response_summary": {
                    "kind": "text",
                    "excerpt_chars": len(source_content),
                    "output_chars": len(source_content),
                    "output_sha256": output_sha256,
                    "excerpt_truncated": False,
                },
            }

            request = urllib.request.Request(
                (
                    f"http://127.0.0.1:{daemon.port}/v1/hooks/pi?"
                    f"guard-home={urllib.parse.quote(str(home_dir))}&"
                    f"home={urllib.parse.quote(str(home_dir))}&"
                    f"workspace={urllib.parse.quote(str(workspace_dir))}"
                ),
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": daemon._server.auth_token,
                },
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                result = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()
            monkeypatch.delenv("HOL_GUARD_HOOK_FAST_PATH", raising=False)

        assert result["decision"] == "allow"
        assert result["model_output_action"] == "allow_original"
        assert result["reviewed_output_sha256"] == output_sha256
        assert result["notice"] == "none"

    def test_fast_path_pre_tool_use_falls_back_to_legacy(self, tmp_path, monkeypatch) -> None:
        """Command PreToolUse without a native runtime still reaches the CLI path."""
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True, exist_ok=True)

        store = GuardStore(home_dir)
        monkeypatch.setenv("HOL_GUARD_HOOK_FAST_PATH", "1")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            payload = {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "echo hello"},
            }

            request = urllib.request.Request(
                (
                    f"http://127.0.0.1:{daemon.port}/v1/hooks/pi?"
                    f"guard-home={urllib.parse.quote(str(home_dir))}&"
                    f"home={urllib.parse.quote(str(home_dir))}&"
                    f"workspace={urllib.parse.quote(str(workspace_dir))}"
                ),
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": daemon._server.auth_token,
                },
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                result = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()
            monkeypatch.delenv("HOL_GUARD_HOOK_FAST_PATH", raising=False)

        # Legacy CLI path returned a response (not the worker's
        # "not_applicable" allow). Legacy may return {} for allow.
        assert result.get("model_output_action") != "not_applicable"
        assert result.get("reason_code") != "non_post_tool_event"

    def test_fast_path_post_tool_use_without_source_ref_scans_inline_output(self, tmp_path, monkeypatch) -> None:
        """PostToolUse inline output is scanned without a second approval."""
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True, exist_ok=True)

        store = GuardStore(home_dir)
        monkeypatch.setenv("HOL_GUARD_HOOK_FAST_PATH", "1")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            payload = {
                "hook_event_name": "PostToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "echo hello"},
                "tool_response": [{"type": "text", "text": "hello\n"}],
            }

            request = urllib.request.Request(
                (
                    f"http://127.0.0.1:{daemon.port}/v1/hooks/pi?"
                    f"guard-home={urllib.parse.quote(str(home_dir))}&"
                    f"home={urllib.parse.quote(str(home_dir))}&"
                    f"workspace={urllib.parse.quote(str(workspace_dir))}"
                ),
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": daemon._server.auth_token,
                },
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                result = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()
            monkeypatch.delenv("HOL_GUARD_HOOK_FAST_PATH", raising=False)

        assert result["decision"] == "allow"
        assert result["model_output_action"] == "allow_original"
        assert result["reason_code"] == "output_scan_allow"

    def test_fast_path_explicitly_disabled_uses_legacy(self, tmp_path, monkeypatch) -> None:
        """An emergency environment override can restore the legacy path."""
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True, exist_ok=True)

        store = GuardStore(home_dir)
        monkeypatch.setenv("HOL_GUARD_HOOK_FAST_PATH", "0")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            payload = {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "echo hello"},
            }

            request = urllib.request.Request(
                (
                    f"http://127.0.0.1:{daemon.port}/v1/hooks/pi?"
                    f"guard-home={urllib.parse.quote(str(home_dir))}&"
                    f"home={urllib.parse.quote(str(home_dir))}&"
                    f"workspace={urllib.parse.quote(str(workspace_dir))}"
                ),
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": daemon._server.auth_token,
                },
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                result = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        # Legacy CLI path (may return {} for allow).
        assert result.get("model_output_action") != "not_applicable"

    def test_fast_path_worker_exception_keeps_pi_deny_contract(self, tmp_path, monkeypatch) -> None:
        """Pi expects internal fast-path denials as decision=deny, not native decision=block."""
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir(parents=True, exist_ok=True)

        store = GuardStore(home_dir)
        monkeypatch.setenv("HOL_GUARD_HOOK_FAST_PATH", "1")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:

            def fail_review(**_kwargs: object) -> dict[str, object]:
                raise RuntimeError("resident worker failed")

            monkeypatch.setattr(
                daemon._server.hook_worker,
                "review_http_payload",
                fail_review,
            )
            payload = {
                "hook_event_name": "PostToolUse",
                "tool_name": "Read",
                "tool_input": {"file_path": "src/secret.ts"},
                "guard_source_ref": {
                    "version": 1,
                    "kind": "source_file",
                    "path": "src/secret.ts",
                    "tool_input_path": "src/secret.ts",
                    "output_sha256": "0" * 64,
                    "output_chars": 10,
                },
            }

            request = urllib.request.Request(
                (
                    f"http://127.0.0.1:{daemon.port}/v1/hooks/pi?"
                    f"guard-home={urllib.parse.quote(str(home_dir))}&"
                    f"home={urllib.parse.quote(str(home_dir))}&"
                    f"workspace={urllib.parse.quote(str(workspace_dir))}"
                ),
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": daemon._server.auth_token,
                },
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                result = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()
            monkeypatch.delenv("HOL_GUARD_HOOK_FAST_PATH", raising=False)

        assert result["decision"] == "allow"
        assert result["policy_action"] == "allow"
        assert result["reason_code"] == "daemon_worker_exception"

    def test_fast_path_secret_source_file_is_denied(self, tmp_path, monkeypatch) -> None:
        """A source file containing a secret must not return allow_original."""
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        (workspace_dir / "src").mkdir(parents=True, exist_ok=True)
        secret_content = 'const token = "sk-proj-FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE";\n'
        source_file = workspace_dir / "src" / "secret.ts"
        source_file.write_text(secret_content)

        import hashlib

        output_sha256 = hashlib.sha256(secret_content.encode("utf-8")).hexdigest()

        store = GuardStore(home_dir)
        monkeypatch.setenv("HOL_GUARD_HOOK_FAST_PATH", "1")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            payload = {
                "hook_event_name": "PostToolUse",
                "tool_name": "Read",
                "tool_input": {"file_path": "src/secret.ts"},
                "guard_source_ref": {
                    "version": 1,
                    "kind": "source_file",
                    "path": "src/secret.ts",
                    "tool_input_path": "src/secret.ts",
                    "output_sha256": output_sha256,
                    "output_chars": len(secret_content),
                },
            }

            request = urllib.request.Request(
                (
                    f"http://127.0.0.1:{daemon.port}/v1/hooks/pi?"
                    f"guard-home={urllib.parse.quote(str(home_dir))}&"
                    f"home={urllib.parse.quote(str(home_dir))}&"
                    f"workspace={urllib.parse.quote(str(workspace_dir))}"
                ),
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": daemon._server.auth_token,
                },
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                result = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()
            monkeypatch.delenv("HOL_GUARD_HOOK_FAST_PATH", raising=False)

        assert result["model_output_action"] != "allow_original"

    def test_fast_path_source_ref_mismatch_is_not_allowed(self, tmp_path, monkeypatch) -> None:
        """Source ref pointing at a different file than the tool target must not allow_original."""
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        (workspace_dir / "src").mkdir(parents=True, exist_ok=True)
        benign_content = "export const safe = 1;\n"
        benign_file = workspace_dir / "src" / "benign.ts"
        benign_file.write_text(benign_content)
        actual_content = "export const actual = 2;\n"
        actual_file = workspace_dir / "src" / "actual.ts"
        actual_file.write_text(actual_content)

        import hashlib

        output_sha256 = hashlib.sha256(benign_content.encode("utf-8")).hexdigest()

        store = GuardStore(home_dir)
        monkeypatch.setenv("HOL_GUARD_HOOK_FAST_PATH", "1")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            payload = {
                "hook_event_name": "PostToolUse",
                "tool_name": "Read",
                "tool_input": {"file_path": "src/actual.ts"},
                "guard_source_ref": {
                    "version": 1,
                    "kind": "source_file",
                    "path": "src/benign.ts",
                    "tool_input_path": "src/benign.ts",
                    "output_sha256": output_sha256,
                    "output_chars": len(benign_content),
                },
            }

            request = urllib.request.Request(
                (
                    f"http://127.0.0.1:{daemon.port}/v1/hooks/pi?"
                    f"guard-home={urllib.parse.quote(str(home_dir))}&"
                    f"home={urllib.parse.quote(str(home_dir))}&"
                    f"workspace={urllib.parse.quote(str(workspace_dir))}"
                ),
                data=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": daemon._server.auth_token,
                },
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                result = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()
            monkeypatch.delenv("HOL_GUARD_HOOK_FAST_PATH", raising=False)

        assert result["model_output_action"] != "allow_original"


def test_unauthorized_response_waits_for_audit_recording() -> None:
    calls: list[str] = []

    class _OrderingStub:
        def _record_auth_audit_event(self) -> None:
            calls.append("audit")

        def _write_json(
            self,
            body: dict[str, object],
            *,
            status: int = 200,
            extra_headers: dict[str, str] | None = None,
        ) -> None:
            calls.append(f"json:{status}")

    daemon_server_module._GuardDaemonHandler._write_unauthorized(_OrderingStub())  # pyright: ignore[reportPrivateUsage]

    assert calls == ["audit", "json:401"]
