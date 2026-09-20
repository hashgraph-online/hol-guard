from __future__ import annotations

from tests.test_guard_surface_server import (
    GuardDaemonServer,
    GuardStore,
    Path,
    daemon_manager_module,
    daemon_server_module,
    hashlib,
    json,
    pytest,
    socket,
    tempfile,
    time,
    urllib,
)


class TestGuardSurfaceServer:
    def test_guard_daemon_hook_queue_bytes_fail_closed_and_reports_health(
        self,
        tmp_path,
        monkeypatch,
    ) -> None:
        monkeypatch.setattr(daemon_manager_module, "_guard_daemon_process_inventory_for_guard_home", lambda _home: [])
        store = GuardStore(tmp_path / "guard-home")
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir()
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon._server.runtime_hook_scheduler = daemon_server_module.RuntimeHookScheduler(retained_bytes_limit=1)
        daemon.start()

        try:
            hook_request = urllib.request.Request(
                (
                    f"http://127.0.0.1:{daemon.port}/v1/hooks/pi?"
                    f"guard-home={urllib.parse.quote(str(store.guard_home))}&"
                    f"workspace={urllib.parse.quote(str(workspace_dir))}"
                ),
                data=json.dumps(
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_name": "Bash",
                        "tool_input": {"command": "curl https://example.test"},
                    }
                ).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": daemon._server.auth_token,
                },
                method="POST",
            )
            with urllib.request.urlopen(hook_request, timeout=1) as response:
                overload = json.loads(response.read().decode("utf-8"))
            health_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/healthz/details",
                headers={"X-Guard-Token": daemon._server.auth_token},
            )
            with urllib.request.urlopen(health_request, timeout=5) as response:
                health = json.loads(response.read().decode("utf-8"))
            runtime_request = urllib.request.Request(
                f"http://127.0.0.1:{daemon.port}/v1/runtime?include_items=0&include_receipts=0",
                headers={"X-Guard-Token": daemon._server.auth_token},
            )
            with urllib.request.urlopen(runtime_request, timeout=5) as response:
                runtime = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert overload["decision"] == "deny"
        assert overload["reason_code"] == "daemon_hook_queue_bytes"
        assert health["hook_capacity"]["active"] == 0
        assert health["hook_capacity"]["limit"] == 32
        assert health["hook_capacity"]["rejected"] == 1
        assert health["hook_capacity"]["per_harness_rejected"]["pi"] == 1
        assert health["hook_capacity"]["rejection_reasons"] == {"daemon_hook_queue_bytes": 1}
        assert health["hook_workers"]["decisions"] == {}
        assert health["request_capacity"]["limit"] == 32
        assert health["request_capacity"]["critical_limit"] == 8
        operator_health = runtime["operator_health"]
        assert operator_health["state"] == "healthy"
        assert operator_health["repairable"] is False
        assert operator_health["queue_depth"] == health["hook_capacity"]["queued"]
        assert operator_health["workers_busy"] == health["hook_workers"]["busy"]
        assert operator_health["workers_ready"] == health["hook_workers"]["ready"]
        assert "automatically" in operator_health["automatic_recovery"]
        assert set(health["sqlite_profile"]) == {
            "connects",
            "transactions",
            "commits",
            "busy_locked",
            "busy_locked_percent",
            "connect_ms",
            "transaction_ms",
            "commit_ms",
        }
        migration_gate = health["sqlite_migration_gate"]
        assert migration_gate["store_wait_gate_tripped"] is None
        expected_conclusion = (
            "sqlite_migration_evaluation_required"
            if migration_gate["busy_locked_gate_tripped"]
            else "insufficient_end_to_end_profile"
        )
        assert migration_gate["conclusion"] == expected_conclusion
        assert health["hook_evidence_writer"]["degraded"] is False

    def test_guard_daemon_queues_hook_burst_until_active_review_completes(
        self,
        tmp_path,
        monkeypatch,
    ) -> None:
        monkeypatch.setattr(daemon_manager_module, "_guard_daemon_process_inventory_for_guard_home", lambda _home: [])
        store = GuardStore(tmp_path / "guard-home")
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir()
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon._server.runtime_hook_scheduler = daemon_server_module.RuntimeHookScheduler(active_limit=1)
        first_started = daemon_server_module.threading.Event()
        release_first = daemon_server_module.threading.Event()
        call_lock = daemon_server_module.threading.Lock()
        call_count = 0

        def execute(
            handler,
            _payload,
            _params,
            *,
            hook_env,
            default_harness,
            home_dir,
            guard_home,
            workspace,
            payload_hydrated=False,
            deadline=None,
        ) -> None:
            del hook_env, default_harness, home_dir, guard_home, workspace, payload_hydrated, deadline
            nonlocal call_count
            with call_lock:
                call_count += 1
                current_call = call_count
            if current_call == 1:
                first_started.set()
                assert release_first.wait(timeout=1)
            handler._write_json({"decision": "allow"})

        monkeypatch.setattr(daemon_server_module._GuardDaemonHandler, "_execute_runtime_hook", execute)
        daemon.start()

        def request_hook() -> dict[str, object]:
            request = urllib.request.Request(
                (
                    f"http://127.0.0.1:{daemon.port}/v1/hooks/pi?"
                    f"guard-home={urllib.parse.quote(str(store.guard_home))}&"
                    f"workspace={urllib.parse.quote(str(workspace_dir))}"
                ),
                data=json.dumps(
                    {
                        "hook_event_name": "PreToolUse",
                        "tool_name": "read",
                        "tool_input": {"path": "README.md"},
                    }
                ).encode(),
                headers={
                    "Content-Type": "application/json",
                    "X-Guard-Token": daemon._server.auth_token,
                },
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=2) as response:
                parsed = json.loads(response.read())
            assert isinstance(parsed, dict)
            return parsed

        first_result: dict[str, object] = {}
        second_result: dict[str, object] = {}
        first_thread = daemon_server_module.threading.Thread(
            target=lambda: first_result.update(request_hook()),
            daemon=True,
        )
        second_thread = daemon_server_module.threading.Thread(
            target=lambda: second_result.update(request_hook()),
            daemon=True,
        )
        try:
            first_thread.start()
            assert first_started.wait(timeout=1)
            second_thread.start()
            deadline = time.monotonic() + 1
            while daemon._server.runtime_hook_scheduler.stats()["queued"] != 1:
                assert time.monotonic() < deadline
                time.sleep(0.005)
            release_first.set()
            first_thread.join(timeout=2)
            second_thread.join(timeout=2)
        finally:
            release_first.set()
            daemon.stop()

        assert not first_thread.is_alive()
        assert not second_thread.is_alive()
        assert first_result == {"decision": "allow"}
        assert second_result == {"decision": "allow"}
        stats = daemon._server.runtime_hook_scheduler.stats()
        assert stats["completed"] == 2
        assert stats["rejected"] == {}

    def test_guard_daemon_native_dispatch_keeps_referenced_payload_opaque(
        self,
        tmp_path,
        monkeypatch,
    ) -> None:
        from codex_plugin_scanner.guard.runtime import hook_payload_reference as payload_reference_module

        monkeypatch.setattr(daemon_manager_module, "_guard_daemon_process_inventory_for_guard_home", lambda _home: [])
        monkeypatch.setenv("HOL_GUARD_NATIVE", "auto")
        monkeypatch.setenv("HOL_GUARD_HOOK_FAST_PATH", "0")
        store = GuardStore(tmp_path / "guard-home")
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir()
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        raw_referenced_payload = b'{"command":"pwd","command":"whoami"}'
        with tempfile.TemporaryDirectory(prefix="hol-guard-hook-payload-") as reference_dir:
            reference_path = Path(reference_dir) / "payload.json"
            reference_path.write_bytes(raw_referenced_payload)
            referenced_payload = {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "guard_payload_ref": {
                    "version": 1,
                    "path": str(reference_path),
                    "sha256": hashlib.sha256(raw_referenced_payload).hexdigest(),
                    "encoding": "json",
                },
            }
            seen_payload: dict[str, object] = {}

            def fail_hydration(_payload: object) -> dict[str, object]:
                pytest.fail("daemon native ingress hydrated the referenced payload")

            def native_dispatch(
                handler,
                payload,
                _params,
                *,
                default_harness,
                home_dir,
                guard_home,
                workspace,
                deadline,
            ) -> dict[str, object]:
                del default_harness, home_dir, guard_home, workspace, deadline
                seen_payload.update(payload)
                return {"decision": "allow"}

            monkeypatch.setattr(payload_reference_module, "hydrate_hook_payload_reference", fail_hydration)
            monkeypatch.setattr(daemon_server_module, "prepare_native_hook_policy", lambda *_args, **_kwargs: True)
            monkeypatch.setattr(daemon_server_module._GuardDaemonHandler, "_handle_runtime_hook_fast", native_dispatch)
            daemon.start()

            try:
                request = urllib.request.Request(
                    (
                        f"http://127.0.0.1:{daemon.port}/v1/hooks/pi?"
                        f"guard-home={urllib.parse.quote(str(store.guard_home))}&"
                        f"workspace={urllib.parse.quote(str(workspace_dir))}"
                    ),
                    data=json.dumps(referenced_payload).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        "X-Guard-Token": daemon._server.auth_token,
                    },
                    method="POST",
                )
                with urllib.request.urlopen(request, timeout=2) as response:
                    result = json.loads(response.read())
            finally:
                daemon.stop()

            assert result == {"decision": "allow"}
            assert seen_payload["guard_payload_ref"] == referenced_payload["guard_payload_ref"]
            assert reference_path.read_bytes() == raw_referenced_payload
            assert daemon._server.runtime_hook_scheduler.stats()["retained_bytes"] == 0

    def test_guard_daemon_server_close_stops_hook_evidence_writer(self, tmp_path, monkeypatch) -> None:
        monkeypatch.setattr(daemon_manager_module, "_guard_daemon_process_inventory_for_guard_home", lambda _home: [])
        daemon = GuardDaemonServer(GuardStore(tmp_path / "guard-home"), host="127.0.0.1", port=0)
        writer = daemon._server.runtime_hook_evidence_writer
        assert writer.stats()["running"] is True

        daemon._server.server_close()

        assert writer.stats()["running"] is False

    def test_guard_daemon_bounds_http_handler_threads_before_request_parsing(
        self,
        tmp_path,
        monkeypatch,
    ) -> None:
        monkeypatch.setattr(daemon_manager_module, "_guard_daemon_process_inventory_for_guard_home", lambda _home: [])
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon._server.connection_capacity_limit = 2
        daemon._server.connection_capacity = daemon_server_module.threading.BoundedSemaphore(2)
        daemon.start()
        clients: list[socket.socket] = []

        try:
            clients = [socket.create_connection(("127.0.0.1", daemon.port), timeout=1) for _ in range(3)]
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                with daemon._server.request_capacity_lock:
                    if daemon._server.active_requests == 2 and daemon._server.rejected_requests >= 1:
                        break
                time.sleep(0.01)
            with daemon._server.request_capacity_lock:
                assert daemon._server.active_requests == 2
                assert daemon._server.rejected_requests >= 1
        finally:
            for client in clients:
                client.close()
            daemon.stop()

    def test_guard_daemon_routes_repeated_liveness_after_parsing_under_general_saturation(
        self,
        tmp_path,
        monkeypatch,
    ) -> None:
        monkeypatch.setattr(daemon_manager_module, "_guard_daemon_process_inventory_for_guard_home", lambda _home: [])
        daemon = GuardDaemonServer(GuardStore(tmp_path / "guard-home"), host="127.0.0.1", port=0)
        acquired = [
            daemon._server.request_capacity.acquire(blocking=False)
            for _ in range(daemon._server.request_capacity_limit)
        ]
        daemon.start()

        try:
            for _ in range(200):
                with urllib.request.urlopen(f"http://127.0.0.1:{daemon.port}/healthz", timeout=1) as response:
                    health = json.loads(response.read().decode("utf-8"))
                assert health["ok"] is True
        finally:
            for held in acquired:
                if held:
                    daemon._server.request_capacity.release()
            daemon.stop()

    def test_guard_daemon_keeps_liveness_available_when_diagnostics_are_saturated(
        self,
        tmp_path,
        monkeypatch,
    ) -> None:
        monkeypatch.setattr(daemon_manager_module, "_guard_daemon_process_inventory_for_guard_home", lambda _home: [])
        store = GuardStore(tmp_path / "guard-home")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon._server.control_request_capacity_limit = 2
        daemon._server.control_request_capacity = daemon_server_module.threading.BoundedSemaphore(2)
        diagnostics_started = daemon_server_module.threading.Event()
        release_diagnostics = daemon_server_module.threading.Event()
        active_diagnostics = 0
        diagnostics_lock = daemon_server_module.threading.Lock()
        original_payload = daemon_server_module._GuardDaemonHandler._detailed_healthz_payload

        def delayed_payload(handler):
            nonlocal active_diagnostics
            with diagnostics_lock:
                active_diagnostics += 1
                if active_diagnostics == 2:
                    diagnostics_started.set()
            release_diagnostics.wait(timeout=2)
            return original_payload(handler)

        monkeypatch.setattr(
            daemon_server_module._GuardDaemonHandler,
            "_detailed_healthz_payload",
            delayed_payload,
        )
        daemon.start()
        diagnostic_threads = [
            daemon_server_module.threading.Thread(
                target=lambda: urllib.request.urlopen(
                    urllib.request.Request(
                        f"http://127.0.0.1:{daemon.port}/v1/healthz/details",
                        headers={"X-Guard-Token": daemon._server.auth_token},
                    ),
                    timeout=3,
                ).read()
            )
            for _ in range(2)
        ]

        try:
            for thread in diagnostic_threads:
                thread.start()
            assert diagnostics_started.wait(timeout=1)
            with urllib.request.urlopen(f"http://127.0.0.1:{daemon.port}/healthz", timeout=1) as response:
                health = json.loads(response.read().decode("utf-8"))
        finally:
            release_diagnostics.set()
            for thread in diagnostic_threads:
                thread.join(timeout=3)
            daemon.stop()

        assert health["ok"] is True

    def test_guard_daemon_collapses_unknown_harness_capacity_keys(self, tmp_path) -> None:
        daemon = GuardDaemonServer(GuardStore(tmp_path / "guard-home"), host="127.0.0.1", port=0)

        try:
            capacity_harnesses = {
                daemon._server.canonical_hook_capacity_harness(f"untrusted-harness-{index}") for index in range(1_000)
            }
            assert capacity_harnesses == {"other"}
        finally:
            daemon._server.server_close()

    @pytest.mark.parametrize(
        ("harness", "event", "expected"),
        [
            ("pi", "PreToolUse", {"decision": "allow", "reason_code": "daemon_hook_queue_capacity"}),
            (
                "claude-code",
                "PreToolUse",
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "allow",
                    }
                },
            ),
            (
                "codex",
                "PermissionRequest",
                {
                    "continue": True,
                    "hookSpecificOutput": {
                        "hookEventName": "PermissionRequest",
                    },
                },
            ),
            ("cursor", "PostToolUse", {"continue": True}),
        ],
    )
    def test_guard_daemon_hook_capacity_uses_native_fail_safe_response(
        self,
        harness: str,
        event: str,
        expected: dict[str, object],
    ) -> None:
        handler = object.__new__(daemon_server_module._GuardDaemonHandler)
        payload = handler._runtime_hook_capacity_response(
            {"hook_event_name": event},
            {},
            default_harness=harness,
        )

        for key, value in expected.items():
            if isinstance(value, dict):
                assert isinstance(payload[key], dict)
                for nested_key, nested_value in value.items():
                    if isinstance(nested_value, dict):
                        assert isinstance(payload[key][nested_key], dict)
                        for leaf_key, leaf_value in nested_value.items():
                            assert payload[key][nested_key][leaf_key] == leaf_value
                    else:
                        assert payload[key][nested_key] == nested_value
            else:
                assert payload[key] == value

    @pytest.mark.parametrize(
        ("event_key", "event_value"),
        [
            ("hook_event_name", "PermissionRequest"),
            ("hookEventName", "permissionrequest"),
            ("eventName", "UserPromptSubmit"),
            ("event", "userPromptSubmitted"),
            ("hook_name", "PreToolUse"),
            ("hookName", "preToolUse"),
        ],
    )
    def test_guard_daemon_normalizes_decision_lane_event_aliases(self, event_key: str, event_value: str) -> None:
        assert daemon_server_module._GuardDaemonHandler._runtime_hook_lane({event_key: event_value}) == "decision"
