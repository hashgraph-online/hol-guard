"""Runtime regression tests: sync local guard cloud proof publishes runtime."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    GuardArtifact,
    GuardConfig,
    GuardStore,
    HarnessDetection,
    build_receipt,
    evaluate_detection,
    guard_runner_module,
    load_guard_config,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_runtime_test_support import (
    _write_text,
)


class TestGuardRuntime:
    def test_sync_local_guard_cloud_proof_publishes_runtime_before_receipts(
        self,
        monkeypatch,
        tmp_path,
    ) -> None:
        store = GuardStore(tmp_path / "guard-home")
        call_order: list[str] = []

        def managed_controls_publish(_view: object, _commit: object) -> object:
            return object()

        shared_auth_context = {
            "sync_url": "https://hol.org/api/guard/receipts/sync",
            "access_token": "oauth-access-token-1",
            "dpop_key_material": object(),
        }

        def fake_resolve_guard_sync_auth_context(current_store: GuardStore) -> dict[str, object]:
            assert current_store is store
            return shared_auth_context

        def fake_sync_runtime_session(
            current_store: GuardStore,
            *,
            session: dict[str, object],
            auth_context: dict[str, object] | None = None,
        ) -> dict[str, object]:
            assert current_store is store
            call_order.append("runtime")
            assert auth_context is shared_auth_context
            assert session == {
                "harness": "hol-guard",
                "surface": "cli",
                "status": "active",
                "client_name": "hol-guard",
                "client_title": "HOL Guard CLI",
                "client_version": guard_runner_module.__version__,
                "workspace": "local-machine",
                "capabilities": ["approval-center", "guard-cloud-sync", "local-daemon"],
                "policy_bundle_versions": [
                    "guard-policy-bundle.v1",
                    "guard-policy-bundle.v2",
                ],
                "policy_contracts": [
                    "guard-policy-bundle/v1",
                    "guard-policy-bundle/v2",
                ],
                "policy_document_versions": [
                    "guard.hashgraphonline.com/v1alpha1",
                ],
                "yaml_import": False,
            }
            return {
                "synced_at": "2026-06-05T12:00:00+00:00",
                "runtime_session_synced_at": "2026-06-05T12:00:00+00:00",
                "runtime_session_id": "runtime-session-1",
                "runtime_sessions_visible": 1,
                "runtime_harness": "hol-guard",
                "runtime_surface": "cli",
                "runtime_workspace": "local-machine",
                "runtime_device_id": "device-1",
                "local_guard_online_at": "2026-06-05T12:00:00+00:00",
            }

        def fake_sync_receipts(
            current_store: GuardStore,
            *,
            persist_sync_summary: bool = True,
            persist_connect_state: bool = True,
            auth_context: dict[str, object] | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            assert current_store is store
            assert persist_sync_summary is False
            assert persist_connect_state is False
            call_order.append("receipts")
            assert auth_context is shared_auth_context
            assert _kwargs["managed_controls_publish"] is managed_controls_publish
            assert _kwargs["force_aibom"] is True
            return {
                "synced_at": "2026-06-05T12:00:05+00:00",
                "receipts_stored": 3,
                "inventory_tracked": 2,
                "local_guard_online_at": "2026-06-05T12:00:05+00:00",
            }

        monkeypatch.setattr(
            guard_runner_module,
            "_resolve_guard_sync_auth_context",
            fake_resolve_guard_sync_auth_context,
        )
        monkeypatch.setattr(guard_runner_module, "sync_runtime_session", fake_sync_runtime_session)
        monkeypatch.setattr(guard_runner_module, "sync_receipts", fake_sync_receipts)

        sync_cloud_proof = guard_runner_module.sync_local_guard_cloud_proof
        payload = sync_cloud_proof(store, force_aibom=True, managed_controls_publish=managed_controls_publish)

        assert call_order == ["runtime", "receipts"]
        assert payload["runtime_session_id"] == "runtime-session-1"
        assert payload["runtime_session_synced_at"] == "2026-06-05T12:00:00+00:00"
        assert payload["runtime_sessions_visible"] == 1
        assert payload["receipts_stored"] == 3
        assert payload["runtime"] == {
            "synced_at": "2026-06-05T12:00:00+00:00",
            "runtime_session_synced_at": "2026-06-05T12:00:00+00:00",
            "runtime_session_id": "runtime-session-1",
            "runtime_sessions_visible": 1,
            "runtime_harness": "hol-guard",
            "runtime_surface": "cli",
            "runtime_workspace": "local-machine",
            "runtime_device_id": "device-1",
            "local_guard_online_at": "2026-06-05T12:00:00+00:00",
        }
        assert payload["receipts"] == {
            "synced_at": "2026-06-05T12:00:05+00:00",
            "receipts_stored": 3,
            "inventory_tracked": 2,
            "local_guard_online_at": "2026-06-05T12:00:05+00:00",
        }

    def test_sync_local_guard_cloud_proof_persists_runtime_fields_in_connect_state(
        self,
        monkeypatch,
        tmp_path,
    ) -> None:
        store = GuardStore(tmp_path / "guard-home")
        store.record_guard_connect_pairing_completed(
            sync_url="https://hol.org/api/guard/receipts/sync",
            allowed_origin="https://hol.org",
            now="2026-06-05T12:00:00+00:00",
            request_id="connect-1",
        )

        shared_auth_context = {
            "sync_url": "https://hol.org/api/guard/receipts/sync",
            "access_token": "oauth-access-token-1",
            "dpop_key_material": object(),
        }

        def fake_resolve_guard_sync_auth_context(current_store: GuardStore) -> dict[str, object]:
            assert current_store is store
            return shared_auth_context

        def fake_sync_runtime_session(
            current_store: GuardStore,
            *,
            session: dict[str, object],
            auth_context: dict[str, object] | None = None,
        ) -> dict[str, object]:
            assert current_store is store
            assert auth_context is shared_auth_context
            assert session["harness"] == "hol-guard"
            return {
                "synced_at": "2026-06-05T12:00:02+00:00",
                "runtime_session_synced_at": "2026-06-05T12:00:02+00:00",
                "runtime_session_id": "runtime-session-1",
                "runtime_sessions_visible": 1,
                "runtime_harness": "hol-guard",
                "runtime_surface": "cli",
                "runtime_workspace": "local-machine",
                "runtime_device_id": "device-1",
                "local_guard_online_at": "2026-06-05T12:00:02+00:00",
            }

        def fake_sync_receipts(
            current_store: GuardStore,
            *,
            persist_sync_summary: bool = True,
            persist_connect_state: bool = True,
            auth_context: dict[str, object] | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            assert current_store is store
            assert persist_sync_summary is False
            assert persist_connect_state is False
            assert auth_context is shared_auth_context
            return {
                "synced_at": "2026-06-05T12:00:05+00:00",
                "receipts_stored": 0,
                "inventory_tracked": 0,
                "local_guard_online_at": "2026-06-05T12:00:05+00:00",
            }

        monkeypatch.setattr(
            guard_runner_module,
            "_resolve_guard_sync_auth_context",
            fake_resolve_guard_sync_auth_context,
        )
        monkeypatch.setattr(guard_runner_module, "sync_runtime_session", fake_sync_runtime_session)
        monkeypatch.setattr(guard_runner_module, "sync_receipts", fake_sync_receipts)

        payload = guard_runner_module.sync_local_guard_cloud_proof(store)
        latest_state = store.get_latest_guard_connect_state(now="2026-06-05T12:00:05+00:00")
        sync_summary = store.get_sync_payload("sync_summary")

        assert payload["runtime_session_id"] == "runtime-session-1"
        assert isinstance(sync_summary, dict)
        assert sync_summary["runtime_session_id"] == "runtime-session-1"
        assert sync_summary["runtime_session_synced_at"] == "2026-06-05T12:00:02+00:00"
        assert latest_state is not None
        assert latest_state["milestone"] == "first_sync_succeeded"
        proof = latest_state["proof"]
        assert isinstance(proof, dict)
        assert proof["runtime_session_id"] == "runtime-session-1"
        assert proof["runtime_session_synced_at"] == "2026-06-05T12:00:02+00:00"
        assert proof["first_synced_at"] == "2026-06-05T12:00:05+00:00"

    def test_cloud_runtime_session_payload_uses_contract_safe_local_identity(
        self,
        tmp_path,
    ) -> None:
        store = GuardStore(tmp_path / "guard-home")

        payload = guard_runner_module._cloud_runtime_session_payload(
            store,
            {
                "session_id": "runtime-session-1",
                "harness": "hol-guard",
                "surface": "cli",
                "status": "active",
                "client_name": "hol-guard",
                "client_title": "HOL Guard CLI",
                "client_version": "2.0.345",
                "workspace": "local-machine",
                "capabilities": ["approval-center", "guard-cloud-sync", "local-daemon"],
            },
        )

        local_identity = payload["localIdentity"]
        assert isinstance(local_identity, dict)
        assert "lastSyncedAt" in local_identity
        assert "daemonId" not in local_identity
        assert "daemonVersion" not in local_identity
        assert "daemonStatus" not in local_identity
        assert "relayState" not in local_identity

    def test_receipt_sync_context_matches_cloud_contract_for_empty_first_sync(
        self,
        tmp_path,
    ) -> None:
        store = GuardStore(tmp_path / "guard-home")
        store.set_sync_payload(
            "runtime_session_summary",
            {
                "runtime_harness": "hol-guard",
                "runtime_session_synced_at": "2026-06-05T12:00:00+00:00",
            },
            "2026-06-05T12:00:00+00:00",
        )
        store.set_sync_payload(
            "sync_summary",
            {
                "synced_at": "2026-06-05T11:59:00+00:00",
            },
            "2026-06-05T11:59:00+00:00",
        )

        context = guard_runner_module._receipt_sync_context(
            store,
            local_guard_online_at="2026-06-05T12:00:05+00:00",
        )

        assert context["deviceId"] == store.get_or_create_installation_id()
        assert isinstance(context["deviceName"], str)
        assert context["harness"] == "hol-guard"
        assert context["lastRuntimeSyncAt"] == "2026-06-05T12:00:00+00:00"
        assert context["localGuardOnlineAt"] == "2026-06-05T12:00:05+00:00"
        assert context["syncHealth"] == "healthy"
        assert "lastReceiptSyncAt" not in context

    def test_guard_store_initializes_runtime_tables_and_receipt_columns(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")

        assert {
            "artifact_diffs",
            "artifact_hashes",
            "artifact_snapshots",
            "harness_installations",
            "managed_installs",
            "policy_decisions",
            "publisher_cache",
            "runtime_receipts",
            "sync_state",
        } <= set(store.list_table_names())

        store.add_receipt(
            build_receipt(
                harness="codex",
                artifact_id="codex:project:workspace-tools",
                artifact_hash="hash-1",
                policy_decision="allow",
                capabilities_summary="mcp server • stdio • node",
                changed_capabilities=["first_seen"],
                provenance_summary="project artifact defined at .codex/config.toml",
                artifact_name="workspace-tools",
                source_scope="project",
            )
        )
        receipts = store.list_receipts(limit=1)

        assert receipts[0]["capabilities_summary"] == "mcp server • stdio • node"

    def test_guard_load_config_parses_override_sections(self, tmp_path):
        guard_home = tmp_path / "guard-home"
        guard_home.mkdir(parents=True, exist_ok=True)
        _write_text(
            guard_home / "config.toml",
            "\n".join(
                [
                    'default_action = "warn"',
                    "[harnesses.codex]",
                    'action = "allow"',
                    '[publishers."hashgraph-online"]',
                    'action = "sandbox-required"',
                    '[artifacts."codex:project:workspace-tools"]',
                    'action = "block"',
                ]
            )
            + "\n",
        )

        config = load_guard_config(guard_home)

        assert config.resolve_action_override("codex", None, None) == "allow"
        assert config.resolve_action_override("codex", None, "hashgraph-online") == "sandbox-required"
        assert config.resolve_action_override("codex", "codex:project:workspace-tools", None) == "block"

    def test_guard_load_config_accepts_default_action_inside_override_sections(self, tmp_path):
        guard_home = tmp_path / "guard-home"
        guard_home.mkdir(parents=True, exist_ok=True)
        _write_text(
            guard_home / "config.toml",
            "\n".join(
                [
                    "[harnesses.codex]",
                    'default_action = "allow"',
                    '[publishers."hashgraph-online"]',
                    'default_action = "sandbox-required"',
                    '[artifacts."codex:project:workspace-tools"]',
                    'default_action = "block"',
                ]
            )
            + "\n",
        )

        config = load_guard_config(guard_home)

        assert config.resolve_action_override("codex", None, None) == "allow"
        assert config.resolve_action_override("codex", None, "hashgraph-online") == "sandbox-required"
        assert config.resolve_action_override("codex", "codex:project:workspace-tools", None) == "block"

    def test_guard_load_config_parses_approval_wait_timeout(self, tmp_path):
        guard_home = tmp_path / "guard-home"
        guard_home.mkdir(parents=True, exist_ok=True)
        _write_text(guard_home / "config.toml", "approval_wait_timeout_seconds = 7\n")

        config = load_guard_config(guard_home)

        assert config.approval_wait_timeout_seconds == 7

    def test_guard_evaluate_detection_uses_config_action_overrides(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        config = GuardConfig(
            guard_home=tmp_path / "guard-home",
            workspace=None,
            harness_actions={"codex": "allow"},
            publisher_actions={"hashgraph-online": "sandbox-required"},
            artifact_actions={"codex:project:workspace-tools": "block"},
        )
        artifact = GuardArtifact(
            artifact_id="codex:project:workspace-tools",
            name="workspace-tools",
            harness="codex",
            artifact_type="mcp_server",
            source_scope="project",
            config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
            command="node",
            args=("workspace.js",),
            transport="stdio",
            publisher="hashgraph-online",
        )
        detection = HarnessDetection(
            harness="codex",
            installed=True,
            command_available=True,
            config_paths=(artifact.config_path,),
            artifacts=(artifact,),
        )

        evaluation = evaluate_detection(detection, store, config, persist=True)
        receipts = store.list_receipts(limit=1)

        assert evaluation["blocked"] is True
        assert evaluation["artifacts"][0]["policy_action"] == "block"
        assert evaluation["artifacts"][0]["decision_v2_json"]["action"] == "block"
        assert evaluation["artifacts"][0]["decision_v2_json"]["harness_message"] == "HOL Guard blocked this action."
        assert receipts[0]["capabilities_summary"] == "mcp server • stdio • node"

    def test_guard_evaluate_detection_blocks_for_sandbox_required_override(self, tmp_path):
        store = GuardStore(tmp_path / "guard-home")
        config = GuardConfig(
            guard_home=tmp_path / "guard-home",
            workspace=None,
            publisher_actions={"hashgraph-online": "sandbox-required"},
        )
        artifact = GuardArtifact(
            artifact_id="codex:project:workspace-tools",
            name="workspace-tools",
            harness="codex",
            artifact_type="mcp_server",
            source_scope="project",
            config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
            command="node",
            args=("workspace.js",),
            transport="stdio",
            publisher="hashgraph-online",
        )
        detection = HarnessDetection(
            harness="codex",
            installed=True,
            command_available=True,
            config_paths=(artifact.config_path,),
            artifacts=(artifact,),
        )

        evaluation = evaluate_detection(detection, store, config, persist=False)

        assert evaluation["blocked"] is True
        assert evaluation["artifacts"][0]["policy_action"] == "sandbox-required"
