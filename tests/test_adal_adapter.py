"""Tests for the AdaL harness adapter."""

from __future__ import annotations

import argparse
import io
import json
from contextlib import redirect_stderr
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters import get_adapter, list_adapters
from codex_plugin_scanner.guard.adapters.adal import (
    ADAL_HOOK_EVENTS,
    ADAL_TOOL_SCOPED_EVENTS,
    AdaLHarnessAdapter,
)
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.contracts import contract_for
from codex_plugin_scanner.guard.inventory_contract import _agent_type


def _ctx(tmp_path: Path) -> HarnessContext:
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "workspace",
        guard_home=tmp_path / "guard-home",
    )


def _write_settings(home_dir: Path, payload: dict[str, object]) -> Path:
    settings_path = home_dir / ".adal" / "settings.json"
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return settings_path


def _patch_shims(monkeypatch: pytest.MonkeyPatch, context: HarnessContext) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.adal.install_guard_shim",
        lambda *args, **kwargs: {
            "shim_path": str(context.guard_home / "bin" / "guard-adal"),
            "notes": [],
        },
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.adapters.adal.remove_guard_shim",
        lambda *args, **kwargs: {
            "shim_path": str(context.guard_home / "bin" / "guard-adal"),
            "notes": [],
        },
    )


class TestAdaLAdapterIdentity:
    def test_adapter_and_alias_are_registered(self) -> None:
        assert isinstance(get_adapter("adal"), AdaLHarnessAdapter)
        assert get_adapter("adal-cli").harness == "adal"
        assert "adal" in {adapter.harness for adapter in list_adapters()}

    def test_contract_and_inventory_type_are_registered(self) -> None:
        contract = contract_for("adal-cli")
        assert contract is not None
        assert contract.harness == "adal"
        assert contract.smoke_command == "hol-guard install adal --dry-run"
        assert _agent_type("adal") == "adal"


class TestAdaLDetect:
    def test_detects_settings_and_hook_artifacts(self, tmp_path: Path) -> None:
        context = _ctx(tmp_path)
        settings_path = _write_settings(
            context.home_dir,
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "*",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "python guard.py",
                                }
                            ],
                        }
                    ]
                }
            },
        )
        result = AdaLHarnessAdapter().detect(context)
        assert result.installed is True
        assert str(settings_path) in result.config_paths
        assert len(result.artifacts) == 1
        assert result.artifacts[0].metadata["event"] == "PreToolUse"

    def test_malformed_settings_are_reported_without_crashing_detection(self, tmp_path: Path) -> None:
        context = _ctx(tmp_path)
        settings_path = context.home_dir / ".adal" / "settings.json"
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        settings_path.write_text("{bad json", encoding="utf-8")
        result = AdaLHarnessAdapter().detect(context)
        assert result.installed is True
        assert result.warnings


class TestAdaLInstallUninstall:
    def test_install_registers_all_events_with_exact_adal_fields(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        context = _ctx(tmp_path)
        _patch_shims(monkeypatch, context)
        AdaLHarnessAdapter().install(context)
        settings_path = context.home_dir / ".adal" / "settings.json"
        payload = json.loads(settings_path.read_text(encoding="utf-8"))
        assert set(payload["hooks"]) == set(ADAL_HOOK_EVENTS)
        for event_name, groups in payload["hooks"].items():
            assert len(groups) == 1
            group = groups[0]
            if event_name in ADAL_TOOL_SCOPED_EVENTS:
                assert group["matcher"] == "*"
            else:
                assert "matcher" not in group
            assert set(group["hooks"][0]) == {"type", "command", "timeout"}
            assert "--harness" in group["hooks"][0]["command"]
            assert "adal" in group["hooks"][0]["command"]

    def test_install_preserves_settings_and_user_hooks(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        context = _ctx(tmp_path)
        _write_settings(
            context.home_dir,
            {
                "model": "user-model",
                "mcpServers": {"github": {"command": "server"}},
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "bash",
                            "hooks": [{"type": "command", "command": "echo user"}],
                        }
                    ]
                },
            },
        )
        _patch_shims(monkeypatch, context)
        AdaLHarnessAdapter().install(context)
        payload = json.loads((context.home_dir / ".adal" / "settings.json").read_text(encoding="utf-8"))
        assert payload["model"] == "user-model"
        assert payload["mcpServers"]["github"]["command"] == "server"
        user_handlers = payload["hooks"]["PreToolUse"][0]["hooks"]
        assert user_handlers == [{"type": "command", "command": "echo user"}]

    def test_repeated_install_is_idempotent(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        context = _ctx(tmp_path)
        _patch_shims(monkeypatch, context)
        adapter = AdaLHarnessAdapter()
        adapter.install(context)
        adapter.install(context)
        payload = json.loads((context.home_dir / ".adal" / "settings.json").read_text(encoding="utf-8"))
        for groups in payload["hooks"].values():
            managed = [
                handler
                for group in groups
                for handler in group.get("hooks", [])
                if "--harness" in handler.get("command", "") and "adal" in handler.get("command", "")
            ]
            assert len(managed) == 1

    def test_uninstall_removes_only_guard_handlers(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        context = _ctx(tmp_path)
        _write_settings(
            context.home_dir,
            {
                "theme": "user-theme",
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "bash",
                            "hooks": [{"type": "command", "command": "echo user"}],
                        }
                    ]
                },
            },
        )
        _patch_shims(monkeypatch, context)
        adapter = AdaLHarnessAdapter()
        adapter.install(context)
        adapter.uninstall(context)
        payload = json.loads((context.home_dir / ".adal" / "settings.json").read_text(encoding="utf-8"))
        assert payload["theme"] == "user-theme"
        assert payload["hooks"] == {
            "PreToolUse": [
                {
                    "matcher": "bash",
                    "hooks": [{"type": "command", "command": "echo user"}],
                }
            ]
        }

    def test_install_refuses_to_overwrite_malformed_settings(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        context = _ctx(tmp_path)
        settings_path = context.home_dir / ".adal" / "settings.json"
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        settings_path.write_text("{bad json", encoding="utf-8")
        _patch_shims(monkeypatch, context)
        with pytest.raises(ValueError, match="malformed AdaL settings"):
            AdaLHarnessAdapter().install(context)
        assert settings_path.read_text(encoding="utf-8") == "{bad json"


class TestAdaLGenericEmitter:
    @staticmethod
    def _run_policy_action(
        tmp_path: Path,
        *,
        event_name: str,
        policy_action: str,
    ) -> tuple[int, dict[str, object]]:
        from codex_plugin_scanner.guard.cli.commands_hook_generic import _run_hook_generic_payload
        from codex_plugin_scanner.guard.config import GuardConfig
        from codex_plugin_scanner.guard.store import GuardStore

        guard_home = tmp_path / ".hol-guard"
        store = GuardStore(guard_home)
        config = GuardConfig(guard_home=guard_home, workspace=tmp_path)
        args = argparse.Namespace(
            harness="adal",
            json=False,
            policy_action=policy_action,
            artifact_id=None,
            artifact_name=None,
        )
        payload = {
            "hook_event_name": event_name,
            "tool_name": "bash",
            "tool_input": {"command": "rm -rf /"},
        }
        stdout_capture = io.StringIO()
        with redirect_stderr(io.StringIO()):
            return_code = _run_hook_generic_payload(
                args,
                action_envelope=None,
                config=config,
                output_stream=stdout_capture,
                payload=payload,
                home_dir=tmp_path,
                runtime_workspace=tmp_path,
                store=store,
            )
        return return_code, json.loads(stdout_capture.getvalue())

    def test_pretool_block_emits_deny_and_exit_two(self, tmp_path: Path) -> None:
        return_code, response = self._run_policy_action(
            tmp_path,
            event_name="PreToolUse",
            policy_action="block",
        )
        assert return_code == 2
        assert response["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_observer_event_block_finding_does_not_claim_enforcement(self, tmp_path: Path) -> None:
        return_code, response = self._run_policy_action(
            tmp_path,
            event_name="PostToolUseFailure",
            policy_action="block",
        )
        assert return_code == 0
        assert response == {"hookSpecificOutput": {"hookEventName": "PostToolUseFailure"}}

    def test_runtime_observer_event_records_finding_without_queueing_approval(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from codex_plugin_scanner.guard.cli import commands_hook_runtime_review as runtime_review
        from codex_plugin_scanner.guard.cli.commands_hook_runtime_state import (
            RuntimeArtifactHookState,
        )
        from codex_plugin_scanner.guard.config import GuardConfig
        from codex_plugin_scanner.guard.models import GuardArtifact
        from codex_plugin_scanner.guard.receipts import build_receipt
        from codex_plugin_scanner.guard.store import GuardStore

        context = _ctx(tmp_path)
        artifact = GuardArtifact(
            artifact_id="adal:project:post-tool-failure",
            name="AdaL observer event",
            harness="adal",
            artifact_type="tool_action_request",
            source_scope="project",
            config_path=str(context.home_dir / ".adal" / "settings.json"),
            command="rm -rf /",
        )
        artifact_hash = "guard-approval-context:v1:adal-observer"
        state = RuntimeArtifactHookState(
            action_envelope=None,
            artifact_id=artifact.artifact_id,
            artifact_name=artifact.name,
            browser_approval_daemon_client=None,
            changed_capabilities=["runtime_tool_call"],
            decision_signals=(),
            decision_v2_payload={},
            event_name="PostToolUseFailure",
            initial_policy_action="block",
            package_evaluation=None,
            policy_action="block",
            receipt=build_receipt(
                harness="adal",
                artifact_id=artifact.artifact_id,
                artifact_hash=artifact_hash,
                policy_decision="block",
                capabilities_summary="runtime tool action",
                changed_capabilities=["runtime_tool_call"],
                provenance_summary="AdaL lifecycle hook",
                artifact_name=artifact.name,
                source_scope=artifact.source_scope,
            ),
            requested_policy_action=None,
            response_payload={"policy_action": "block"},
            risk_summary="Guard observed a blocked policy after execution.",
            runtime_artifact=artifact,
            runtime_artifact_hash=artifact_hash,
            scanner_evidence_payload=[],
            stored_policy_action=None,
        )

        def fail_queue(*args: object, **kwargs: object) -> None:
            raise AssertionError(f"observer event queued approval: {args!r} {kwargs!r}")

        monkeypatch.setattr(runtime_review, "ensure_guard_daemon", fail_queue)
        monkeypatch.setattr(runtime_review, "queue_blocked_approvals", fail_queue)
        result = runtime_review._review_runtime_artifact_hook(
            state,
            argparse.Namespace(harness="adal", json=False),
            config=GuardConfig(
                guard_home=context.guard_home,
                workspace=context.workspace_dir,
            ),
            context=context,
            guard_home=context.guard_home,
            managed_install=None,
            payload={
                "hook_event_name": "PostToolUseFailure",
                "tool_name": "bash",
            },
            store=GuardStore(context.guard_home),
            workspace=context.workspace_dir,
        )

        assert result is None
        assert state.policy_action == "allow"
        assert state.response_payload["observed_policy_action"] == "block"
        assert state.response_payload["observer_only_event"] is True
