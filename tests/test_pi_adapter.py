"""Tests for the Pi harness adapter."""

from __future__ import annotations

import argparse
import json
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path

from codex_plugin_scanner.guard.adapters import get_adapter, list_adapters
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.contracts import contract_for
from codex_plugin_scanner.guard.cli.commands_hook_generic import _run_hook_generic_payload
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.runtime.actions import normalize_harness_payload
from codex_plugin_scanner.guard.store import GuardStore


def _ctx(tmp_path: Path, *, workspace: bool = False) -> HarnessContext:
    workspace_dir = tmp_path / "workspace" if workspace else None
    if workspace_dir is not None:
        workspace_dir.mkdir(parents=True, exist_ok=True)
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=workspace_dir,
        guard_home=tmp_path / "guard-home",
    )


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


class TestPiAdapterIdentity:
    def test_harness_identifier_is_pi(self) -> None:
        adapter = get_adapter("pi")
        assert adapter.harness == "pi"

    def test_aliases_resolve_to_pi(self) -> None:
        for alias in ("pi", "pi-agent", "pi-coding-agent"):
            assert get_adapter(alias).harness == "pi"

    def test_pi_is_registered(self) -> None:
        assert "pi" in {item.harness for item in list_adapters()}

    def test_contract_exists(self) -> None:
        contract = contract_for("pi")
        assert contract is not None
        assert contract.harness == "pi"
        assert contract.smoke_command == "hol-guard install pi --dry-run"


class TestPiDetect:
    def test_detects_settings_extensions_skills_prompts_themes_and_packages(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        assert ctx.workspace_dir is not None
        _write_json(
            ctx.home_dir / ".pi" / "agent" / "settings.json",
            {
                "packages": ["npm:@demo/pi-tools@1.2.3"],
                "extensions": ["/opt/pi/extensions/custom.ts"],
            },
        )
        _write_text(ctx.home_dir / ".pi" / "agent" / "extensions" / "demo.ts", "export default function () {}\n")
        _write_text(ctx.home_dir / ".pi" / "agent" / "skills" / "ship" / "SKILL.md", "# Ship\n")
        _write_text(ctx.home_dir / ".pi" / "agent" / "prompts" / "review.md", "Review this\n")
        _write_text(ctx.home_dir / ".pi" / "agent" / "themes" / "night.json", "{}\n")
        _write_text(ctx.workspace_dir / ".pi" / "extensions" / "local.ts", "export default function () {}\n")

        result = get_adapter("pi").detect(ctx)

        assert result.harness == "pi"
        assert any(path.endswith(".pi/agent/settings.json") for path in result.config_paths)
        artifact_ids = {artifact.artifact_id for artifact in result.artifacts}
        assert "pi:global:package:0" in artifact_ids
        assert "pi:global:extension:demo.ts" in artifact_ids
        assert "pi:global:skill:skills/ship" in artifact_ids
        assert "pi:global:prompt:review.md" in artifact_ids
        assert "pi:global:theme:night.json" in artifact_ids
        assert "pi:project:extension:local.ts" in artifact_ids


class TestPiInstall:
    def test_install_writes_managed_extension(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.adapters.pi.install_guard_shim",
            lambda *args, **kwargs: {"shim_path": str(ctx.guard_home / "bin" / "guard-pi"), "notes": []},
        )

        manifest = get_adapter("pi").install(ctx)

        assert manifest["harness"] == "pi"
        extension_path = Path(str(manifest["config_path"]))
        assert extension_path.is_file()
        text = extension_path.read_text(encoding="utf-8")
        assert 'pi.on("tool_call"' in text
        assert 'pi.on("input"' in text
        assert '"--harness", "pi"' in text

    def test_uninstall_removes_managed_extension(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.adapters.pi.install_guard_shim",
            lambda *args, **kwargs: {"shim_path": str(ctx.guard_home / "bin" / "guard-pi"), "notes": []},
        )
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.adapters.pi.remove_guard_shim",
            lambda *args, **kwargs: {"shim_path": str(ctx.guard_home / "bin" / "guard-pi"), "notes": []},
        )
        adapter = get_adapter("pi")
        manifest = adapter.install(ctx)
        extension_path = Path(str(manifest["config_path"]))

        uninstall_manifest = adapter.uninstall(ctx)

        assert uninstall_manifest["active"] is False
        assert not extension_path.exists()


class TestPiRuntime:
    def test_pi_payload_normalizes_like_other_harnesses(self, tmp_path: Path) -> None:
        envelope = normalize_harness_payload(
            "pi",
            "PreToolUse",
            {"tool_name": "bash", "tool_input": {"command": "cat .env"}},
            workspace=tmp_path,
            home_dir=tmp_path,
        )

        assert envelope.harness == "pi"
        assert envelope.action_type == "shell_command"

    def test_pi_block_emits_native_json_and_stderr(self, tmp_path: Path) -> None:
        store = GuardStore(tmp_path / ".hol-guard")
        config = GuardConfig(guard_home=tmp_path / ".hol-guard", workspace=tmp_path)
        args = argparse.Namespace(
            harness="pi",
            json=False,
            policy_action="block",
            artifact_id=None,
            artifact_name=None,
        )
        stdout_capture = StringIO()
        stderr_capture = StringIO()

        with redirect_stderr(stderr_capture):
            rc = _run_hook_generic_payload(
                args,
                action_envelope=None,
                config=config,
                output_stream=stdout_capture,
                payload={"hookEventName": "PreToolUse", "tool_name": "bash", "tool_input": {"command": "cat .env"}},
                home_dir=tmp_path,
                runtime_workspace=tmp_path,
                store=store,
            )

        assert rc == 2
        assert json.loads(stdout_capture.getvalue())["decision"] == "deny"
        assert "HOL Guard" in stderr_capture.getvalue()
