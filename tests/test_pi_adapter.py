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
from codex_plugin_scanner.guard.adapters.pi_support import stable_suffix
from codex_plugin_scanner.guard.cli.commands_hook_generic import _run_hook_generic_payload
from codex_plugin_scanner.guard.cli.commands_hook_runtime_review import _approval_open_key
from codex_plugin_scanner.guard.cli.commands_support_codex_tool_output_messages import (
    _codex_tool_output_request_summary,
    _codex_tool_output_runtime_reason,
    _codex_tool_output_runtime_summary,
)
from codex_plugin_scanner.guard.cli.commands_support_hook_payload import _approval_surface_policy_for_flow
from codex_plugin_scanner.guard.cli.commands_support_runtime_artifacts import _codex_post_tool_output_artifact
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.inventory_contract import inventory_snapshot_from_detection
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
        for alias in ("pi", "pi-agent", "pi-coding-agent", "omp", "oh-my-pi"):
            assert get_adapter(alias).harness == "pi"

    def test_pi_is_registered(self) -> None:
        assert "pi" in {item.harness for item in list_adapters()}

    def test_contract_exists(self) -> None:
        contract = contract_for("pi")
        assert contract is not None
        assert contract.harness == "pi"
        assert contract.smoke_command == "hol-guard install pi --dry-run"
        assert "tool_result" in contract.event_surfaces
        assert contract_for("omp") == contract
        assert "omp" in contract.install_aliases
        assert "oh-my-pi" in contract.install_aliases

    def test_managed_approval_flow_auto_opens_approval_center_once_as_fallback(self) -> None:
        flow = get_adapter("pi").approval_flow(managed_install={"active": True, "manifest": {}})

        assert flow["tier"] == "approval-center"
        assert flow["prompt_channel"] == "native-fallback"
        assert flow["auto_open_browser"] is True
        assert _approval_surface_policy_for_flow("auto-open-once", flow) == "auto-open-once"
        assert _approval_open_key("pi", "pi:project:tool-a") == "pi-approval-center"
        assert _approval_open_key("codex", "codex:project:tool-a") == "codex:project:tool-a"

    def test_unmanaged_approval_flow_keeps_browser_fallback_visible(self) -> None:
        flow = get_adapter("pi").approval_flow(managed_install=None)

        assert flow["tier"] == "approval-center"
        assert flow["prompt_channel"] == "browser"
        assert flow["auto_open_browser"] is True
        assert _approval_surface_policy_for_flow("auto-open-once", flow) == "auto-open-once"


class TestPiDetect:
    def test_detect_marks_omp_cli_as_available(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.adapters.pi._resolve_command",
            lambda command, candidates=(): "/opt/homebrew/bin/omp" if command == "omp" else None,
        )

        result = get_adapter("pi").detect(ctx)

        assert result.installed is True
        assert result.command_available is True

    def test_detect_omp_warning_mentions_pi_or_omp(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        _write_json(ctx.home_dir / ".omp" / "agent" / "settings.json", {"extensions": []})
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.adapters.pi._resolve_command",
            lambda command, candidates=(): None,
        )

        adapter = get_adapter("pi")
        result = adapter.detect(ctx)
        warnings = adapter.diagnostic_warnings(result, runtime_probe=None)

        assert any("pi or omp command" in warning for warning in warnings)

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
        assert f"pi:pi-global:package:{stable_suffix('npm:@demo/pi-tools@1.2.3')}" in artifact_ids
        assert "pi:pi-global:extension:demo.ts" in artifact_ids
        assert "pi:pi-global:skill:skills/ship" in artifact_ids
        assert "pi:pi-global:prompt:review.md" in artifact_ids
        assert "pi:pi-global:theme:night.json" in artifact_ids
        assert "pi:pi-project:extension:local.ts" in artifact_ids

    def test_detect_keeps_empty_settings_file(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_text(ctx.home_dir / ".pi" / "agent" / "settings.json", "{}\n")

        result = get_adapter("pi").detect(ctx)

        assert str(ctx.home_dir / ".pi" / "agent" / "settings.json") in result.config_paths
        assert result.installed is True

    def test_detects_omp_settings_and_extensions(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_json(
            ctx.home_dir / ".omp" / "agent" / "settings.json",
            {"extensions": ["/opt/omp/extensions/custom.ts"]},
        )
        _write_text(ctx.home_dir / ".omp" / "agent" / "extensions" / "omp-ext.ts", "export default function () {}\n")

        result = get_adapter("pi").detect(ctx)

        assert str(ctx.home_dir / ".omp" / "agent" / "settings.json") in result.config_paths
        assert "pi:omp-global:extension:omp-ext.ts" in {artifact.artifact_id for artifact in result.artifacts}

    def test_pi_and_omp_managed_extensions_have_distinct_aibom_item_ids(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_text(ctx.home_dir / ".pi" / "agent" / "extensions" / "hol-guard.ts", "export default 'pi';\n")
        _write_text(ctx.home_dir / ".omp" / "agent" / "extensions" / "hol-guard.ts", "export default 'omp';\n")

        detection = get_adapter("pi").detect(ctx)
        snapshot = inventory_snapshot_from_detection(
            detection,
            generated_at="2026-06-29T00:00:00Z",
            home_dir=ctx.home_dir,
            workspace_dir=ctx.workspace_dir,
        )

        item_keys = [(item.item_kind, item.item_id) for item in snapshot.items]
        assert len(item_keys) == len(set(item_keys))
        assert {item.item_id for item in snapshot.items} >= {
            "pi:pi-global:extension:hol-guard.ts",
            "pi:omp-global:extension:hol-guard.ts",
        }

    def test_pi_and_omp_shared_configured_extension_keeps_both_scoped_items(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        shared_extension = tmp_path / "shared" / "hol-guard.ts"
        _write_text(shared_extension, "export default 'shared';\n")
        _write_json(ctx.home_dir / ".pi" / "agent" / "settings.json", {"extensions": [str(shared_extension)]})
        _write_json(ctx.home_dir / ".omp" / "agent" / "settings.json", {"extensions": [str(shared_extension)]})

        result = get_adapter("pi").detect(ctx)

        artifact_ids = {artifact.artifact_id for artifact in result.artifacts}
        assert "pi:pi-global:extension:hol-guard.ts" in artifact_ids
        assert "pi:omp-global:extension:hol-guard.ts" in artifact_ids

    def test_detect_expands_configured_extension_glob(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        assert ctx.workspace_dir is not None
        shared_root = tmp_path / "shared" / "pi-exts"
        _write_text(shared_root / "one.ts", "export default function () {}\n")
        _write_text(shared_root / "two.ts", "export default function () {}\n")
        _write_json(
            ctx.workspace_dir / ".pi" / "settings.json",
            {"extensions": ["../../shared/pi-exts/*.ts"]},
        )

        result = get_adapter("pi").detect(ctx)

        artifact_ids = {artifact.artifact_id for artifact in result.artifacts}
        assert "pi:pi-project:extension:one.ts" in artifact_ids
        assert "pi:pi-project:extension:two.ts" in artifact_ids
        assert str(shared_root / "one.ts") in result.config_paths

    def test_root_skill_uses_stable_identity(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_text(ctx.home_dir / ".pi" / "agent" / "skills" / "SKILL.md", "# Root\n")

        result = get_adapter("pi").detect(ctx)

        skills = [artifact for artifact in result.artifacts if artifact.artifact_type == "skill"]
        assert skills[0].artifact_id == "pi:pi-global:skill:skills"
        assert skills[0].name == "skills"


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
        settings_path = ctx.home_dir / ".pi" / "agent" / "settings.json"
        omp_extension_path = ctx.home_dir / ".omp" / "agent" / "extensions" / "hol-guard.ts"
        omp_settings_path = ctx.home_dir / ".omp" / "agent" / "settings.json"
        text = extension_path.read_text(encoding="utf-8")
        assert 'pi.on("tool_call"' in text
        assert 'pi.on("tool_result"' in text
        assert 'pi.on("input"' in text
        assert 'hook_event_name: "PostToolUse"' in text
        assert 'const GUARD_COMMAND_CANDIDATES = ["plugin-guard", "hol-guard"]' in text
        assert 'const GUARD_HOME =' in text
        assert "daemon-state.json" in text
        assert "daemon-auth-token" in text
        assert "/v1/hooks/pi?" in text
        assert "guardPayload.tool_response = event.content" in text
        assert "const GUARD_CONFIG_PATH =" in text
        assert "config_path: GUARD_CONFIG_PATH" in text
        assert '"hook", "--guard-home"' in text
        assert '"guard", "hook"' not in text
        assert '"--harness", "pi"' in text
        assert '"--home"' in text
        assert "ctx.cwd" in text
        assert "timeout: GUARD_TIMEOUT_MS" in text
        assert str(extension_path) in json.loads(settings_path.read_text(encoding="utf-8"))["extensions"]
        assert omp_extension_path.is_file()
        assert str(omp_extension_path) in json.loads(omp_settings_path.read_text(encoding="utf-8"))["extensions"]

    def test_install_writes_managed_extension_that_denies_on_hook_errors(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.adapters.pi.install_guard_shim",
            lambda *args, **kwargs: {"shim_path": str(ctx.guard_home / "bin" / "guard-pi"), "notes": []},
        )

        manifest = get_adapter("pi").install(ctx)

        text = Path(str(manifest["config_path"])).read_text(encoding="utf-8")
        assert "serializedPayload = JSON.stringify(payloadToSend);" in text
        assert "serializedPayload.length > GUARD_MAX_SERIALIZED_PAYLOAD_CHARS" in text
        assert "for (const command of GUARD_COMMAND_CANDIDATES)" in text
        assert "resultError?.code === 'ENOENT'" in text
        assert "async function daemonGuardResponse(" in text
        assert "await fetch(`http://127.0.0.1:${port}/v1/hooks/pi?" in text
        assert "const daemonResponse = await daemonGuardResponse(serializedPayload, cwd);" in text
        assert "const response = await runGuard(" in text
        assert "if (result.error) {" in text
        assert "const resultError =" in text
        assert "const errorCode =" in text
        assert 'decision: "deny"' in text
        assert "errorCode === 'ETIMEDOUT'" in text
        assert "HOL Guard Pi hook timed out after" in text
        assert "HOL Guard Pi hook failed before completing review" in text

    def test_install_writes_managed_extension_that_truncates_post_tool_payloads(
        self,
        tmp_path: Path,
        monkeypatch,
    ) -> None:
        ctx = _ctx(tmp_path)
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.adapters.pi.install_guard_shim",
            lambda *args, **kwargs: {"shim_path": str(ctx.guard_home / "bin" / "guard-pi"), "notes": []},
        )

        manifest = get_adapter("pi").install(ctx)

        text = Path(str(manifest["config_path"])).read_text(encoding="utf-8")
        assert "const GUARD_TEXT_LIMIT_CHARS =" in text
        assert "const GUARD_CONTENT_ITEM_LIMIT =" in text
        assert "const GUARD_OBJECT_KEY_LIMIT =" in text
        assert "const GUARD_MAX_DEPTH =" in text
        assert "const GUARD_MAX_SERIALIZED_PAYLOAD_CHARS =" in text
        assert "function truncateText(" in text
        assert "function boundValue(" in text
        assert "function boundedOutputText(" in text
        assert "function referencedPayload(" in text
        assert "function toolCallIdKey(" in text
        assert "guard_payload_ref" in text
        assert "mkdtempSync(join(tmpdir(), 'hol-guard-hook-payload-'))" in text
        assert "createCipheriv('aes-256-gcm', key, nonce)" in text
        assert "createHash('sha256').update(encrypted.ciphertext).digest('hex')" in text
        assert "encryption: 'aes-256-gcm'" in text
        assert "if (value === undefined) return { value: undefined, truncated: false };" in text
        assert "typeof value === 'bigint'" in text
        assert "value.toString()" in text
        assert "new WeakSet<object>()" in text
        assert "[deep object omitted by HOL Guard]" in text
        assert "const boundedContent = boundValue(event.content);" in text
        assert "const boundedStdout = boundedOutputText(event.content);" in text
        assert (
            "const reviewedContent = outputTruncated ? [{ type: 'text', text: toolOutput }] : boundedContent.value;"
            in text
        )
        # Only output truncation gates the reviewed-result replacement. Guard
        # still receives full tool input and full tool response data through
        # the generic payload-reference path when the payload is too large.
        assert "boundedContent.truncated || boundedStdout.truncated" in text
        assert "boundedToolInput.truncated || boundedContent.truncated" not in text
        assert "const boundedToolInput = boundValue(" not in text
        assert "const blockedToolResults = new Map<string, string>();" in text
        assert 'pi.on("message_end"' in text
        assert "const toolCallId = toolCallIdKey(event.toolCallId);" in text
        assert "if (toolCallId) blockedToolResults.set(toolCallId, reason);" in text
        assert "blockedToolResults.delete(toolCallId);" in text
        # Oversized tool results are passed to Guard by reference for full
        # review, not pre-emptively blocked.
        assert "HOL Guard blocked oversized Pi tool output before review" not in text
        assert "oversizeNotice" not in text
        assert 'ctx.ui.notify(oversizeNotice' not in text
        assert "const response = await runGuard(" in text
        # When truncated, the reviewed excerpt (not the full unreviewed output) is
        # returned to Pi so omitted content never reaches the model.
        assert "function reviewedToolResult(" in text
        assert "return reviewedToolResult(reviewedContent, event.details, event.isError === true);" in text
        assert "guardPayload.tool_response = event.content" in text
        assert "stdout: toolOutput" in text
        assert "contentText(event.content)" not in text
        assert "options?.enforceSizeCap === true" in text
        assert 'payloadToSend.hook_event_name === "PostToolUse"' not in text
        assert "delete reducedPayload.stdout;" not in text
        # Source-ref fast path support
        assert "guard_source_ref" in text
        assert "digestOutputText" in text
        assert "sourceFileRefForPostToolUse" in text
        assert "GUARD_SOURCE_REF_MAX_OUTPUT_CHARS" in text
        assert "GUARD_SOURCE_REF_ALLOWED_TOOL_NAMES" in text
        assert "reviewed_output_sha256" in text
        assert 'response.model_output_action === "allow_original"' in text
        assert "response.reviewed_output_sha256 === digest.sha256" in text
        # digestOutputText must only hash text-bearing fields, not metadata
        # like {type: "text"} — otherwise structured source reads never match
        assert 'record.type === \'text\'' in text
        assert 'record.text' in text
        assert 'OUTPUT_TEXT_KEYS' in text
        # guard_payload_ref fallback still present
        assert "guard_payload_ref" in text
        # Reviewed excerpt still returned when not proven safe
        assert "return reviewedToolResult(reviewedContent, event.details, event.isError === true);" in text

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
        settings_path = ctx.home_dir / ".pi" / "agent" / "settings.json"
        omp_extension_path = ctx.home_dir / ".omp" / "agent" / "extensions" / "hol-guard.ts"
        omp_settings_path = ctx.home_dir / ".omp" / "agent" / "settings.json"

        uninstall_manifest = adapter.uninstall(ctx)

        assert uninstall_manifest["active"] is False
        assert not extension_path.exists()
        assert not omp_extension_path.exists()
        assert json.loads(settings_path.read_text(encoding="utf-8"))["extensions"] == []
        assert json.loads(omp_settings_path.read_text(encoding="utf-8"))["extensions"] == []


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

    def test_pi_post_tool_payload_normalizes_like_other_harnesses(self, tmp_path: Path) -> None:
        envelope = normalize_harness_payload(
            "pi",
            "PostToolUse",
            {
                "tool_name": "read",
                "tool_input": {"filePath": "notes.txt"},
                "tool_response": [{"type": "text", "text": "TOKEN=secret"}],
                "stdout": "TOKEN=secret",
            },
            workspace=tmp_path,
            home_dir=tmp_path,
        )

        assert envelope.harness == "pi"
        assert envelope.event_name == "PostToolUse"
        assert envelope.action_type == "file_read"
        assert envelope.raw_payload_redacted["stdout"] == "[redacted]"
        assert "tool_response" in envelope.raw_payload_redacted

    def test_pi_post_tool_output_creates_runtime_artifact(self, tmp_path: Path) -> None:
        secret_path = tmp_path / ".npmrc"
        secret_line = "//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz012345\n"
        secret_path.write_text(secret_line, encoding="utf-8")

        artifact = _codex_post_tool_output_artifact(
            harness="pi",
            payload={
                "tool_name": "read",
                "tool_input": {"filePath": str(secret_path)},
                "tool_response": [{"type": "text", "text": secret_line.strip()}],
                "stdout": secret_line.strip(),
            },
            config_path="~/.pi/agent/settings.json",
            source_scope="project",
            cwd=tmp_path,
            home_dir=tmp_path,
        )

        assert artifact is not None
        assert artifact.harness == "pi"
        assert artifact.artifact_id.startswith("pi:")
        assert artifact.metadata["guard_default_action"] == "require-reapproval"

    def test_pi_stdout_only_post_tool_output_creates_runtime_artifact(self, tmp_path: Path) -> None:
        secret_path = tmp_path / ".npmrc"
        secret_line = "//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz012345\n"
        secret_path.write_text(secret_line, encoding="utf-8")

        artifact = _codex_post_tool_output_artifact(
            harness="pi",
            payload={
                "tool_name": "read",
                "tool_input": {"filePath": str(secret_path)},
                "stdout": secret_line.strip(),
            },
            config_path="~/.pi/agent/settings.json",
            source_scope="project",
            cwd=tmp_path,
            home_dir=tmp_path,
        )

        assert artifact is not None
        assert artifact.harness == "pi"
        assert artifact.artifact_id.startswith("pi:")

    def test_pi_source_file_read_with_credential_like_code_does_not_block(self, tmp_path: Path) -> None:
        source_path = tmp_path / "src" / "lib" / "guard-notion-api.ts"
        source_path.parent.mkdir(parents=True)
        source_path.write_text("export const NOTION_API_KEY = process.env.NOTION_API_KEY;\n", encoding="utf-8")

        artifact = _codex_post_tool_output_artifact(
            harness="pi",
            payload={
                "tool_name": "Read",
                "tool_input": {"file_path": str(source_path)},
                "tool_response": [{"type": "text", "text": source_path.read_text(encoding="utf-8")}],
            },
            config_path="~/.pi/agent/settings.json",
            source_scope="project",
            cwd=tmp_path,
            home_dir=tmp_path,
        )

        assert artifact is None

    def test_pi_focused_pytest_messages_label_pi_runtime(self) -> None:
        assert _codex_tool_output_request_summary(
            harness_label="Pi",
            tool_name="Bash",
            command_text=(
                "python3 -m pytest "
                "tests/test_guard_harness_smoke.py::TestSmokeEvidenceTemplate::"
                "test_release_checklist_references_smoke_evidence -q 2>&1"
            ),
            local_secret_source=None,
            focused_pytest=True,
            merged_output_capture=True,
        ) == (
            "Pi tool `Bash` ran focused pytest, merged stderr into stdout while running "
            "`python3 -m pytest "
            "tests/test_guard_harness_smoke.py::TestSmokeEvidenceTemplate::"
            "test_release_checklist_references_smoke_evidence -q 2>&1`, and the captured output "
            "looked credential-like."
        )
        assert _codex_tool_output_runtime_summary(
            None,
            harness_label="Pi",
            focused_pytest=True,
            merged_output_capture=True,
        ) == (
            "Focused pytest merged stderr into stdout and emitted credential-looking output before "
            "it reached Pi. Pytest can execute repository-controlled code, so this could be a real "
            "local secret."
        )
        assert _codex_tool_output_runtime_reason(
            None,
            harness_label="Pi",
            focused_pytest=True,
            merged_output_capture=True,
        ) == (
            "Guard stopped this pytest output because pytest executes repository-controlled code, "
            "and merging stderr into stdout can forward real local secrets to Pi. If you only need "
            "the exit status, rerun without `2>&1` or keep stderr out of model-visible output."
        )

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
