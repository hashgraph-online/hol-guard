"""Managed Pi extension installation and removal cases."""

from __future__ import annotations

__test__ = False


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
        text = extension_path.read_text(encoding="utf-8")
        assert 'pi.on("tool_call"' in text
        assert 'pi.on("tool_result"' in text
        assert 'pi.on("input"' in text
        assert 'hook_event_name: "PostToolUse"' in text
        assert "    if (originalOutputProof) return undefined;\n" in text
        assert (
            "return blockedToolResult(modelVisibleBlockedReason(reason, response.reason_code), event.details);" in text
        )
        assert '    if (response.decision === "allow") return undefined;\n' in text
        assert "const GUARD_CLI_WRAPPER_COMMAND =" in text
        assert "const GUARD_CLI_WRAPPER_ARGS =" in text
        assert "const GUARD_HOME =" in text
        assert "daemon-state.json" in text
        assert "daemon-auth-token" in text
        assert "/v1/hooks/pi?" in text
        assert "approval_request_id?: string" in text
        assert "approvalBlockedReason" in text
        assert "This exact tool call remains blocked" in text
        assert "Retry the exact same tool call once" in text
        assert "changing the command, arguments, or working directory creates a new action" in text
        assert "the saved HOL Guard approval should allow it" not in text
        assert "Do not call ask for this HOL Guard approval" in text
        assert 'option labeled "I\'ve approved this request in HOL Guard"' in text
        assert "void openApprovalUrl(response, openedApprovalUrls)" in text
        assert "trySpawnOpen(command, args)" in text
        assert "child.once('error', () => settle(false))" in text
        assert "pollApprovalResolution" in text
        assert "GUARD_APPROVAL_RESUME_FETCH_TIMEOUT_MS" in text
        assert "controller?.abort()" in text
        assert "pi.sendMessage(" in text
        assert "hol_guard_approval_resume" in text
        assert "triggerTurn: true, deliverAs: 'nextTurn'" in text
        assert "guardPayload.tool_response = event.content" in text
        assert "const GUARD_CONFIG_PATH =" in text
        assert "config_path: GUARD_CONFIG_PATH" in text
        assert '"hook", "--json", "--guard-home"' in text
        assert '"guard", "hook"' not in text
        assert '"--harness", "pi"' in text
        assert '"--home"' in text
        assert "ctx.cwd" in text
        assert "const timeoutHandle = setTimeout(() => {" in text
        assert "}, timeoutMs);" in text
        assert "const GUARD_TASKKILL_PATH =" in text
        assert "process.env.SystemRoot" not in text
        assert "process.env.SYSTEMROOT" not in text
        if os.name == "nt":
            assert "taskkill.exe" in text
        else:
            assert "const GUARD_TASKKILL_PATH = null;" in text
        assert "['/PID', String(child.pid), '/T', '/F']" in text
        assert "taskkill.once('close', (status) => finish(status === 0))" in text
        assert "taskkill.kill('SIGKILL')" in text
        assert "return waitForGuardCliChildExit(child, 200)" in text
        assert "guardCliContainmentFailed = true" in text
        assert "containmentFailure," in text
        assert 'reason_code: "guard_cli_containment_failed"' in text
        assert "{ code: 'ECONTAINMENT' }" in text
        recovery_block = text.split("async function recoverGuardDaemon(", 1)[1].split(
            "async function daemonGuardResponse(",
            1,
        )[0]
        assert recovery_block.index("if (guardCliContainmentFailed) return false;") < recovery_block.index(
            "runGuardCliCommand("
        )
        assert str(extension_path) in json.loads(settings_path.read_text(encoding="utf-8"))["extensions"]
        assert not omp_extension_path.exists()
        assert "guardPayload.tool_response = event.content" in text
        assert "stdout: toolOutput" not in text
        assert "tool_response: toolOutput" in text
        assert "contentText(event.content)" not in text
        assert "options?.enforceSizeCap === true" in text
        assert 'payloadToSend.hook_event_name === "PostToolUse"' not in text
        assert "delete reducedPayload.stdout;" not in text
        # Source-ref fast path support
        assert "guard_source_ref" in text
        assert "digestOutputText" in text
        assert "sourceFileRefForPostToolUse" in text
        assert "isVirtualSourcePath" in text
        assert "isAbsoluteSourcePath" not in text
        assert "if (!path || isVirtualSourcePath(path)) return null;" in text
        assert "text_excerpt: toolOutput" in text
        assert "GUARD_SOURCE_REF_MAX_OUTPUT_CHARS" in text
        assert "GUARD_SOURCE_REF_ALLOWED_TOOL_NAMES" in text
        assert "reviewed_output_sha256" in text
        assert 'response.model_output_action === "allow_original"' in text
        assert "response.reviewed_output_sha256 === digest.sha256" in text
        assert "function daemonResponseCanReturn(" in text
        assert "daemonResponseCanReturn(payload, daemonAttempt.response)" in text
        assert 'if (response.decision === "allow" || response.decision === "deny") return true;' in text
        assert "observe_mode?: boolean;" in text
        assert "if (response.observe_mode === true) return undefined;" in text
        assert text.index("if (response.observe_mode === true) return undefined;") < text.index(
            "if (outputTruncated) {"
        )
        # digestOutputText must only hash text-bearing fields, not metadata
        # like {type: "text"} - otherwise structured source reads never match
        assert "record.type === 'text'" in text
        assert "record.text" in text
        assert "OUTPUT_TEXT_KEYS" in text
        # guard_payload_ref fallback still present
        assert "guard_payload_ref" in text
        # Reviewed excerpt still returned when not proven safe
        assert "return reviewedToolResult(reviewedContent, event.details, event.isError === true);" in text

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
        assert "[...GUARD_CLI_WRAPPER_ARGS, JSON.stringify(args)]" in text
        assert "async function daemonGuardResponse(" in text
        assert "await fetch(`http://127.0.0.1:${connection.port}/v1/hooks/pi?" in text
        assert "serializedPayload, cwd, GUARD_DAEMON_TIMEOUT_MS, deadlineAt" in text
        assert "parsedPayload.guard_remaining_ms" in text
        assert "body: daemonPayload" in text
        assert 'recoveryKind: "authenticated-control-plane-failure",\n        };' in text
        assert "const response = await runGuard(" in text
        assert "if (result.error) {" in text
        assert "const errorMessage = result.error.message;" in text
        assert "const errorCode =" in text
        assert 'decision: "deny"' in text
        assert "errorCode === 'ETIMEDOUT'" in text
        assert "could not complete fallback review before the Pi deadline" in text
        assert "HOL Guard Pi hook failed before completing review" in text

    def test_managed_extension_fails_safe_on_ambiguous_success_payloads(
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

        assert 'if (!raw) return { response: null, recoveryKind: "transport-failure" };' in text
        assert "function normalizeGuardResponse(" in text
        assert "const normalized = normalizeGuardResponse(parsed);" in text
        assert 'parsed.reason !== undefined && parsed.reason !== null && typeof parsed.reason !== "string"' in text
        assert 'if (parsed.decision === "block")' in text
        assert "Array.isArray(value)" in text
        assert "function fallbackGuardResponse(" in text
        assert '"guard_cli_invalid_response"' in text
        assert 'normalized !== null && (result.status === 0 || normalized.decision === "deny")' in text
        assert "if (result.status !== 0)" in text
        assert 'hook_event_name: "PreToolUse"' in text

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
        assert "function modelVisibleBlockedReason(reason: string, reasonCode?: string): string" in text
        assert "Do not retry the same tool call automatically" in text
        assert 'reasonCode === "guard_cli_recovery_timeout"' in text
        assert 'reasonCode === "daemon_hook_deadline_exhausted"' in text
        assert "const modelReason = modelVisibleBlockedReason(reason, response.reason_code);" in text
        assert "if (toolCallId) blockedToolResults.set(toolCallId, modelReason);" in text
        assert "return blockedToolResult(modelReason, event.details);" in text
        assert "return blockedToolResult(reason, event.details);" not in text
        assert "blockedToolResults.delete(toolCallId);" in text
        # Oversized tool results are passed to Guard by reference for full
        # review, not pre-emptively blocked.
        assert "HOL Guard blocked oversized Pi tool output before review" not in text
        assert "oversizeNotice" not in text
        assert "ctx.ui.notify(oversizeNotice" not in text
        assert "const response = await runGuard(" in text
        # When truncated, the reviewed excerpt (not the full unreviewed output) is
        # returned to Pi so omitted content never reaches the model.
        assert "function reviewedToolResult(" in text
        assert "return reviewedToolResult(reviewedContent, event.details, event.isError === true);" in text
        assert "guardPayload.tool_response = event.content" in text
        assert "stdout: toolOutput" not in text
        assert "tool_response: toolOutput" in text
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
        assert "function daemonResponseCanReturn(" in text
        assert "daemonResponseCanReturn(payload, daemonAttempt.response)" in text
        assert 'if (response.decision === "allow" || response.decision === "deny") return true;' in text
        # digestOutputText must only hash text-bearing fields, not metadata
        # like {type: "text"} — otherwise structured source reads never match
        assert "record.type === 'text'" in text
        assert "record.text" in text
        assert "OUTPUT_TEXT_KEYS" in text
        # guard_payload_ref fallback still present
        assert "guard_payload_ref" in text
        # Reviewed excerpt still returned when not proven safe
        assert "return reviewedToolResult(reviewedContent, event.details, event.isError === true);" in text

    def test_omp_install_writes_only_omp_extension(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.adapters.pi.install_guard_shim",
            lambda *args, **kwargs: {"shim_path": str(ctx.guard_home / "bin" / "guard-omp"), "notes": []},
        )

        manifest = get_adapter("omp").install(ctx)

        extension_path = Path(str(manifest["config_path"]))
        assert manifest["harness"] == "omp"
        assert extension_path == ctx.home_dir / ".omp" / "agent" / "extensions" / "hol-guard.ts"
        assert '"--harness", "omp"' in extension_path.read_text(encoding="utf-8")
        assert "/v1/hooks/omp?" in extension_path.read_text(encoding="utf-8")
        assert "Oh My Pi hook failed before completing review" in extension_path.read_text(encoding="utf-8")
        assert "before Pi could use it" not in extension_path.read_text(encoding="utf-8")
        assert not (ctx.home_dir / ".pi" / "agent" / "extensions" / "hol-guard.ts").exists()

    def test_omp_display_name_does_not_rewrite_paths_containing_pi(self) -> None:
        home_dir = Path("Pieter") / "__PI_NAME__"
        guard_home = home_dir / "Pi Tools" / ".hol-guard"
        settings_path = home_dir / ".omp" / "agent" / "settings.json"

        source = managed_extension_source(
            guard_home=guard_home,
            home_dir=home_dir,
            settings_path=settings_path,
            harness="omp",
            display_name="Oh My Pi",
        )

        assert str(guard_home) in source
        assert str(home_dir) in source
        assert "Oh My Pieter" not in source
        assert "Pieter/Oh My Pi" not in source
        assert "Oh My Pi hook failed before completing review" in source

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
        omp_extension_path.parent.mkdir(parents=True, exist_ok=True)
        omp_extension_path.write_text("export default 'omp';\n", encoding="utf-8")
        omp_settings_path.parent.mkdir(parents=True, exist_ok=True)
        omp_settings_path.write_text(json.dumps({"extensions": [str(omp_extension_path)]}), encoding="utf-8")

        uninstall_manifest = adapter.uninstall(ctx)

        assert uninstall_manifest["active"] is False
        assert not extension_path.exists()
        assert omp_extension_path.exists()
        assert json.loads(settings_path.read_text(encoding="utf-8"))["extensions"] == []
        assert json.loads(omp_settings_path.read_text(encoding="utf-8"))["extensions"] == [str(omp_extension_path)]


# Bind the unchanged facade globals after class definitions to allow either import order.
from .test_pi_adapter import (  # noqa: E402
    Path,
    _ctx,
    get_adapter,
    json,
    managed_extension_source,
    os,
)
