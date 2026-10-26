"""Audit trail for scripts embedded in shell commands via heredoc."""

from __future__ import annotations

import argparse
import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

from codex_plugin_scanner.guard.cli.commands_dispatch_records import (
    _embedded_scripts_for_receipt,
    _run_guard_history_command,
)
from codex_plugin_scanner.guard.models import GuardReceipt
from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope
from codex_plugin_scanner.guard.runtime.embedded_script_evidence import (
    EMBEDDED_SCRIPT_REMEDIATION_GUIDANCE,
    embedded_script_evidence_entries,
)
from codex_plugin_scanner.guard.store import GuardStore

_MAX_EMBEDDED_SCRIPT_EVIDENCE_ENTRIES = 8


def _store_with_command_receipt(tmp_path: Path, command: str, receipt_id: str) -> GuardStore:
    store = GuardStore(tmp_path / "guard")
    entries = embedded_script_evidence_entries(command)
    receipt = GuardReceipt(
        receipt_id=receipt_id,
        harness="kimi",
        artifact_id="kimi:project:Bash",
        artifact_hash="sha256:test",
        policy_decision="block",
        capabilities_summary="shell command",
        changed_capabilities=("shell",),
        provenance_summary="test",
        scanner_evidence=tuple(entries),
        raw_command_text=command,
        timestamp="2025-01-01T00:00:00Z",
    )
    envelope = GuardActionEnvelope(
        schema_version=1,
        action_id="test-action",
        harness="kimi",
        event_name="PreToolUse",
        action_type="shell_command",
        workspace=str(tmp_path),
        workspace_hash=None,
        tool_name="Bash",
        command=command,
        prompt_excerpt=None,
        prompt_text=None,
        target_paths=(),
        network_hosts=(),
        mcp_server=None,
        mcp_tool=None,
        package_manager=None,
        package_name=None,
    )
    store.add_receipt(receipt, action_envelope=envelope)
    return store


def test_interpreter_heredoc_is_marked_executed() -> None:
    entries = embedded_script_evidence_entries("python3 - <<'EOF'\nimport os\nprint(os.name)\nEOF")
    assert len(entries) == 1
    entry = entries[0]
    assert entry["kind"] == "heredoc"
    assert entry["executed"] is True
    assert entry["execution_status"] == "executed"
    assert entry["executable"] == "python3"
    assert entry["quoted"] is True
    body = "import os\nprint(os.name)\n"
    assert entry["sha256"] == hashlib.sha256(body.encode("utf-8")).hexdigest()
    assert entry["bytes"] == len(body.encode("utf-8"))
    assert entry["lines"] == 2


def test_write_then_run_heredoc_is_marked_not_executed() -> None:
    command = "cat > /tmp/pw.mjs << 'EOF'\nconsole.log('x')\nEOF\nnode /tmp/pw.mjs"
    entries = embedded_script_evidence_entries(command)
    assert len(entries) == 1
    entry = entries[0]
    assert entry["executed"] is False
    assert entry["execution_status"] == "not_executed"
    assert entry["executable"] == "cat"


def test_opaque_wrapper_heredoc_execution_is_indeterminate() -> None:
    command = "python-stdin-wrapper <<'EOF'\nprint('wrapped')\nEOF"
    entries = embedded_script_evidence_entries(command)

    assert len(entries) == 1
    assert entries[0]["executable"] == "python-stdin-wrapper"
    assert entries[0]["executed"] is None
    assert entries[0]["execution_status"] == "indeterminate"


def test_multiple_heredocs_are_each_indexed() -> None:
    command = "cat << 'A' > x.txt\nfirst\nA\npython3 - <<'B'\nsecond\nB"
    entries = embedded_script_evidence_entries(command)
    assert len(entries) == 2
    assert entries[0]["index"] == 0
    assert entries[1]["index"] == 1
    assert entries[1]["executed"] is True


def test_evidence_entries_are_bounded() -> None:
    parts = [f"cat << 'D{i}' > /tmp/f{i}.txt\nbody{i}\nD{i}" for i in range(_MAX_EMBEDDED_SCRIPT_EVIDENCE_ENTRIES + 3)]
    entries = embedded_script_evidence_entries("\n".join(parts))
    heredoc_entries = [e for e in entries if e.get("kind") == "heredoc"]
    summary_entries = [e for e in entries if e.get("kind") == "summary"]
    assert len(heredoc_entries) == _MAX_EMBEDDED_SCRIPT_EVIDENCE_ENTRIES
    assert len(summary_entries) == 1
    assert summary_entries[0]["truncated"] is True
    assert summary_entries[0]["total_heredocs"] == _MAX_EMBEDDED_SCRIPT_EVIDENCE_ENTRIES + 3


def _receipt_with_embedded_script(command: str) -> dict[str, object]:
    return {
        "receipt_id": "guard-receipt-test",
        "scanner_evidence": embedded_script_evidence_entries(command),
        "action_envelope_json": {"command": command},
    }


def test_embedded_scripts_for_receipt_reconstructs_and_verifies_body() -> None:
    body = "import os\nprint('auditable')\n"
    command = f"python3 - <<'EOF'\n{body}EOF"
    scripts = _embedded_scripts_for_receipt(_receipt_with_embedded_script(command))
    assert len(scripts) == 1
    script = scripts[0]
    assert script["executed"] is True
    assert script["sha256_verified"] is True
    assert script["body"] == body


def test_embedded_scripts_for_receipt_tampered_body_fails_verification() -> None:
    command = "python3 - <<'EOF'\noriginal\nEOF"
    receipt = _receipt_with_embedded_script(command)
    tampered = dict(receipt)
    tampered["action_envelope_json"] = {"command": "python3 - <<'EOF'\ntampered\nEOF"}
    scripts = _embedded_scripts_for_receipt(tampered)
    assert len(scripts) == 1
    assert scripts[0]["sha256_verified"] is False


def test_embedded_scripts_for_receipt_recovers_from_whitespace_shifted_command() -> None:
    """Evidence spans are computed on stripped command text; the envelope may
    retain the unstripped form. Recovery must still verify the hash."""
    body = "echo shifted\n"
    stripped = f"cat << 'EOF'\n{body}EOF"
    shifted = f" {stripped}\n"
    receipt: dict[str, object] = {
        "receipt_id": "guard-receipt-shifted",
        "scanner_evidence": embedded_script_evidence_entries(stripped),
        "action_envelope_json": {"command": shifted},
    }
    scripts = _embedded_scripts_for_receipt(receipt)
    assert len(scripts) == 1
    assert scripts[0]["body"] == body
    assert scripts[0]["sha256_verified"] is True


def test_embedded_scripts_for_receipt_recovers_with_non_ascii_prefix() -> None:
    """Spans are code-point indices while ``bytes`` counts UTF-8 bytes;
    recovery must not confuse the two for multibyte text before the body."""
    body = "print('héllo wörld')\n"
    stripped = f"echo '日本語のパス' > /tmp/ñame.txt && python3 - <<'EOF'\n{body}EOF"
    receipt: dict[str, object] = {
        "receipt_id": "guard-receipt-unicode",
        "scanner_evidence": embedded_script_evidence_entries(stripped),
        "action_envelope_json": {"command": f" {stripped}"},
    }
    scripts = _embedded_scripts_for_receipt(receipt)
    assert len(scripts) == 1
    assert scripts[0]["body"] == body
    assert scripts[0]["sha256_verified"] is True


def test_embedded_scripts_for_receipt_without_evidence_returns_empty() -> None:
    assert _embedded_scripts_for_receipt({"scanner_evidence": []}) == []
    assert _embedded_scripts_for_receipt({}) == []
    assert _embedded_scripts_for_receipt({"scanner_evidence": [{"source": "policy_composition"}]}) == []


def test_history_explain_includes_embedded_scripts(tmp_path: Path, capsys: Any) -> None:
    body = "console.log('from history')\n"
    command = f"node << 'EOF'\n{body}EOF"
    receipt_id = str(uuid.uuid4())
    store = _store_with_command_receipt(tmp_path, command, receipt_id)
    args = argparse.Namespace(receipt_id=receipt_id, json=True, script=False, history_command="explain")
    result = _run_guard_history_command(args, store=store)
    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    scripts = payload["embedded_scripts"]
    assert len(scripts) == 1
    assert scripts[0]["body"] == body
    assert scripts[0]["sha256_verified"] is True


def test_history_explain_preserves_indeterminate_wrapper_execution(tmp_path: Path, capsys: Any) -> None:
    command = "python-stdin-wrapper <<'EOF'\nprint('wrapped')\nEOF"
    receipt_id = str(uuid.uuid4())
    store = _store_with_command_receipt(tmp_path, command, receipt_id)
    args = argparse.Namespace(receipt_id=receipt_id, json=True, script=False, history_command="explain")

    result = _run_guard_history_command(args, store=store)

    assert result == 0
    script = json.loads(capsys.readouterr().out)["embedded_scripts"][0]
    assert script["executed"] is None
    assert script["execution_status"] == "indeterminate"


def test_history_explain_script_flag_emits_only_scripts(tmp_path: Path, capsys: Any) -> None:
    body = "console.log('focused')\n"
    command = f"node << 'EOF'\n{body}EOF"
    receipt_id = str(uuid.uuid4())
    store = _store_with_command_receipt(tmp_path, command, receipt_id)
    args = argparse.Namespace(receipt_id=receipt_id, json=True, script=True, history_command="explain")
    result = _run_guard_history_command(args, store=store)
    assert result == 0
    payload = json.loads(capsys.readouterr().out)
    assert "receipt" not in payload
    assert "evidence" not in payload
    assert payload["embedded_script_count"] == 1
    assert payload["embedded_scripts"][0]["body"] == body


def test_history_explain_missing_receipt_returns_error(tmp_path: Path, capsys: Any) -> None:
    store = GuardStore(tmp_path / "guard")
    args = argparse.Namespace(receipt_id="guard-receipt-missing", json=True, script=False, history_command="explain")
    result = _run_guard_history_command(args, store=store)
    assert result == 1
    payload = json.loads(capsys.readouterr().out)
    assert "error" in payload


def test_remediation_guidance_is_actionable() -> None:
    assert "workspace file" in EMBEDDED_SCRIPT_REMEDIATION_GUIDANCE
    assert "audit" in EMBEDDED_SCRIPT_REMEDIATION_GUIDANCE.lower()
