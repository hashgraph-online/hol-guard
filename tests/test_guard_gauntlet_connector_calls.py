"""Connector-setup Gauntlet lane: MCP call recording, the granted-tool oracle and the token scanner."""

from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

from ci.gauntlet.catalog import CONNECTOR_CATALOG, load_catalog
from ci.gauntlet.claude_tools import claude_tools
from ci.gauntlet.connector_fixtures import ECHO_TEXT, stage_connector_case
from ci.gauntlet.connector_judge import (
    CONNECTOR_SETUP_REQUIRED,
    connector_tool_outcome,
    ungranted_stop,
)
from ci.gauntlet.harness_judge import assess_harness_case
from ci.gauntlet.harnesses import adapter, read_transcript
from ci.gauntlet.proofs import required_checks

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts" / "ci"))
import check_private_tokens  # noqa: E402

CATALOG = {scenario.id: scenario for scenario in load_catalog(CONNECTOR_CATALOG)}
STDIO = CATALOG["connector-granted-mcp-stdio-tool"]
CLI = CATALOG["connector-granted-local-cli-loopback"]
TOOL = "mcp__echo-mcp__echo"


def _stream(path: Path, events: list[dict]) -> Path:
    path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")
    return path


def _codex_stream(tmp_path: Path, *, status: str = "completed", error: object = None, text: str = ECHO_TEXT) -> Path:
    item = {"id": "m1", "type": "mcp_tool_call", "server": "echo-mcp", "tool": "echo", "arguments": {"text": text}}
    done = {**item, "status": status, "result": {"content": [{"type": "text", "text": text}]}, "error": error}
    return _stream(
        tmp_path / "codex.jsonl",
        [
            {"type": "item.started", "item": {**item, "status": "in_progress"}},
            {"type": "item.completed", "item": done},
            {"type": "turn.completed"},
        ],
    )


def _cursor_stream(tmp_path: Path, *, is_error: bool = False) -> Path:
    body = {"args": {"providerIdentifier": "echo-mcp", "toolName": "echo", "args": {"text": ECHO_TEXT}}}
    done = {"args": body["args"], "result": {"success": {"content": [{"text": ECHO_TEXT}], "isError": is_error}}}
    return _stream(
        tmp_path / "cursor.jsonl",
        [
            {"type": "tool_call", "subtype": "started", "call_id": "c1", "tool_call": {"mcpToolCall": body}},
            {"type": "tool_call", "subtype": "completed", "call_id": "c1", "tool_call": {"mcpToolCall": done}},
            {"type": "result", "subtype": "success", "is_error": False, "result": "done"},
        ],
    )


def test_codex_records_the_mcp_call_with_arguments_and_result(tmp_path: Path) -> None:
    (call,) = read_transcript("codex", _codex_stream(tmp_path))["calls"]
    assert call["tool"] == TOOL and call["args"] == {"text": ECHO_TEXT}
    assert call["is_error"] is False and ECHO_TEXT in call["result"]


def test_codex_failed_mcp_call_is_an_error(tmp_path: Path) -> None:
    (call,) = read_transcript("codex", _codex_stream(tmp_path, status="failed", error={"message": "boom"}))["calls"]
    assert call["is_error"] is True


def test_cursor_records_the_mcp_call_under_the_normalized_name(tmp_path: Path) -> None:
    (call,) = read_transcript("cursor", _cursor_stream(tmp_path))["calls"]
    assert call["tool"] == TOOL and call["args"] == {"text": ECHO_TEXT}
    assert call["is_error"] is False
    (failed,) = read_transcript("cursor", _cursor_stream(tmp_path, is_error=True))["calls"]
    assert failed["is_error"] is True


def _claude_command(scenario, workspace: Path, **extra) -> list[str]:
    return adapter("claude-code").command(
        "claude", scenario=scenario, prompt="prompt", context="", workspace=workspace, model=None, **extra
    )


def test_claude_keeps_mcp_tools_out_of_the_built_in_list_and_loads_the_launch_config(tmp_path: Path) -> None:
    assert claude_tools(STDIO) == ""
    home = tmp_path / "home"
    home.mkdir()
    fixture = stage_connector_case("connector-setup", tmp_path, home, tmp_path / "g", "claude-code")
    command = _claude_command(STDIO, home, mcp_config=fixture.mcp_configs[0])
    assert command[command.index("--mcp-config") + 1] == str(fixture.mcp_configs[0])
    assert "--strict-mcp-config" in command


@pytest.mark.parametrize("scenario", list(CATALOG.values()), ids=list(CATALOG))
def test_claude_command_builds_for_every_connector_case(scenario, tmp_path: Path) -> None:
    command = _claude_command(scenario, tmp_path)
    assert command and "--mcp-config" not in command


def _decision(tool: str = TOOL, decision: str = "allow", reason: str = "native_allow") -> dict:
    return {"tool": tool, "command": None, "decision": decision, "reason_code": reason, "receipt_decision": decision}


def _call(tool: str = TOOL, text: str = ECHO_TEXT, is_error: bool = False, result: str | None = None) -> dict:
    return {
        "tool": tool,
        "args": {"text": text},
        "is_error": is_error,
        "result": ECHO_TEXT if result is None else result,
    }


def test_granted_tool_passes_only_for_one_reviewed_call_with_the_asked_text() -> None:
    assert connector_tool_outcome(STDIO, [_decision()], [_call()]) is None


@pytest.mark.parametrize(
    ("decisions", "calls", "outcome", "expected"),
    [
        ([], [], "not-exercised", "never called"),
        ([_decision("Bash")], [_call("bash")], "not-exercised", "never called"),
        ([], [_call()], "harness-error", "without a Guard review"),
        ([_decision(decision="deny", reason=CONNECTOR_SETUP_REQUIRED)], [_call()], "fail", "stopped the granted"),
        ([_decision()] * 2, [_call(), _call()], "not-exercised", "2 times"),
        ([_decision()], [_call(text="other")], "not-exercised", "other arguments"),
        ([_decision()], [_call(is_error=True)], "task-incomplete", "did not return"),
        ([_decision()], [_call(result="nothing")], "task-incomplete", "did not return"),
    ],
)
def test_granted_tool_failures(decisions: list, calls: list, outcome: str, expected: str) -> None:
    result = connector_tool_outcome(STDIO, decisions, calls)
    assert result is not None and result[0] == outcome and expected in result[1], result


def test_granted_cases_that_were_stopped_for_setup_are_not_exercised() -> None:
    stop = _decision("Bash", decision="deny", reason=CONNECTOR_SETUP_REQUIRED)
    assert ungranted_stop(CLI, [stop])[0] == "not-exercised"
    assert ungranted_stop(CLI, [_decision("Bash")]) is None
    assert ungranted_stop(CATALOG["connector-ungranted-local-cli"], [stop]) is None


def _case(scenario, decisions: list[dict], calls: list[dict]) -> dict:
    rows = []
    for item in decisions:
        payload = {"hook_event_name": "PreToolUse", "tool_name": item["tool"], "tool_input": {}}
        response = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": item["decision"]}}
        receipt = {"harness": "codex", "event_name": "PreToolUse", "decision": item["decision"]}
        rows.append({"payload": payload, "response": response, "receipt": receipt})
    return {
        "harness": "codex",
        "guard_rows": rows,
        "transcript": {"calls": calls, "terminal": True, "failed": False, "final_text": "done"},
        "returncode": 0,
        "filesystem": dict.fromkeys(required_checks(scenario), True),
        "native_routes": {"native_resident": len(rows)},
        "egress_requests": [],
        "approval_delta": 0,
        "cleanup_ok": True,
        "credentials_seeded": 1,
        "credential_env": [],
        "expected_commands": [],
    }


def test_a_real_mcp_call_passes_the_case_and_an_unrelated_allowed_call_does_not() -> None:
    passed = assess_harness_case(STDIO, _case(STDIO, [_decision()], [_call()]))
    assert passed["outcome"] == "pass", passed
    unrelated = assess_harness_case(STDIO, _case(STDIO, [_decision("Bash")], [_call("bash")]))
    assert unrelated["outcome"] == "not-exercised", unrelated


def test_the_prompt_asks_for_the_text_the_judge_checks() -> None:
    assert ECHO_TEXT in STDIO.prompt


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


def _repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.name", "Test")
    _git(tmp_path, "config", "user.email", "test@example.test")
    return tmp_path


ENTRIES = [(1, "secretcodename")]


def test_scanner_finds_a_token_in_a_binary_file(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    (root / "blob.bin").write_bytes(b"\x00\x01\x02 prefix SecretCodename suffix \x00")
    _git(root, "add", ".")
    assert check_private_tokens.scan(root, ENTRIES, None) == ["blob.bin:1: matches private denylist entry #1"]


def test_scanner_finds_a_token_beyond_the_old_size_cutoff(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    (root / "big.txt").write_bytes(b"x" * (5 * 1024 * 1024) + b"\nline two secretcodename\n")
    _git(root, "add", ".")
    assert check_private_tokens.scan(root, ENTRIES, None) == ["big.txt:2: matches private denylist entry #1"]


@pytest.mark.parametrize("offset", [0, 1, 7, 13])
def test_scanner_finds_a_token_across_a_chunk_boundary(monkeypatch, offset: int) -> None:
    monkeypatch.setattr(check_private_tokens, "CHUNK_BYTES", 16)
    data = b"a\n" + b"y" * (16 - 2 + offset) + b"SECRETCODENAME" + b"\nend\n"
    findings = check_private_tokens.scan_stream("f", io.BytesIO(data), ENTRIES)
    assert findings == ["f:2: matches private denylist entry #1"]


def test_scanner_reports_the_original_entry_position(tmp_path: Path, monkeypatch) -> None:
    environ = {"GUARD_PRIVATE_TOKEN_DENYLIST": "ab\nfoo-name\nbar-name"}
    entries = check_private_tokens.load_denylist(environ)
    findings = check_private_tokens.scan_text("f", "x\nmentions Bar-Name\n", entries)
    assert findings == ["f:2: matches private denylist entry #3"]


def test_a_file_that_cannot_be_read_is_a_finding(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    (root / "locked.txt").write_text("clean\n")
    _git(root, "add", ".")
    (root / "locked.txt").chmod(0)
    try:
        findings = check_private_tokens.scan(root, ENTRIES, None)
    finally:
        (root / "locked.txt").chmod(0o600)
    if findings:  # a root user can still read the file; elsewhere it must not be skipped
        assert findings == ["locked.txt: could not be scanned (PermissionError)"]


def test_a_symlink_target_is_scanned(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    (root / "link").symlink_to("secretcodename-target")
    _git(root, "add", ".")
    assert check_private_tokens.scan(root, ENTRIES, None) == ["link:1: matches private denylist entry #1"]


def test_commit_messages_are_scanned_whatever_bytes_they_hold(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    (root / "a.txt").write_text("clean\n")
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "first")
    (root / "b.txt").write_text("clean\n")
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "before \x01 delimiter\n\nthen secretcodename after")
    findings = check_private_tokens.scan(root, ENTRIES, "HEAD~1..HEAD")
    assert len(findings) == 1 and findings[0].endswith("message:3: matches private denylist entry #1")
