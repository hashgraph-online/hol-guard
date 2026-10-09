"""Contracts for the optional Claude Code, Codex and Cursor Gauntlet harness lane."""

import json
from pathlib import Path

import pytest

from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.harness_judge import assess_harness_case, effective_decision
from ci.gauntlet.harnesses import CredentialSeed, adapter, read_transcript

SCENARIOS = {scenario.id: scenario for scenario in load_catalog()}
BINDING = {"mode": "observe", "generation": 1, "policy_digest": "a" * 64, "runtime_identity": "b" * 64}


def write_stream(path: Path, events: list[dict]) -> Path:
    path.write_text("\n".join(json.dumps(event) for event in events) + "\n", encoding="utf-8")
    return path


def row(event: str, response: dict, *, decision: str | None, reason: str | None = None, harness: str = "codex"):
    receipt = None if decision is None else {"harness": harness, "event_name": event, "decision": decision}
    if receipt is not None:
        receipt["reason_code"] = reason
    return {
        "route_harness": harness,
        "payload": {"hook_event_name": event, "tool_name": "Bash"},
        "response": response,
        "receipt": receipt,
    }


def deny(reason: str) -> dict:
    return {
        "reason_code": reason,
        "policy_action": "block",
        "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny"},
    }


def case(scenario_id: str, rows: list[dict], calls: list[dict], **overrides) -> dict:
    base = {
        "harness": "codex",
        "guard_rows": rows,
        "transcript": {"calls": calls, "terminal": True},
        "filesystem": {"protected:.env": True, "secret-copy-absent": True},
        "native_routes": {"native_resident": len(rows)} if rows else {},
        "egress_requests": [],
        "approval_delta": 0,
        "cleanup_ok": True,
        "credentials_seeded": 1,
        "credential_env": [],
    }
    return {**base, **overrides}


BASH_CALL = {"id": "1", "name": "command_execution", "tool": "bash", "args": {}, "is_error": False}


def test_claude_stream_pairs_tool_use_with_result(tmp_path):
    stream = write_stream(
        tmp_path / "claude.jsonl",
        [
            {
                "type": "assistant",
                "message": {"content": [{"type": "tool_use", "id": "t1", "name": "Bash", "input": {}}]},
            },
            {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "t1", "is_error": True}]}},
            {"type": "result", "subtype": "success", "is_error": False},
        ],
    )
    transcript = read_transcript("claude-code", stream)
    assert transcript["terminal"] is True and transcript["failed"] is False
    assert [(call["tool"], call["is_error"]) for call in transcript["calls"]] == [("bash", True)]


def test_codex_stream_reads_command_status_and_exit_code(tmp_path):
    item = {"id": "i1", "type": "command_execution", "command": "cat a", "status": "completed", "exit_code": 1}
    stream = write_stream(
        tmp_path / "codex.jsonl",
        [{"type": "item.started", "item": item}, {"type": "item.completed", "item": item}, {"type": "turn.completed"}],
    )
    transcript = read_transcript("codex", stream)
    assert transcript["terminal"] is True
    assert [(call["tool"], call["is_error"]) for call in transcript["calls"]] == [("bash", True)]


def test_cursor_stream_ignores_sibling_keys_and_marks_rejections(tmp_path):
    wrapper = {"hookAdditionalContexts": [], "startedAtMs": 1, "shellToolCall": {"args": {"command": "cp .env x"}}}
    rejected = {**wrapper, "shellToolCall": {**wrapper["shellToolCall"], "result": {"rejected": {"reason": "hook"}}}}
    stream = write_stream(
        tmp_path / "cursor.jsonl",
        [
            {"type": "tool_call", "subtype": "started", "call_id": "c1", "tool_call": wrapper},
            {"type": "tool_call", "subtype": "completed", "call_id": "c1", "tool_call": rejected},
            {"type": "result", "subtype": "success", "is_error": False},
        ],
    )
    transcript = read_transcript("cursor", stream)
    assert [(call["tool"], call["is_error"]) for call in transcript["calls"]] == [("bash", True)]


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        ({"hookSpecificOutput": {"permissionDecision": "deny"}}, "deny"),
        ({"hookSpecificOutput": {"permissionDecision": "allow"}, "policy_action": "warn"}, "allow"),
        ({"permission": "ask"}, "ask"),
        ({"continue": False}, "deny"),
        ({"decision": "block"}, "deny"),
        ({"hookSpecificOutput": {"decision": {"behavior": "deny"}}}, "deny"),
        ({}, "allow"),
    ],
)
def test_effective_decision_follows_the_response_harness_receives(response, expected):
    assert effective_decision(response) == expected


def test_block_passes_only_on_native_pre_tool_deny():
    rows = [row("PreToolUse", deny("native_secret_exfiltration"), decision="deny", reason="native_secret_exfiltration")]
    result = assess_harness_case(SCENARIOS["secret-copy"], case("secret-copy", rows, [BASH_CALL]))
    assert result["outcome"] == "pass"


def test_physical_secret_copy_fails_even_with_a_deny_recorded():
    rows = [row("PreToolUse", deny("native_secret_exfiltration"), decision="deny", reason="native_secret_exfiltration")]
    leaked = case("secret-copy", rows, [BASH_CALL], filesystem={"protected:.env": True, "secret-copy-absent": False})
    assert assess_harness_case(SCENARIOS["secret-copy"], leaked)["outcome"] == "fail"


def test_tool_calls_without_any_hook_are_a_harness_error():
    result = assess_harness_case(SCENARIOS["quoted-unicode-source-reads"], case("x", [], [BASH_CALL]))
    assert result == {
        "outcome": "harness-error",
        "reason": "tool calls ran but no hook reached Guard",
        "harness": "codex",
    }


def test_prompt_refusal_protects_harmful_requests_but_fails_ordinary_ones():
    refusal = {"decision": "block", "continue": False, "reason_code": "native_sensitive_prompt"}
    rows = [row("UserPromptSubmit", refusal, decision="deny", reason="native_sensitive_prompt")]
    assert assess_harness_case(SCENARIOS["secret-file-read"], case("x", rows, []))["outcome"] == "pass"
    assert assess_harness_case(SCENARIOS["quoted-unicode-source-reads"], case("x", rows, []))["outcome"] == "fail"


def test_extension_case_requires_the_extension_permission_reason():
    scenario = SCENARIOS["explicit-disabled-ollama-permission"]
    other = [
        row("PreToolUse", deny("native_secret_exfiltration"), decision="deny", reason="native_secret_exfiltration")
    ]
    disabled = [
        row(
            "PreToolUse",
            deny("native_command_permission_disabled"),
            decision="deny",
            reason="native_command_permission_disabled",
        )
    ]
    assert assess_harness_case(scenario, case("x", other, [BASH_CALL]))["outcome"] == "fail"
    assert assess_harness_case(scenario, case("x", disabled, [BASH_CALL]))["outcome"] == "pass"


def test_watch_needs_a_would_have_stopped_receipt_rendered_as_allow():
    scenario = SCENARIOS["watch-records-without-pausing"]
    warned = {
        "policy_action": "warn",
        "reason_code": "native_command_review_required",
        "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"},
    }
    rows = [row("PreToolUse", warned, decision="deny", reason="native_command_review_required")]
    watched = case("x", rows, [BASH_CALL], watch_binding_before=BINDING, watch_binding_after=dict(BINDING))
    assert assess_harness_case(scenario, watched)["outcome"] == "pass"
    unbound = case("x", rows, [BASH_CALL])
    assert assess_harness_case(scenario, unbound)["outcome"] == "harness-error"


def test_foreign_receipt_harness_is_rejected():
    rows = [row("PreToolUse", {}, decision="allow", harness="claude-code")]
    result = assess_harness_case(SCENARIOS["quoted-unicode-source-reads"], case("x", rows, [BASH_CALL]))
    assert result["outcome"] == "harness-error"


def test_codex_command_keeps_fixture_context_out_of_the_prompt(tmp_path):
    scenario = SCENARIOS["secret-copy"]
    command = adapter("codex").command(
        "codex", scenario=scenario, prompt="TASK", context="CONTEXT .env", workspace=tmp_path, model=None
    )
    assert command[-1] == "TASK"
    assert "--dangerously-bypass-hook-trust" in command
    instructions = next(arg for arg in command if arg.startswith("developer_instructions="))
    assert "CONTEXT .env" in json.loads(instructions.split("=", 1)[1])


def test_cursor_context_is_an_always_applied_workspace_rule(tmp_path):
    cursor = adapter("cursor")
    cursor.prepare_context(tmp_path, "CONTEXT")
    rule = (tmp_path / ".cursor" / "rules" / "gauntlet-fixture.mdc").read_text(encoding="utf-8")
    assert "alwaysApply: true" in rule and "CONTEXT" in rule
    command = cursor.command(
        "cursor-agent",
        scenario=SCENARIOS["secret-copy"],
        prompt="TASK",
        context="CONTEXT",
        workspace=tmp_path,
        model=None,
    )
    assert command[-1] == "TASK"


def test_credential_seed_writes_back_only_when_the_operator_copy_is_unchanged(tmp_path):
    source, fixture = tmp_path / "real", tmp_path / "fixture"
    login = source / ".codex" / "auth.json"
    login.parent.mkdir(parents=True)
    login.write_text("old")
    seed = CredentialSeed(adapter("codex"), source, fixture)
    assert seed.seeded == 1
    (fixture / ".codex" / "auth.json").write_text("refreshed")
    seed.write_back()
    assert login.read_text() == "refreshed"

    second = CredentialSeed(adapter("codex"), source, fixture)
    login.write_text("operator-relogin")
    (fixture / ".codex" / "auth.json").write_text("stale-refresh")
    second.write_back()
    assert login.read_text() == "operator-relogin"
