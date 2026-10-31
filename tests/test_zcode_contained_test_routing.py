"""Harnesses that apply updatedInput must rewrite native containment receipts, never allow the original runner.

The resident writes the request snapshot and quotes the sink command; its
snapshot location, permissions, size bound and stale-snapshot cleanup are
pinned by the Rust tests beside ``hook_decision_containment_rewrite``. These
tests replay the adapter end to end against the session's resident.
"""

import hashlib
import shlex
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import _build_parser, _resolve_legacy_args
from codex_plugin_scanner.guard.runtime.contained_test_hook import read_contained_test_request
from tests import containment_rewrite_client as client
from tests.containment_rewrite_client import ContainmentRewrite, route_zcode_containment

_VITEST_RECEIPT = {
    "decision": "deny",
    "policy_action": "sandbox-required",
    "reason_code": "native_vitest_readonly_containment_required",
    "required_execution_profile": "vitest-readonly-v1",
}


def _route(receipt, payload, tmp_path, *, harness="zcode", workspace=None):
    return route_zcode_containment(
        receipt,
        harness=harness,
        payload=payload,
        guard_home=tmp_path / "guard",
        home_dir=tmp_path,
        workspace=tmp_path if workspace is None else workspace,
    )


def _argv(result) -> list[str]:
    return shlex.split(result["hookSpecificOutput"]["updatedInput"]["command"])


def _request_file(argv: list[str]) -> Path:
    return Path(argv[argv.index("--request-file") + 1])


def _discard(argv: list[str]) -> None:
    request = _request_file(argv)
    request.unlink()
    request.parent.rmdir()


@pytest.mark.parametrize(
    ("harness", "keys"),
    [
        ("zcode", ("hookEventName", "toolName", "toolInput")),
        ("claude-code", ("hook_event_name", "tool_name", "tool_input")),
    ],
)
def test_routes_multifile_vitest_to_authenticated_sink(containment_resident, tmp_path, monkeypatch, harness, keys):
    monkeypatch.setattr(sys, "platform", "darwin")
    event_key, tool_key, input_key = keys
    payload = {
        event_key: "PreToolUse",
        tool_key: "Bash",
        "cwd": str(tmp_path),
        input_key: {"command": "bunx vitest run __tests__/one.test.ts __tests__/two.test.ts", "timeout": 120000},
    }
    result = _route(_VITEST_RECEIPT, payload, tmp_path, harness=harness)
    assert result["reason_code"] == "native_contained_execution_routed"
    updated = result["hookSpecificOutput"]["updatedInput"]
    assert updated["timeout"] == 120000
    argv = _argv(result)
    try:
        assert "execute-contained-test" in argv
        assert argv[argv.index("--harness") + 1] == harness
        assert argv[argv.index("--guard-home") + 1] == str(tmp_path / "guard")
        assert argv[argv.index("--home") + 1] == str(tmp_path)
        request = _request_file(argv)
        digest = argv[argv.index("--request-sha256") + 1]
        assert request.parent.stat().st_mode & 0o777 == 0o700
        assert request.stat().st_mode & 0o777 == 0o600
        assert hashlib.sha256(request.read_bytes()).hexdigest() == digest
        snapshot = read_contained_test_request(request, digest, workspace=tmp_path)
        assert snapshot["tool_input"] == payload[input_key]
    finally:
        _discard(argv)


@pytest.mark.parametrize(
    "change",
    [
        {"decision": "allow"},
        {"policy_action": "review"},
        {"observe_mode": True},
        {"required_execution_profile": "wrong"},
        {"reason_code": "native_destructive_command"},
    ],
)
def test_zcode_does_not_rewrite_unproven_or_denied_requests(containment_resident, tmp_path, monkeypatch, change):
    monkeypatch.setattr(sys, "platform", "darwin")
    receipt = {**_VITEST_RECEIPT, **change}
    payload = {"hookEventName": "PreToolUse", "toolName": "Bash", "cwd": str(tmp_path), "toolInput": {"command": "x"}}
    assert _route(receipt, payload, tmp_path) is receipt


@pytest.mark.parametrize("harness", ["cursor", "omp", ""])
def test_harnesses_without_updated_input_are_never_rewritten(containment_resident, tmp_path, monkeypatch, harness):
    monkeypatch.setattr(sys, "platform", "darwin")
    payload = {"hookEventName": "PreToolUse", "toolName": "Bash", "cwd": str(tmp_path), "toolInput": {"command": "x"}}
    assert _route(_VITEST_RECEIPT, payload, tmp_path, harness=harness) is _VITEST_RECEIPT


def test_execution_sink_receives_original_containment_receipt(containment_resident, tmp_path):
    result = _route(_VITEST_RECEIPT, {"guard_containment_receipt_only": True}, tmp_path)
    assert result is _VITEST_RECEIPT
    assert result["decision"] == "deny"


def test_without_a_workspace_the_receipt_stands_unasked(monkeypatch, tmp_path):
    def unexpected(*args, **kwargs):
        raise AssertionError("no snapshot can be written without a workspace")

    monkeypatch.setattr(client, "native_containment_rewrite", unexpected)
    assert (
        route_zcode_containment(
            _VITEST_RECEIPT, harness="zcode", payload={}, guard_home=tmp_path, home_dir=tmp_path, workspace=None
        )
        is _VITEST_RECEIPT
    )


@pytest.fixture
def routing_inputs(containment_resident, tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    return {
        "hookEventName": "PreToolUse",
        "toolName": "Bash",
        "cwd": str(tmp_path),
        "toolInput": {"command": "bunx vitest run tests/example.test.ts"},
    }


@pytest.mark.parametrize(
    "change",
    [
        {"hookEventName": "PostToolUse"},
        {"toolName": "Read"},
        {"toolInput": []},
        {"toolInput": {"command": 12}},
        {"toolInput": {"command": "x" * 1_048_577}},
    ],
)
def test_invalid_inputs_keep_the_receipt(routing_inputs, tmp_path, change):
    assert _route(_VITEST_RECEIPT, {**routing_inputs, **change}, tmp_path) is _VITEST_RECEIPT


def test_workspace_must_be_a_directory(routing_inputs, tmp_path):
    file = tmp_path / "ordinary.txt"
    file.write_text("ordinary")
    assert _route(_VITEST_RECEIPT, routing_inputs, tmp_path, workspace=file) is _VITEST_RECEIPT
    assert _route(_VITEST_RECEIPT, routing_inputs, tmp_path, workspace=tmp_path / "missing") is _VITEST_RECEIPT


def test_frozen_routing_preserves_home_and_workspace_arguments(routing_inputs, monkeypatch, tmp_path):
    from codex_plugin_scanner.guard import stable_guard_cli

    routing_inputs.pop("cwd")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(stable_guard_cli, "resolve_frozen_guard_cli", lambda: "guard-test-cli")
    argv = _argv(_route(_VITEST_RECEIPT, routing_inputs, tmp_path))
    try:
        assert argv[0] == "guard-test-cli"
        assert argv[argv.index("--home") + 1] == str(tmp_path)
        assert argv[argv.index("--workspace") + 1] == str(tmp_path.resolve())
        # The Desktop launcher runs as `hol-guard`; the rewritten command must parse there.
        parsed = _build_parser("hol-guard", program_mode="hol-guard").parse_args(
            _resolve_legacy_args(argv[1:], program_mode="hol-guard")
        )
        assert parsed.guard_command == "execute-contained-test"
    finally:
        _discard(argv)


@pytest.mark.parametrize("routed", [None, {"policy_action": "allow"}])
def test_authority_edge_returns_routed_response_or_original(monkeypatch, tmp_path, routed):
    from codex_plugin_scanner.guard.adapters import zcode_contained_tests as adapter

    original = {"decision": "deny"}

    def rewrite(response, **kwargs):
        assert response is original
        assert kwargs["workspace"] == tmp_path
        assert kwargs["bridge"] is False
        assert tuple(kwargs["sink_command"]) == adapter.contained_sink_command_prefix()
        return ContainmentRewrite("vitest-readonly-v1", None, routed)

    monkeypatch.setattr(client, "native_containment_rewrite", rewrite)
    assert route_zcode_containment(
        original, harness="zcode", payload={}, guard_home=tmp_path, home_dir=tmp_path, workspace=tmp_path
    ) is (original if routed is None else routed)


@pytest.mark.parametrize(
    ("reason", "profile", "routed"),
    [
        ("native_workspace_containment_required", "workspace-contained-v1", True),
        ("native_vitest_readonly_containment_required", "vitest-readonly-v1", False),
    ],
)
def test_linux_routes_only_the_workspace_sandbox(containment_resident, tmp_path, monkeypatch, reason, profile, routed):
    monkeypatch.setattr(sys, "platform", "linux")
    receipt = {
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": reason,
        "required_execution_profile": profile,
    }
    payload = {
        "hookEventName": "PreToolUse",
        "toolName": "Bash",
        "cwd": str(tmp_path),
        "toolInput": {"command": "python3 todo.py list > out.txt"},
    }
    result = _route(receipt, payload, tmp_path)
    assert (result is not receipt) is routed
    if routed:
        _discard(_argv(result))


def test_windows_sink_bootstrap_has_no_escaped_backslashes(tmp_path, monkeypatch):
    """Git Bash halves doubled backslashes, so the bootstrap must not need them."""
    from codex_plugin_scanner.guard.adapters import zcode_contained_tests as adapter

    package_root = tmp_path / "site\\packages"
    package_root.mkdir(parents=True)
    config = {"python_executable": sys.executable, "package_root": str(package_root)}
    monkeypatch.setattr(sys, "platform", "darwin")
    unchanged = adapter._sink_command_prefix(config)
    assert repr(str(package_root.resolve())) in unchanged[-1]
    monkeypatch.setattr(sys, "platform", "win32")
    windows = adapter._sink_command_prefix(config)
    assert windows[:-1] == unchanged[:-1]
    assert "\\" not in windows[-1]
    assert repr(str(package_root.resolve()).replace("\\", "/")) in windows[-1]
