"""ZCode must rewrite native containment receipts, never allow the original runner."""

import hashlib
import json
import os
import shlex
import sys
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.zcode_contained_tests import (
    cleanup_stale_zcode_requests,
    contained_zcode_response,
    route_zcode_containment,
)
from codex_plugin_scanner.guard.runtime.contained_test_hook import read_contained_test_request


def test_zcode_routes_multifile_vitest_to_authenticated_sink(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    payload = {
        "hookEventName": "PreToolUse",
        "toolName": "Bash",
        "cwd": str(tmp_path),
        "toolInput": {"command": "bunx vitest run __tests__/one.test.ts __tests__/two.test.ts", "timeout": 120000},
    }
    config = {
        "harness": "zcode",
        "python_executable": sys.executable,
        "package_root": str(tmp_path),
        "guard_home": str(tmp_path / "guard"),
    }
    receipt = {
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": "native_vitest_readonly_containment_required",
        "required_execution_profile": "vitest-readonly-v1",
    }
    result = contained_zcode_response(receipt, input_text=json.dumps(payload), config=config, cli_args=[])
    assert result is not None
    updated = result["hookSpecificOutput"]["updatedInput"]
    assert updated["timeout"] == 120000
    argv = shlex.split(updated["command"])
    assert "execute-contained-test" in argv
    assert argv[argv.index("--harness") + 1] == "zcode"
    request = Path(argv[argv.index("--request-file") + 1])
    digest = argv[argv.index("--request-sha256") + 1]
    try:
        assert request.parent.stat().st_mode & 0o777 == 0o700
        assert request.stat().st_mode & 0o777 == 0o600
        assert hashlib.sha256(request.read_bytes()).hexdigest() == digest
        snapshot = read_contained_test_request(request, digest, workspace=tmp_path)
        assert snapshot["tool_input"] == payload["toolInput"]
    finally:
        request.unlink()
        request.parent.rmdir()


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
def test_zcode_does_not_rewrite_unproven_or_denied_requests(tmp_path, monkeypatch, change):
    monkeypatch.setattr(sys, "platform", "darwin")
    receipt = {
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": "native_vitest_readonly_containment_required",
        "required_execution_profile": "vitest-readonly-v1",
        **change,
    }
    assert contained_zcode_response(receipt, input_text="{}", config={"harness": "zcode"}, cli_args=[]) is None


def test_execution_sink_receives_original_containment_receipt(tmp_path):
    receipt = {
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": "native_vitest_readonly_containment_required",
        "required_execution_profile": "vitest-readonly-v1",
    }
    result = route_zcode_containment(
        receipt,
        harness="zcode",
        payload={"guard_containment_receipt_only": True},
        guard_home=tmp_path / "guard",
        home_dir=tmp_path,
        workspace=tmp_path,
    )
    assert result is receipt
    assert result["decision"] == "deny"


@pytest.mark.skipif(os.name != "posix", reason="ZCode containment snapshots use POSIX private files")
def test_stale_snapshot_cleanup_preserves_fresh_requests_and_symlinks(tmp_path, monkeypatch):
    import tempfile

    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    old = time.time() - 90_000
    stale = Path(tempfile.mkdtemp(prefix="hol-guard-contained-test-", dir=tmp_path))
    fresh = Path(tempfile.mkdtemp(prefix="hol-guard-contained-test-", dir=tmp_path))
    linked = Path(tempfile.mkdtemp(prefix="hol-guard-contained-test-", dir=tmp_path))
    for directory in (stale, fresh):
        request = directory / "request.json"
        descriptor = os.open(request, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
    protected = tmp_path / "protected.txt"
    protected.write_text("keep")
    (linked / "request.json").symlink_to(protected)
    (tmp_path / "hol-guard-contained-test-linked-dir").symlink_to(stale, target_is_directory=True)
    os.utime(stale / "request.json", (old, old))
    os.utime(stale, (old, old))
    os.utime(linked, (old, old))
    cleanup_stale_zcode_requests()
    assert not stale.exists()
    assert (fresh / "request.json").exists()
    assert (linked / "request.json").is_symlink()
    assert protected.read_text() == "keep"


@pytest.fixture
def routing_inputs(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    # All adapter snapshots in these tests are isolated from the real temp root.
    import tempfile

    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))
    return (
        {
            "decision": "deny",
            "policy_action": "sandbox-required",
            "reason_code": "native_vitest_readonly_containment_required",
            "required_execution_profile": "vitest-readonly-v1",
        },
        {
            "hookEventName": "PreToolUse",
            "toolName": "Bash",
            "cwd": str(tmp_path),
            "toolInput": {"command": "bunx vitest run tests/example.test.ts"},
        },
        {
            "harness": "zcode",
            "guard_home": str(tmp_path / "guard"),
            "python_executable": sys.executable,
            "package_root": str(tmp_path),
        },
    )


@pytest.mark.parametrize(
    "change",
    [
        {"hookEventName": "PostToolUse"},
        {"toolName": "Read"},
        {"toolInput": []},
        {"toolInput": {"command": 12}},
        {"cwd": None},
        {"toolInput": {"command": "x" * 1_048_577}},
    ],
)
def test_invalid_inputs_never_create_a_snapshot(routing_inputs, tmp_path, change):
    receipt, payload, config = routing_inputs
    assert (
        contained_zcode_response(receipt, input_text=json.dumps({**payload, **change}), config=config, cli_args=[])
        is None
    )
    assert not list(tmp_path.glob("hol-guard-contained-test-*"))


@pytest.mark.parametrize("text", ["[]", "invalid-json"])
def test_invalid_json_never_routes(routing_inputs, text):
    receipt, _, config = routing_inputs
    assert contained_zcode_response(receipt, input_text=text, config=config, cli_args=[]) is None


def test_workspace_must_be_a_directory(routing_inputs, tmp_path):
    receipt, payload, config = routing_inputs
    file = tmp_path / "ordinary.txt"
    file.write_text("ordinary")
    assert (
        contained_zcode_response(
            receipt, input_text=json.dumps({**payload, "cwd": str(file)}), config=config, cli_args=[]
        )
        is None
    )


def test_frozen_routing_preserves_home_and_workspace_arguments(routing_inputs, monkeypatch, tmp_path):
    from codex_plugin_scanner.guard import stable_guard_cli

    receipt, payload, config = routing_inputs
    payload.pop("cwd")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(stable_guard_cli, "resolve_frozen_guard_cli", lambda: "guard-test-cli")
    response = contained_zcode_response(
        receipt,
        input_text=json.dumps(payload),
        config=config,
        cli_args=["--workspace", str(tmp_path), "--home", str(tmp_path)],
    )
    argv = shlex.split(response["hookSpecificOutput"]["updatedInput"]["command"])
    assert argv[0] == "guard-test-cli"
    assert argv[argv.index("--home") + 1] == str(tmp_path)
    assert argv[argv.index("--workspace") + 1] == str(tmp_path)


@pytest.mark.parametrize("failure", ["launch", "cleanup"])
def test_failed_routing_cleans_its_snapshot_best_effort(routing_inputs, monkeypatch, tmp_path, failure):
    from codex_plugin_scanner.guard.adapters import zcode_contained_tests as adapter

    receipt, payload, config = routing_inputs

    def fail(*args, **kwargs):
        raise OSError("synthetic failure")

    monkeypatch.setattr(adapter, "isolated_guard_cli_command", fail)
    if failure == "cleanup":
        monkeypatch.setattr(Path, "unlink", fail)
    assert contained_zcode_response(receipt, input_text=json.dumps(payload), config=config, cli_args=[]) is None
    if failure == "launch":
        assert not list(tmp_path.glob("hol-guard-contained-test-*"))


@pytest.mark.parametrize("routed", [None, {"policy_action": "allow"}])
def test_authority_edge_returns_routed_response_or_original(monkeypatch, tmp_path, routed):
    from codex_plugin_scanner.guard.adapters import zcode_contained_tests as adapter

    original = {"decision": "deny"}

    def route(response, **kwargs):
        assert response is original
        assert json.loads(kwargs["input_text"])["cwd"] == str(tmp_path)
        return routed

    monkeypatch.setattr(adapter, "contained_zcode_response", route)
    assert route_zcode_containment(
        original, harness="zcode", payload={}, guard_home=tmp_path, home_dir=tmp_path, workspace=tmp_path
    ) is (original if routed is None else routed)


def test_cleanup_failure_does_not_interrupt_routing(monkeypatch):
    from codex_plugin_scanner.guard.adapters import zcode_contained_tests as adapter

    def fail(*args, **kwargs):
        raise OSError("temp directory unavailable")

    monkeypatch.setattr(adapter.os, "scandir", fail)
    cleanup_stale_zcode_requests()
