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
