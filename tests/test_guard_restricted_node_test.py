"""Real OS containment for ordinary Node tests and unsafe test effects."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.restricted_node_test import (
    _node_runtime_args,
    prepare_restricted_node_test,
    run_restricted_node_test,
)
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import RestrictedPytestError


@pytest.mark.usefixtures("native_context_digest")
def test_mutable_shell_entrypoint_is_not_a_node_runtime(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    impostor = tmp_path / "node"
    impostor.write_text("#!/bin/sh\necho not-node\n", encoding="utf-8")
    impostor.chmod(0o755)
    with pytest.raises(RestrictedPytestError):
        prepare_restricted_node_test(
            [str(impostor), "--test"], workspace=tmp_path, platform="darwin", backend_executable=Path("/usr/bin/true")
        )


@pytest.mark.parametrize("platform,value", [("darwin", 67), ("linux", 105)])
def test_native_process_budget_is_presented_without_python_measurement(monkeypatch, platform, value):
    from codex_plugin_scanner.guard import native_restricted_pytest as transport
    from codex_plugin_scanner.guard.runtime import restricted_pytest_sandbox as sandbox

    monkeypatch.setattr(sandbox.sys, "platform", platform)
    calls = []

    def call(action, **kwargs):
        calls.append(action)
        return {"value": value}

    monkeypatch.setattr(transport, "_call", call)
    assert sandbox._current_user_process_ceiling() == value
    assert calls[0]["body"]["operation"] == "process_ceiling"


@pytest.mark.parametrize(
    "response",
    [
        None,
        {"value": True},
        {"value": "105"},
        {"reason_code": "pytest_restricted_sandbox_unavailable", "message": "Process measurement unavailable."},
    ],
)
def test_unavailable_process_budget_cannot_start_execution(monkeypatch, response):
    from codex_plugin_scanner.guard import native_restricted_pytest as transport
    from codex_plugin_scanner.guard.runtime import restricted_pytest_sandbox as sandbox

    monkeypatch.setattr(sandbox.sys, "platform", "linux")
    monkeypatch.setattr(transport, "_call", lambda *a, **k: response)
    with pytest.raises(RestrictedPytestError):
        sandbox._current_user_process_ceiling()


@pytest.mark.usefixtures("native_context_digest")
@pytest.mark.parametrize(
    "argv",
    [
        ["node", "--eval", "1+1"],
        ["node", "script.js"],
        ["node", "--test", ";", "sh"],
        ["sh", "--test"],
        ["node", "--test-other"],
        ["node", "--test", "&&", "rm"],
    ],
)
def test_non_test_and_shell_forms_are_not_delegated(argv: list[str], tmp_path: Path) -> None:
    with pytest.raises(RestrictedPytestError):
        prepare_restricted_node_test(argv, workspace=tmp_path)


@pytest.mark.usefixtures("native_context_digest")
def test_bounded_heap_option_is_preserved_for_direct_node_test() -> None:
    assert _node_runtime_args(["node", "--max-old-space-size=12288", "--test"]) == ("--max-old-space-size=12288",)
    with pytest.raises(RestrictedPytestError):
        _node_runtime_args(["node", "--max-old-space-size=999999", "--test"])


@pytest.mark.usefixtures("native_context_digest")
@pytest.mark.skipif(sys.platform != "darwin" or shutil.which("node") is None, reason="requires Node and Seatbelt")
def test_actual_node_runner_preserves_cwd_and_denies_sensitive_effects(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"type":"module"}', encoding="utf-8")
    source = tmp_path / "test.mjs"
    secret = tmp_path / ".env"
    secret.write_text("synthetic-only", encoding="utf-8")
    victim = tmp_path / "keep.txt"
    victim.write_text("keep", encoding="utf-8")
    (tmp_path / "alias.txt").symlink_to(secret)
    source.write_text(
        """
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

test('ordinary source reads and private writes', () => {
  assert.match(fs.readFileSync('test.mjs', 'utf8'), /ordinary source reads/);
  const output = path.join(os.tmpdir(), 'node-fixture.txt');
  fs.writeFileSync(output, 'test data');
  assert.equal(fs.readFileSync(output, 'utf8'), 'test data');
});
test('credentials and destructive effects denied', () => {
  const denied = error => ['EACCES', 'EPERM'].includes(error.code);
  assert.throws(() => fs.readFileSync('.env'), denied);
  assert.throws(() => fs.readFileSync('alias.txt'), denied);
  assert.throws(() => fs.unlinkSync('keep.txt'), denied);
  assert.throws(() => fs.writeFileSync('test.mjs', 'bad'), denied);
  assert.throws(() => execFileSync('/bin/cat', ['keep.txt']));
  assert.equal(process.env.SYNTHETIC_SECRET_TOKEN, undefined);
  assert.equal(process.env.NODE_OPTIONS, undefined);
});
""".lstrip(),
        encoding="utf-8",
    )
    result = run_restricted_node_test(
        ["node", "--test", "test.mjs"],
        workspace=tmp_path,
        cwd=tmp_path,
        env={"SYNTHETIC_SECRET_TOKEN": "not-a-real-token", "NODE_OPTIONS": "--require /not/a/real/preload.js"},
        timeout_seconds=60,
    )
    assert result == 0
    assert secret.read_text() == "synthetic-only"
    assert victim.read_text() == "keep"
    assert "ordinary source reads" in source.read_text()
    assert prepare_restricted_node_test(["node", "--test", "test.mjs"], workspace=tmp_path).to_evidence()["writes"] == [
        "private-temporary-directory"
    ]
