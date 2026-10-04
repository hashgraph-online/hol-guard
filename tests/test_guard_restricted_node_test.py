"""Real OS containment for ordinary Node tests and unsafe test effects."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.runtime.restricted_node_test import (
    prepare_restricted_node_test,
    run_restricted_node_test,
)
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import RestrictedPytestError


def test_mutable_shell_entrypoint_is_not_a_node_runtime(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    impostor = tmp_path / "node"
    impostor.write_text("#!/bin/sh\necho not-node\n", encoding="utf-8")
    impostor.chmod(0o755)
    with pytest.raises(RestrictedPytestError):
        prepare_restricted_node_test(
            [str(impostor), "--test"], workspace=tmp_path, platform="darwin", backend_executable=Path("/usr/bin/true")
        )


@pytest.mark.parametrize("output,code", [(b"1\n2\n3\n", 0), (b"bad\n", 0), (b"1\n", 1)])
def test_desktop_process_budget_accounts_for_existing_processes(
    monkeypatch: pytest.MonkeyPatch, output: bytes, code: int
) -> None:
    from codex_plugin_scanner.guard.runtime import restricted_pytest_sandbox as sandbox

    monkeypatch.setattr(sandbox.sys, "platform", "darwin")

    def measure(argv, **kwargs):
        assert argv == ["/bin/ps", "-U", str(sandbox.os.getuid()), "-o", "pid="]
        kwargs["stdout"].write(output)
        return SimpleNamespace(returncode=code)

    monkeypatch.setattr(sandbox.subprocess, "run", measure)
    if code == 0 and output.startswith(b"1\n2"):
        assert sandbox._current_user_process_ceiling() == 3 + sandbox._DEFAULT_PROCESSES
    else:
        with pytest.raises(RestrictedPytestError):
            sandbox._current_user_process_ceiling()


@pytest.mark.parametrize("output", [b"8\n30\n3\n", b"0\n", b"bad\n"])
def test_linux_process_budget_counts_existing_threads(monkeypatch: pytest.MonkeyPatch, output: bytes) -> None:
    from codex_plugin_scanner.guard.runtime import restricted_pytest_sandbox as sandbox

    monkeypatch.setattr(sandbox.sys, "platform", "linux")

    def measure(argv, **kwargs):
        assert argv[-1] == "nlwp="
        kwargs["stdout"].write(output)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(sandbox.subprocess, "run", measure)
    if output.startswith(b"8"):
        assert sandbox._current_user_process_ceiling() == 41 + sandbox._DEFAULT_PROCESSES
    else:
        with pytest.raises(RestrictedPytestError):
            sandbox._current_user_process_ceiling()


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
