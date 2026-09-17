"""Real Linux backend tests. Run only in the provisioned containment CI job."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.containment_execution_support import containment_positive_proof
from codex_plugin_scanner.guard.daemon.manager import current_guard_daemon_runtime_fingerprint
from codex_plugin_scanner.guard.runtime.containment_contract import ContainmentPolicy, ContainmentRequest
from codex_plugin_scanner.guard.runtime.containment_executor import execute_contained, file_sha256
from codex_plugin_scanner.guard.runtime.containment_health import probe_containment_health
from codex_plugin_scanner.guard.runtime.effect_contract import ProofRoute
from codex_plugin_scanner.guard.runtime.local_node_runner_evidence import build_local_node_runner_evidence
from codex_plugin_scanner.guard.runtime.package_intent_parser import parse_package_intent
from codex_plugin_scanner.guard.runtime.workspace_snapshot_inputs import complete_workspace_snapshot


def _request(workspace: Path, argv: tuple[str, ...], *, include_inputs: bool = False) -> ContainmentRequest:
    digest, inputs = complete_workspace_snapshot(workspace, exclude_protected=True) if include_inputs else ("empty", ())
    return ContainmentRequest(
        argv=argv,
        cwd=str(workspace),
        environment=(),
        policy=ContainmentPolicy(str(workspace), ()),
        inputs=inputs,
        launch_digest=hashlib.sha256(f"linux-integration:{digest}:{argv}".encode()).hexdigest(),
        executable_digest=file_sha256(argv[0]),
        operation_id="integration-test",
    )


@pytest.mark.parametrize("status", (0, 1, 17))
def test_real_backend_preserves_child_exit_status(tmp_path: Path, status: int) -> None:
    request = _request(tmp_path.resolve(), (str(Path("/bin/sh").resolve()), "-c", f"exit {status}"))
    result = execute_contained(request)
    assert result.enforced, result.stderr
    assert result.exit_code == status
    assert result.attestation.failure is None


def test_exec_failure_cannot_mint_an_enforcement_attestation(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid-executable"
    # A missing shebang interpreter is a true exec startup failure. Plain text
    # without a shebang is intentionally eligible for POSIX /bin/sh fallback
    # and therefore is not evidence that containment failed to start.
    invalid.write_bytes(b"#!/definitely/missing/guard-interpreter\n")
    invalid.chmod(0o500)
    result = execute_contained(_request(tmp_path.resolve(), (str(invalid),)))
    assert not result.enforced
    assert result.exit_code is None
    assert result.attestation.failure is not None


def test_real_vitest_cannot_read_credentials_write_host_or_use_host_network(tmp_path: Path) -> None:
    fixture = Path(os.environ["GUARD_VITEST_FIXTURE"]).resolve(strict=True)
    workspace = tmp_path / "workspace"
    shutil.copytree(fixture, workspace, symlinks=True)
    (workspace / ".env").write_text("GUARD_CANARY=synthetic-secret-sentinel\n", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("synthetic-secret-sentinel", encoding="utf-8")
    host_marker = tmp_path / "must-not-exist.txt"
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(0.2)
    port = listener.getsockname()[1]
    script = """import { test, expect } from 'vitest';
import fs from 'node:fs';
import net from 'node:net';
test('contained runtime boundaries', async () => {
  const value: number = 7;
  expect(value).toBe(7);
  for (const path of ['.env', OUTSIDE]) {
    expect(() => fs.readFileSync(path, 'utf8')).toThrow();
  }
  expect(() => fs.writeFileSync(HOST_MARKER, 'escaped')).toThrow();
  fs.writeFileSync('ephemeral-result.txt', 'snapshot only');
  await new Promise<void>((resolve, reject) => {
    const socket = net.connect({host: '127.0.0.1', port: HOST_PORT});
    socket.setTimeout(1000);
    socket.on('connect', () => { socket.destroy(); reject(new Error('host network exposed')); });
    socket.on('error', () => { socket.destroy(); resolve(); });
    socket.on('timeout', () => { socket.destroy(); resolve(); });
  });
});
"""
    script = (
        script.replace("OUTSIDE", json.dumps(str(outside)))
        .replace("HOST_MARKER", json.dumps(str(host_marker)))
        .replace("HOST_PORT", str(port))
    )
    (workspace / "boundary.test.ts").write_text(script, encoding="utf-8")
    args = ("--no-install", "vitest", "run", "boundary.test.ts", "--reporter=dot")
    intent = parse_package_intent("npx " + " ".join(args), workspace=workspace)
    assert intent is not None and len(intent.local_executions) == 1
    evidence = build_local_node_runner_evidence("npx", args, intent.local_executions[0], workspace=workspace)
    assert evidence is not None and evidence.status == "complete"
    node = str(Path(shutil.which("node") or "node").resolve(strict=True))
    request = _request(
        workspace.resolve(),
        (node, "node_modules/vitest/vitest.mjs", *evidence.runner_args),
        include_inputs=True,
    )
    fingerprint = current_guard_daemon_runtime_fingerprint()
    health = probe_containment_health(daemon_fingerprint=fingerprint)
    assert health.probe_enforced, health.to_dict()
    try:
        result = execute_contained(request, timeout_seconds=90)
        assert result.enforced, result.stderr
        assert result.exit_code == 0, result.stdout + result.stderr
        proof = containment_positive_proof(result, request, health, fingerprint)
        assert proof.route is ProofRoute.CONTAINED and proof.enforced
        assert "synthetic-secret-sentinel" not in result.stdout + result.stderr
        assert not host_marker.exists()
        assert not (workspace / "ephemeral-result.txt").exists()
        assert outside.read_text(encoding="utf-8") == "synthetic-secret-sentinel"
        with pytest.raises(TimeoutError):
            connection, _ = listener.accept()
            connection.close()
    finally:
        listener.close()
