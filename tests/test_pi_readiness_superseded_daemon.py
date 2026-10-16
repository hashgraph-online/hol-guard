"""Exercise generated readiness recovery when a superseded daemon cannot prepare policy."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source


def _readiness_outcome(tmp_path: Path, responses: list[dict[str, object]], recovers: bool) -> dict[str, object]:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required to execute the generated readiness helper")
    source = managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path,
        settings_path=tmp_path / "settings.json",
        harness="omp",
        display_name="fixture",
    )
    start = source.index("const GUARD_DAEMON_READINESS_TIMEOUT_MS")
    end = source.index("async function runGuard(", start)
    script = f"""
const GUARD_HOME = '/fixture/guard-home';
const GUARD_HOME_DIR = '/fixture';
const GUARD_HOME_DIR_IS_DEFAULT = true;
const GUARD_TEXT_LIMIT_CHARS = 65536;
async function boundedResponseText(response) {{ return await response.text(); }}
let connection = {{ stateId: 'old', port: 1, authToken: 'fixture' }};
function loadGuardDaemonConnection() {{ return connection; }}
const responses = {json.dumps(responses)};
let fetches = 0, recoveries = 0;
globalThis.fetch = async () => {{
  const next = responses[Math.min(fetches++, responses.length - 1)];
  return new Response(JSON.stringify(next.body), {{ status: next.status }});
}};
async function recoverGuardDaemon(timeoutMs, kind) {{
  recoveries++;
  if ({json.dumps(recovers)}) connection = {{ stateId: 'new', port: 2, authToken: 'fixture' }};
  return {json.dumps(recovers)} && kind === 'authenticated-control-plane-failure' && timeoutMs > 0;
}}
{source[start:end]}
const result = await daemonWorkspaceReadiness('/fixture/workspace', {{ deadlineAt: Date.now() + 5000 }});
console.log(JSON.stringify({{ result, fetches, recoveries }}));
"""
    harness_path = tmp_path / "readiness.ts"
    harness_path.write_text(script, encoding="utf-8")
    completed = subprocess.run(
        [node, "--experimental-strip-types", str(harness_path)],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    return json.loads(completed.stdout.strip().splitlines()[-1])


_NOT_READY = {"status": 503, "body": {"ready": False, "reason_code": "native_policy_not_ready"}}
_READY = {
    "status": 200,
    "body": {
        "ready": True,
        "native_required": True,
        "native_route": "native_resident",
        "workspace_acknowledged": True,
        "worker_ready": True,
    },
}


def test_superseded_daemon_recovers_once_and_readies_replacement(tmp_path: Path) -> None:
    outcome = _readiness_outcome(tmp_path, [_NOT_READY, _READY], recovers=True)
    assert outcome == {"result": {"ready": True, "daemonStateId": "new"}, "fetches": 2, "recoveries": 1}


def test_unready_replacement_fails_closed_without_recovery_loop(tmp_path: Path) -> None:
    outcome = _readiness_outcome(tmp_path, [_NOT_READY, _NOT_READY], recovers=True)
    assert outcome == {
        "result": {"ready": False, "reasonCode": "native_policy_not_ready", "daemonStateId": "new"},
        "fetches": 2,
        "recoveries": 1,
    }


def test_failed_recovery_keeps_native_policy_not_ready(tmp_path: Path) -> None:
    outcome = _readiness_outcome(tmp_path, [_NOT_READY], recovers=False)
    assert outcome == {
        "result": {"ready": False, "reasonCode": "native_policy_not_ready", "daemonStateId": "old"},
        "fetches": 1,
        "recoveries": 1,
    }


def test_other_unready_reasons_do_not_recover(tmp_path: Path) -> None:
    other = {"status": 503, "body": {"ready": False, "reason_code": "native_runtime_unavailable"}}
    outcome = _readiness_outcome(tmp_path, [other], recovers=True)
    assert outcome == {
        "result": {"ready": False, "reasonCode": "native_runtime_unavailable", "daemonStateId": "old"},
        "fetches": 1,
        "recoveries": 0,
    }
