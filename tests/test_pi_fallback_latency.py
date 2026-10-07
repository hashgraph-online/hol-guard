from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.manager import GUARD_DAEMON_COMPATIBILITY_VERSION
from tests.test_pi_hook_latency import _bun_executable, _decode_json_object

pytestmark = pytest.mark.usefixtures("approval_questionnaire_mode")


@pytest.mark.skipif(_bun_executable() is None, reason="Bun is required to execute the managed Pi extension")
def test_pi_extension_treats_authenticated_daemon_overload_as_terminal(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source

    bun = _bun_executable()
    assert bun is not None
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    _ = (guard_home / "daemon-state.json").write_text(
        json.dumps({"compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION, "port": 1, "state_id": "test"}),
        encoding="utf-8",
    )
    _ = (guard_home / "daemon-auth-token").write_text("test-token", encoding="utf-8")
    extension_path = tmp_path / "hol-guard.ts"
    compiled_path = tmp_path / "hol-guard.mjs"
    harness_path = tmp_path / "load.mjs"
    _ = extension_path.write_text(
        managed_extension_source(
            guard_home=guard_home,
            home_dir=tmp_path,
            settings_path=tmp_path / "settings.json",
        ),
        encoding="utf-8",
    )
    _ = subprocess.run(
        [
            bun,
            "build",
            str(extension_path),
            "--target=bun",
            "--format=esm",
            f"--outfile={compiled_path}",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    _ = harness_path.write_text(
        f"""
import installGuard from {json.dumps(str(compiled_path))};
let fetchCount = 0;
globalThis.fetch = async (url) => {{
  if (String(url).includes('/readiness')) return Response.json({{ready: true}});
  fetchCount += 1;
  return new Response(
    JSON.stringify({{ error: "daemon_hook_capacity" }}),
    {{ status: 503, headers: {{ "Content-Type": "application/json" }} }},
  );
}};
const handlers = new Map();
installGuard({{ on: (event, handler) => handlers.set(event, handler), sendMessage: () => {{}} }});
const handler = handlers.get("tool_call");
const notices = [];
const sessionManager = {{getSessionId: () => "test-session", getCwd: () => {json.dumps(str(tmp_path))}}};
await handlers.get("session_start")({{}}, {{sessionManager, ui: {{notify() {{}}}}}});
const results = await Promise.all(Array.from({{ length: 20 }}, (_, index) => handler(
  {{ toolCallId: `call-${{index}}`, toolName: "read", input: {{ path: "README.md" }} }},
  {{ cwd: {json.dumps(str(tmp_path))}, sessionManager,
     ui: {{ notify: (reason) => notices.push(reason) }} }},
)));
console.log(JSON.stringify({{
  fetchCount,
  blocked: results.filter((result) => result?.block === true).length,
  overloadReasons: notices.filter((reason) => reason.includes("daemon_hook_capacity")).length,
}}));
""",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [bun, str(harness_path)],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    )
    payload = _decode_json_object(completed.stdout)

    assert payload == {"fetchCount": 20, "blocked": 20, "overloadReasons": 20}


@pytest.mark.skipif(
    _bun_executable() is None or os.name != "posix",
    reason="Bun and POSIX process groups are required for fallback termination testing",
)
def test_pi_extension_allows_only_one_cli_fallback_during_daemon_outage(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source

    bun = _bun_executable()
    assert bun is not None
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    _ = (guard_home / "daemon-state.json").write_text(
        json.dumps({"compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION, "port": 1, "state_id": "test"}),
        encoding="utf-8",
    )
    _ = (guard_home / "daemon-auth-token").write_text("test-token", encoding="utf-8")
    extension_path = tmp_path / "hol-guard.ts"
    compiled_path = tmp_path / "hol-guard.mjs"
    harness_path = tmp_path / "load.mjs"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fallback_count_path = tmp_path / "fallback-count"
    fake_cli = fake_bin / "plugin-guard"
    _ = fake_cli.write_text(
        (
            '#!/bin/sh\ntrap "" TERM\nprintf "1\\n" >> "$FALLBACK_COUNT_PATH"\n'
            'sleep 5\nprintf \'{"decision":"allow"}\\n\'\n'
        ),
        encoding="utf-8",
    )
    _ = fake_cli.chmod(0o755)
    source = managed_extension_source(
        guard_home=guard_home,
        home_dir=tmp_path,
        settings_path=tmp_path / "settings.json",
    )
    false_command = shutil.which("false")
    assert false_command is not None
    source = re.sub(
        r"const GUARD_DAEMON_RECOVERY_COMMAND = .*?;",
        f"const GUARD_DAEMON_RECOVERY_COMMAND = {json.dumps(false_command)};",
        source,
        count=1,
    )
    source = re.sub(
        r"const GUARD_CLI_WRAPPER_COMMAND = .*?;",
        f"const GUARD_CLI_WRAPPER_COMMAND = {json.dumps(str(fake_cli))};",
        source,
        count=1,
    )
    source = source.replace(
        source[
            source.index("const GUARD_CLI_WRAPPER_ARGS = ") : source.index(
                ";\n", source.index("const GUARD_CLI_WRAPPER_ARGS = ")
            )
            + 2
        ],
        "const GUARD_CLI_WRAPPER_ARGS = [];\n",
    )
    assert f"const GUARD_DAEMON_RECOVERY_COMMAND = {json.dumps(false_command)};" in source
    _ = extension_path.write_text(source, encoding="utf-8")
    _ = subprocess.run(
        [
            bun,
            "build",
            str(extension_path),
            "--target=bun",
            "--format=esm",
            f"--outfile={compiled_path}",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    _ = harness_path.write_text(
        f"""
import installGuard from {json.dumps(str(compiled_path))};
globalThis.fetch = async (url) => {{
  if (String(url).includes('/readiness')) return Response.json({{ready: true}});
  throw new Error("daemon unavailable");
}};
const handlers = new Map();
installGuard({{ on: (event, handler) => handlers.set(event, handler), sendMessage: () => {{}} }});
const handler = handlers.get("tool_call");
const notices = [];
const sessionManager = {{getSessionId: () => "test-session", getCwd: () => {json.dumps(str(tmp_path))}}};
await handlers.get("session_start")({{}}, {{sessionManager, ui: {{notify() {{}}}}}});
const startedAt = performance.now();
const results = await Promise.all(Array.from({{ length: 20 }}, (_, index) => handler(
  {{ toolCallId: `call-${{index}}`, toolName: "read", input: {{ path: "README.md" }} }},
  {{ cwd: {json.dumps(str(tmp_path))}, sessionManager,
     ui: {{ notify: (reason) => notices.push(reason) }} }},
)));
console.log(JSON.stringify({{
  elapsedMs: performance.now() - startedAt,
  allowed: results.filter((result) => result === undefined).length,
  blocked: results.filter((result) => result?.block === true).length,
  recoveryBusy: notices.filter((reason) => reason.includes("recovery is already reviewing")).length,
  recoveryTimeout: notices.filter((reason) => reason.includes("could not complete fallback review")).length,
}}));
""",
        encoding="utf-8",
    )
    completed = subprocess.run(
        [bun, str(harness_path)],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
        env={
            **os.environ,
            "FALLBACK_COUNT_PATH": str(fallback_count_path),
            "PATH": f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}",
        },
    )
    payload = _decode_json_object(completed.stdout)

    assert fallback_count_path.read_text(encoding="utf-8").splitlines() == ["1"]
    assert payload["allowed"] == 0
    assert payload["blocked"] == 20
    assert payload["recoveryBusy"] == 19
    assert payload["recoveryTimeout"] == 1
    elapsed_ms = payload["elapsedMs"]
    assert isinstance(elapsed_ms, (int, float))
    assert elapsed_ms < 2_000
