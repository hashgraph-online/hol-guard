"""The OpenCode plugin starts the native bounded hook bridge when the runtime offers it."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.bounded_cli_hook_native import NATIVE_BOUNDED_HOOK_FEATURE
from codex_plugin_scanner.guard.adapters.opencode_pretool import pretool_plugin_source

pytestmark = pytest.mark.skipif(os.name != "posix", reason="the native bounded bridge is POSIX-only")


def _bun() -> str:
    path = os.pathsep.join(
        entry for entry in os.environ.get("PATH", "").split(os.pathsep) if "package-shims" not in entry
    )
    found = shutil.which("bun", path=path) or shutil.which("bun")
    if found is None:
        pytest.skip("bun not installed")
    return found


def _offer_native(monkeypatch: pytest.MonkeyPatch, runtime: Path) -> None:
    from codex_plugin_scanner.guard import native_runtime
    from codex_plugin_scanner.guard.native_runtime import (
        NativeRuntimeCapabilities,
        NativeRuntimeIdentity,
        NativeRuntimeStatus,
    )

    status = NativeRuntimeStatus(
        mode="auto",
        available=True,
        compatible=True,
        reason="ok",
        identity=NativeRuntimeIdentity(path=runtime, size=1, mtime_ns=1, sha256="0" * 64),
        capabilities=NativeRuntimeCapabilities(
            protocol_version=1,
            runtime_version="0",
            rule_digest="0" * 64,
            build_sha="0" * 40,
            target="test",
            features=(NATIVE_BOUNDED_HOOK_FEATURE,),
        ),
    )
    monkeypatch.delenv("HOL_GUARD_BOUNDED_HOOK_BRIDGE", raising=False)
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda *, deadline_monotonic=None: status)


def _context(tmp_path: Path) -> HarnessContext:
    return HarnessContext(home_dir=tmp_path / "home", workspace_dir=None, guard_home=tmp_path / "guard-home")


def _fake_runtime(tmp_path: Path) -> Path:
    runtime = tmp_path / "hol-guard-runtime"
    runtime.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$@\" > {tmp_path / 'argv.txt'}\n"
        f"cat > {tmp_path / 'stdin.txt'}\n"
        'printf \'{"decision":"allow"}\\n\'\n',
        encoding="utf-8",
    )
    runtime.chmod(0o755)
    return runtime


def _run_plugin(tmp_path: Path, source: str, body: str) -> subprocess.CompletedProcess[str]:
    (tmp_path / "plugin.ts").write_text(source, encoding="utf-8")
    runner = tmp_path / "runner.ts"
    runner.write_text(body, encoding="utf-8")
    return subprocess.run([_bun(), str(runner)], capture_output=True, text=True, check=False, timeout=20)


def test_plugin_runs_the_native_bridge_with_the_workspace_argv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = _fake_runtime(tmp_path)
    _offer_native(monkeypatch, runtime)
    source = pretool_plugin_source(_context(tmp_path))
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    completed = _run_plugin(
        tmp_path,
        source,
        "import { HolGuardPretoolPlugin } from './plugin';\n"
        f"const hooks = await HolGuardPretoolPlugin({{ directory: {json.dumps(str(workspace))} }});\n"
        'await hooks["tool.execute.before"]({ tool: "bash" }, { args: { command: "ls" } });\n'
        'console.log("allowed");\n',
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "allowed"
    argv = (tmp_path / "argv.txt").read_text(encoding="utf-8").splitlines()
    assert argv[0] == "bounded-hook-bridge"
    assert argv[2:4] == ["-I", "-c"]
    assert "bounded_cli_hook_bridge" in argv[4]
    config = json.loads(argv[5])
    assert config["harness"] == "opencode"
    assert config["python_executable"] == argv[1]
    assert Path(argv[1]).resolve() == Path(argv[1])
    assert config["cli_args"][:2] == ["guard", "hook"]
    assert config["cli_args"][config["cli_args"].index("--workspace") + 1] == str(workspace)
    assert config["timeout_seconds"] == 25
    payload = json.loads((tmp_path / "stdin.txt").read_text(encoding="utf-8"))
    assert payload["tool_input"]["command"] == "ls"


def test_plugin_keeps_the_python_launcher_without_the_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = _fake_runtime(tmp_path)
    _offer_native(monkeypatch, runtime)
    source = pretool_plugin_source(_context(tmp_path))
    runtime.unlink()

    completed = _run_plugin(
        tmp_path,
        source,
        "import { resolveGuardNativeRuntime } from './plugin';\nconsole.log(String(resolveGuardNativeRuntime()));\n",
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "null"


def test_non_executable_runtime_keeps_the_python_launcher(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = _fake_runtime(tmp_path)
    runtime.chmod(0o644)
    _offer_native(monkeypatch, runtime)
    source = pretool_plugin_source(_context(tmp_path))

    completed = _run_plugin(
        tmp_path,
        source,
        "import { resolveGuardNativeRuntime } from './plugin';\nconsole.log(String(resolveGuardNativeRuntime()));\n",
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "null"
    assert "accessSync" in source
    assert "fsConstants.X_OK" in source


def test_unrunnable_native_runtime_falls_back_to_python(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    runtime = tmp_path / "hol-guard-runtime"
    runtime.write_text("#!/no/such/hol-guard-interpreter\n", encoding="utf-8")
    runtime.chmod(0o755)
    _offer_native(monkeypatch, runtime)
    source = pretool_plugin_source(_context(tmp_path))
    resolved = _run_plugin(
        tmp_path,
        source,
        "import { resolveGuardNativeRuntime } from './plugin';\nconsole.log(String(resolveGuardNativeRuntime()));\n",
    )
    assert resolved.returncode == 0, resolved.stderr
    assert resolved.stdout.strip() == str(runtime.resolve())

    completed = _run_plugin(
        tmp_path,
        source,
        "import { spawnGuardProcess } from './plugin';\n"
        "const result = await spawnGuardProcess({\n"
        '  args: ["-c", "import sys; sys.stdout.write(\'python-fallback\')"],\n'
        "  nativeArgs: (pythonTarget) => ['bounded-hook-bridge', pythonTarget],\n"
        f"  cwd: {json.dumps(str(tmp_path))},\n"
        "  deadlineMs: Date.now() + 10000,\n"
        "  env: { PATH: process.env.PATH ?? '' },\n"
        "  stdin: '',\n"
        "});\n"
        "console.log(JSON.stringify({ exitCode: result.exitCode, stdout: result.stdout }));\n",
    )

    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {"exitCode": 0, "stdout": "python-fallback"}
    assert "nodeSpawn(command, args, spawnOptions)" in source


def test_python_bridge_pin_installs_no_native_bridge(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _offer_native(monkeypatch, _fake_runtime(tmp_path))
    monkeypatch.setenv("HOL_GUARD_BOUNDED_HOOK_BRIDGE", "python")

    source = pretool_plugin_source(_context(tmp_path))

    assert "} | null = null;" in source
