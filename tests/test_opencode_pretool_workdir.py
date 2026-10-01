from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.opencode_pretool import pretool_plugin_source
from codex_plugin_scanner.guard.cli.commands_support_workspace import _workspace_from_hook_payload
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_opencode_pretool import _bun_executable, _ctx


@pytest.mark.parametrize(
    ("directory", "workdir", "expected"),
    [
        ("/project", None, "/project"),
        ("/project", "/project/subfolder", "/project/subfolder"),
        ("/project", "../other", "/other"),
        ("/project", " spaced folder ", "/project/ spaced folder "),
        ("/project", "", "/project"),
        ("/project", 13, None),
        ("/project trailing ", None, "/project trailing "),
        ("/project trailing ", "child", "/project trailing /child"),
        ("", None, "."),
        ("/project", "~", "@home"),
        ("/project", "~/child", "@home/child"),
        ("/project", "~//child", "@home/child"),
        ("/project", "~other", "/project/~other"),
        ("/project", "/mnt/c/workspace", "/mnt/c/workspace"),
        ("/project", "/cygdrive/d/workspace", "/cygdrive/d/workspace"),
        ("/project", "/c:/workspace", "/c:/workspace"),
        ("/project", "/c/workspace", "/c/workspace"),
        ("/project", "None", "/project/None"),
    ],
)
@pytest.mark.parametrize("exit_code", [0, 1, 2])
def test_v2_shell_reviews_its_effective_workdir(
    tmp_path: Path, directory: str, workdir: object, expected: str | None, exit_code: int
) -> None:
    bun = _bun_executable()
    if bun is None:
        pytest.skip("bun not installed")
    source = pretool_plugin_source(_ctx(tmp_path)).replace(
        "return spawnGuardProcess({", "return globalThis.guardTestSpawn({"
    )
    (tmp_path / "plugin.ts").write_text(source, encoding="utf-8")
    args: dict[str, object] = {"command": "pwd"}
    if workdir is not None:
        args["workdir"] = workdir
    script = tmp_path / "runner.ts"
    script.write_text(
        "import plugin from './plugin';\n"
        "import { resolve } from 'node:path';\n"
        "import { homedir } from 'node:os';\n"
        "let handler; let calls = 0; let reviewed;\n"
        "globalThis.guardTestSpawn = async (options) => {\n"
        "  const argv = JSON.parse(options.env.HOL_GUARD_HOOK_ARGV);\n"
        "  const directory = argv[argv.indexOf('--workspace') + 1];\n"
        "  calls++; reviewed = { directory, payload: JSON.parse(options.stdin) };\n"
        f"  return {{ exitCode: {exit_code}, stdout: '', stderr: 'rejected' }};\n"
        "};\n"
        f"await plugin.setup({{ location: {{ directory: {json.dumps(directory)} }}, tool: {{\n"
        "  async hook(name, callback) { handler = callback; }\n"
        "} });\n"
        "let blocked = false; let errorMessage = '';\n"
        f"try {{ await handler({{ tool: 'shell', input: {json.dumps(args)} }}); }}\n"
        "catch (error) { blocked = true; errorMessage = error.message; }\n"
        f"if (blocked !== {str(expected is None or exit_code != 0).lower()})\n"
        "  throw new Error('Guard decision changed');\n"
        f"if (calls !== {int(expected is not None)}) throw new Error('wrong review count');\n"
        f"let expectedPath = {json.dumps(expected)};\n"
        "if (expectedPath?.startsWith('@home')) expectedPath = homedir() + expectedPath.slice(5);\n"
        "if (process.platform === 'win32' && expectedPath !== null) {\n"
        "  const aliases = { '/mnt/c/workspace': 'C:/workspace',\n"
        "    '/cygdrive/d/workspace': 'D:/workspace', '/c:/workspace': 'C:/workspace',\n"
        "    '/c/workspace': 'C:/workspace' };\n"
        "  expectedPath = aliases[expectedPath] ?? expectedPath;\n"
        "}\n"
        "let expected = expectedPath;\n"
        f"if (expected !== null && {str(workdir is not None or not directory).lower()})\n"
        "  expected = resolve(expected);\n"
        f"const project = {json.dumps(directory)} || process.cwd();\n"
        "if (expected !== null && (reviewed.directory !== project ||\n"
        "    reviewed.payload.workspace_root !== project || reviewed.payload.cwd !== expected ||\n"
        "    reviewed.payload.tool_input.workdir !== expected || reviewed.payload.tool_input.command !== 'pwd'))\n"
        "  throw new Error('wrong effective working directory: ' + JSON.stringify(reviewed));\n"
        "if (expected === null && (!errorMessage.includes('workdir must be a string') ||\n"
        "    errorMessage.includes('install opencode'))) throw new Error('misleading validation error');\n"
        "console.log(JSON.stringify({ reviewed }));\n",
        encoding="utf-8",
    )
    completed = subprocess.run([bun, str(script)], capture_output=True, text=True, timeout=15, check=False)
    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    if expected is not None:
        reviewed = result["reviewed"]
        policy_workspace = _workspace_from_hook_payload(reviewed["payload"], Path(reviewed["directory"]))
        assert policy_workspace == Path(reviewed["payload"]["workspace_root"]).resolve()
        # The real launcher passes --workspace; also exercise the payload-only fallback
        # where legacy whitespace normalization does not change the project path.
        if reviewed["directory"] == reviewed["directory"].strip():
            assert _workspace_from_hook_payload(reviewed["payload"]) == policy_workspace
        assert (
            policy_workspace != Path(reviewed["payload"]["cwd"]).resolve()
            or reviewed["payload"]["cwd"] == reviewed["payload"]["workspace_root"]
        )
        store = GuardStore(tmp_path / "policy-guard")
        store.upsert_policy(
            PolicyDecision(harness="opencode", scope="workspace", action="block", workspace=str(policy_workspace)),
            datetime.now(timezone.utc).isoformat(),
        )
        decision = store.resolve_policy_decision("opencode", None, workspace=str(policy_workspace))
        assert decision is not None
        assert decision["action"] == "block"
