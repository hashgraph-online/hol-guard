from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source
from codex_plugin_scanner.guard.daemon.hook_worker_responses import harness_json_from_native_prompt
from codex_plugin_scanner.guard.daemon.manager import GUARD_DAEMON_COMPATIBILITY_VERSION
from tests.test_pi_hook_latency import _bun_executable

NATIVE_PROMPT_ALLOW = {
    "policy_action": "warn",
    "reason_code": "native_policy_warning",
    "hookSpecificOutput": {"hookEventName": "UserPromptSubmit"},
}


@pytest.mark.skipif(_bun_executable() is None, reason="Bun is required for the managed extension")
@pytest.mark.parametrize("harness", ("pi", "omp"))
@pytest.mark.parametrize(
    ("response", "tool_call", "allowed", "fallback"),
    [
        (NATIVE_PROMPT_ALLOW, False, True, False),
        ({**NATIVE_PROMPT_ALLOW, "policy_action": "allow"}, False, True, False),
        (
            harness_json_from_native_prompt(
                "omp", {"decision": "allow", "minimum_action": "allow", "reason_code": "native_prompt_clean"}
            ),
            False,
            True,
            False,
        ),
        ({"decision": "deny", "reason": "protected prompt"}, False, False, False),
        ({"decision": "block", "reason": "protected prompt"}, False, False, False),
        (NATIVE_PROMPT_ALLOW, True, False, True),
        ({**NATIVE_PROMPT_ALLOW, "policy_action": "review"}, False, False, True),
        ({**NATIVE_PROMPT_ALLOW, "hookSpecificOutput": {"hookEventName": "PreToolUse"}}, False, False, True),
        ({**NATIVE_PROMPT_ALLOW, "decision": "ask"}, False, False, True),
        ({**NATIVE_PROMPT_ALLOW, "continue": False}, False, False, True),
        ({**NATIVE_PROMPT_ALLOW, "hookSpecificOutput": []}, False, False, True),
        ({**NATIVE_PROMPT_ALLOW, "reason_code": None}, False, False, True),
        ({**NATIVE_PROMPT_ALLOW, "risk_signals": "not an array"}, False, False, True),
    ],
)
def test_prompt_receipt_is_bound_to_the_input_event(
    tmp_path: Path, harness: str, response: dict, tool_call: bool, allowed: bool, fallback: bool
) -> None:
    bun = _bun_executable()
    assert bun is not None
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    (guard_home / "daemon-state.json").write_text(
        json.dumps({"compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION, "port": 1, "state_id": "test"})
    )
    (guard_home / "daemon-auth-token").write_text("test-token")
    marker = tmp_path / "fallback"
    cli = tmp_path / "guard-cli"
    cli.write_text(
        f"#!{sys.executable}\nfrom pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('called')\n"
        'print(\'{"decision":"deny","reason":"fallback denied"}\')\n'
    )
    cli.chmod(0o755)
    source = managed_extension_source(
        guard_home=guard_home, home_dir=tmp_path, settings_path=tmp_path / "settings.json", harness=harness
    )
    source = re.sub(
        r"const GUARD_CLI_WRAPPER_COMMAND = .*?;",
        f"const GUARD_CLI_WRAPPER_COMMAND = {json.dumps(str(cli))};",
        source,
        count=1,
    )
    extension = tmp_path / "guard.ts"
    extension.write_text(source)
    script = tmp_path / "input.ts"
    script.write_text(
        f"""
import installGuard from {json.dumps(str(extension))};
const handlers = new Map(); const notices = [];
globalThis.fetch = async (url) => Response.json(
  String(url).includes('/readiness') ? {{ready: true}} : {json.dumps(response)}
);
installGuard({{on(name, handler) {{handlers.set(name, handler);}}, sendMessage() {{}}}});
const cwd = {json.dumps(str(tmp_path))};
const ctx = {{cwd, sessionManager: {{getCwd: () => cwd, getSessionId: () => 'input-contract'}},
  ui: {{notify(message) {{notices.push(message);}}}}}};
const isTool = {json.dumps(tool_call)};
if (isTool) await handlers.get('session_start')({{}}, ctx);
const event = isTool ? {{toolCallId: 'test', toolName: 'read', input: {{path: 'README.md'}}}}
  : {{text: 'Read README.md.', source: 'interactive'}};
const first = await handlers.get(isTool ? 'tool_call' : 'input')(event, ctx);
const second = await handlers.get(isTool ? 'tool_call' : 'input')(event, ctx);
console.log(JSON.stringify({{first, second, notices}}));
"""
    )
    result = subprocess.run([bun, str(script)], capture_output=True, text=True, check=True, timeout=10)
    output = json.loads(result.stdout)
    for key in ("first", "second"):
        if tool_call:
            assert output[key]["block"] is True
        else:
            assert (output[key]["action"] == "continue") is allowed
    assert marker.exists() is fallback
    if allowed:
        assert output["notices"] == []
