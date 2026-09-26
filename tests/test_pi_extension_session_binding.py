"""Run the generated tool-call boundary, not a hand-built hook payload."""

import json
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source


@pytest.mark.parametrize("harness", ("pi", "omp"))
def test_generated_pre_tool_payload_binds_sdk_session(tmp_path: Path, harness: str) -> None:
    source = managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path / "home",
        settings_path=tmp_path / "settings.json",
        harness=harness,
        display_name="fixture",
    )
    start = source.index('pi.on("tool_call", async (event, ctx) => {')
    # Execute the actual payload-construction slice; downstream delivery is covered separately.
    end = source.index("    if (", start)
    fragment = source[start:end] + "\n});"
    for field in ("input", "toolInput", "arguments"):
        fragment = fragment.replace(f"(event as {{ {field}?: Record<string, unknown> }}).{field}", f"event.{field}")
    javascript = (
        """
const GUARD_CONFIG_PATH = '/fixture/settings.json';
let handler;
let captured;
const pi = { on: (_, callback) => { handler = callback; } };
async function runGuard(payload) { captured = payload; return {}; }
"""
        + fragment
        + """
await handler({ toolCallId: 'call-one', toolName: 'read', input: {path: 'src/example.py'} },
  {cwd: '/fixture', sessionManager: { getSessionId: () => 'session-one' }});
console.log(JSON.stringify(captured));
"""
    )
    result = subprocess.run(
        ["node", "--input-type=module", "-e", javascript],
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(result.stdout)
    assert payload["session_id"] == "session-one"
    assert payload["tool_call_id"] == "call-one"
    assert payload["tool_input"] == {"path": "src/example.py"}
