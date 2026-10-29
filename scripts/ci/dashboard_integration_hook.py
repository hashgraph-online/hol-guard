"""Ask the integration daemon what it decides for one Claude Code Bash call.

Usage: dashboard_integration_hook.py GUARD_HOME WORKSPACE COMMAND

The request goes through the daemon's Claude hook route with the same identity
challenge a hook bridge uses, and only the decisions and the reason code are
printed, as one JSON object. Specs use it to check that a choice saved in the
dashboard is the one Guard enforces.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import urllib.parse
import uuid
from pathlib import Path
from types import ModuleType

_SCRIPTS = Path(__file__).resolve().parents[1]


def _load_script(name: str, module_name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(module_name, _SCRIPTS / f"{name}.py")
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def main() -> None:
    guard_home, workspace, command = sys.argv[1:4]
    if "scripts.daemon_hook_auth" not in sys.modules:
        _load_script("daemon_hook_auth", "scripts.daemon_hook_auth")
    client = _load_script("daemon_hook_client", "dashboard_integration_hook_client")
    body = {
        "hook_event_name": "PreToolUse",
        "session_id": f"dashboard-e2e-{uuid.uuid4().hex}",
        "tool_use_id": f"toolu_{uuid.uuid4().hex}",
        "cwd": workspace,
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }
    text = client.authenticated_claude_hook_response(
        state_path=Path(guard_home) / "daemon-state.json",
        query=urllib.parse.urlencode({"home": guard_home, "workspace": workspace}),
        data=json.dumps(body),
        timeout_seconds=30,
    )
    response = json.loads(text)
    specific = response.get("hookSpecificOutput")
    permission = specific.get("permissionDecision") if isinstance(specific, dict) else None
    print(
        json.dumps(
            {
                "permission_decision": permission,
                "decision": response.get("decision"),
                "reason_code": response.get("reason_code"),
            }
        )
    )


if __name__ == "__main__":
    main()
