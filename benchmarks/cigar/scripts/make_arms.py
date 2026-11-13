"""Write the four arms: Codex base/cigar and Claude Code clbase/clcigar.

Run with the rig venv's python after cigar_setup.py:
    HOME=$W/ghome $W/gvenv/bin/python -I make_arms.py <work dir>
The CIGAR arms carry only Guard's prompt hook (the note), copied with its trust hash from the rig
Guard home, so the arms differ in the note and nothing else. No login is copied here; batch.sh adds
the Codex login for a run and cleanup.sh removes it.
"""

import json
import re
import shlex
import sys
from pathlib import Path

work = Path(sys.argv[1]).resolve()
home = work / "ghome"
guard = home / ".hol-guard"
arms = work / "arms"
BASE = """model = "gpt-6-luna"
model_reasoning_effort = "medium"
approval_policy = "never"
sandbox_mode = "workspace-write"

[sandbox_workspace_write]
network_access = false

[features]
{hooks}plugins = false
apps = false
remote_plugin = false
plugin_discovery_prefetch = false
"""

source = (home / ".codex" / "config.toml").read_text()
line = next(l for l in source.splitlines() if l.startswith("UserPromptSubmit = "))
state = re.search(r'\[hooks\.state\."[^"]*:user_prompt_submit:0:0"\]\ntrusted_hash = "([^"]+)"', source)
assert state, "no trusted prompt hook in the rig Guard home; rerun cigar_setup.py"
for arm in ("base", "cigar"):
    codex_home = arms / arm / "codex_home"
    codex_home.mkdir(parents=True, exist_ok=True)
    # An empty HOME keeps the user's shell startup files and tool configs out of the session.
    (arms / arm / "home").mkdir(exist_ok=True)
    text = BASE.format(hooks="hooks = true\n" if arm == "cigar" else "")
    if arm == "cigar":
        key = f"{codex_home / 'config.toml'}:user_prompt_submit:0:0"
        text += f'\n[hooks]\n{line}\n\n[hooks.state."{key}"]\ntrusted_hash = "{state[1]}"\n'
    (codex_home / "config.toml").write_text(text)

from codex_plugin_scanner.guard.adapters import claude_code  # noqa: E402
from codex_plugin_scanner.guard.adapters.base import HarnessContext  # noqa: E402

port = json.loads((guard / "daemon-state.json").read_text()).get("port") or 0
claude_code.load_guard_daemon_url = lambda _guard_home: f"http://127.0.0.1:{port}"
ctx = HarnessContext(home_dir=home, workspace_dir=None, guard_home=guard, home_override_explicit=True)
parts = claude_code.ClaudeCodeHarnessAdapter._daemon_hook_command_parts(ctx)
settings = {
    "sandbox": {"enabled": True, "autoAllowBashIfSandboxed": True, "allowUnsandboxedCommands": False},
    "permissions": {"defaultMode": "bypassPermissions", "deny": ["WebFetch", "WebSearch"]},
}
for arm in ("clbase", "clcigar"):
    where = arms / arm
    where.mkdir(parents=True, exist_ok=True)
    (where / "harness").write_text("claude-code\n")
    s = dict(settings)
    if arm == "clcigar":
        s["hooks"] = {
            "UserPromptSubmit": [{"hooks": [{"type": "command", "command": shlex.join(parts), "timeout": 30}]}]
        }
    (where / "claude_settings.json").write_text(json.dumps(s, indent=2) + "\n")
print("arms written:", ", ".join(sorted(p.name for p in arms.iterdir())))
