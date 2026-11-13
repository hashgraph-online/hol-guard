"""Write the full-Guard arms: Codex `gfull` and Claude Code `clgfull`.

Run with the rig venv's python after cigar_setup.py and make_arms.py:
    HOME=$W/ghome $W/gvenv/bin/python -I make_full_arms.py <work dir>
These arms carry every Guard hook (tool checks, permission requests, the CIGAR note), the way a user
who installed Guard runs, so they measure CIGAR with Guard's safety checks on. Hooks are installed
only into the rig's own homes under <work dir>; the user's ~/.codex, ~/.claude and ~/.hol-guard are
never touched. No login is copied here; batch.sh adds the Codex login for a run.
"""

import json
import re
import sys
from pathlib import Path

work = Path(sys.argv[1]).resolve()
home = work / "ghome"
guard = home / ".hol-guard"
arms = work / "arms"
assert Path.home().resolve() == home, "run with HOME=<work>/ghome"

# Codex: copy every Guard hook and its trust hash from the rig home, re-keyed to the arm's config.
source = (home / ".codex" / "config.toml").read_text()
hooks = [
    l for l in source.splitlines() if re.match(r"(PreToolUse|PermissionRequest|UserPromptSubmit|PostToolUse) = ", l)
]
assert len(hooks) == 4, "rig home lacks the four Codex hooks; rerun cigar_setup.py"
base_config = (arms / "base" / "codex_home" / "config.toml").read_text()
codex_home = arms / "gfull" / "codex_home"
codex_home.mkdir(parents=True, exist_ok=True)
(arms / "gfull" / "home").mkdir(exist_ok=True)
text = base_config.replace("[features]\n", "[features]\nhooks = true\n", 1) + "\n[hooks]\n" + "\n".join(hooks) + "\n"
for event in ("pre_tool_use", "permission_request", "user_prompt_submit", "post_tool_use"):
    state = re.search(rf'\[hooks\.state\."[^"]*:{event}:0:0"\]\ntrusted_hash = "([^"]+)"', source)
    assert state, f"no trusted {event} hook in the rig home"
    text += f'\n[hooks.state."{codex_home / "config.toml"}:{event}:0:0"]\ntrusted_hash = "{state[1]}"\n'
(codex_home / "config.toml").write_text(text)

# Claude Code: let Guard install its hooks into the rig home, then carry them into the arm settings.
# The hooks must name the daemon's own HOME: the daemon rejects any other home as an unexpected
# root and then reviews every call with no working directory, which holds git reads and pytest.
from codex_plugin_scanner.guard.adapters.base import HarnessContext  # noqa: E402
from codex_plugin_scanner.guard.adapters.claude_code import ClaudeCodeHarnessAdapter  # noqa: E402

ctx = HarnessContext(home_dir=home, workspace_dir=None, guard_home=guard, home_override_explicit=True)
ClaudeCodeHarnessAdapter().install(ctx)
installed = json.loads((home / ".claude" / "settings.json").read_text())
assert installed.get("hooks", {}).get("PreToolUse"), "Guard did not install a PreToolUse hook"
settings = json.loads((arms / "clbase" / "claude_settings.json").read_text())
settings["hooks"] = installed["hooks"]
# Guard rewrites test runs into its runtime, which runs them in its own sandbox. Inside Claude Code's
# sandbox that runtime can neither start its sandbox nor reach the daemon, so every pytest fails with
# contained_run_authorization_failed. The runtime still contains the command it runs.
runtime = installed["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
assert runtime.endswith("hol-guard-runtime"), "unexpected Guard hook command"
settings.setdefault("sandbox", {})["excludedCommands"] = [f"{runtime}:*"]
where = arms / "clgfull"
where.mkdir(parents=True, exist_ok=True)
(where / "harness").write_text("claude-code\n")
(where / "claude_settings.json").write_text(json.dumps(settings, indent=2) + "\n")
print("full arms written: gfull (", len(hooks), "hooks ), clgfull (", ", ".join(sorted(installed["hooks"])), ")")
