#!/usr/bin/env python3
"""Smoke-test the project Cursor hook script (used by CI/agents)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
HOOK_SCRIPT = REPO_ROOT / ".cursor" / "hooks" / "hol-guard-cursor-hook.py"


def main() -> int:
    if not HOOK_SCRIPT.is_file():
        print(f"missing hook script: {HOOK_SCRIPT}", file=sys.stderr)
        return 1
    payload = json.dumps({"hook_event_name": "beforeShellExecution", "command": "echo hol-guard-e2e"})
    completed = subprocess.run(
        [sys.executable, str(HOOK_SCRIPT)],
        input=payload,
        text=True,
        capture_output=True,
        cwd=REPO_ROOT,
        timeout=60,
        check=False,
    )
    if completed.returncode != 0:
        print(completed.stderr or completed.stdout, file=sys.stderr)
        return completed.returncode or 1
    response = json.loads(completed.stdout)
    permission = response.get("permission")
    print(json.dumps({"permission": permission, "hook": str(HOOK_SCRIPT)}))
    return 0 if permission == "allow" else 2


if __name__ == "__main__":
    raise SystemExit(main())
