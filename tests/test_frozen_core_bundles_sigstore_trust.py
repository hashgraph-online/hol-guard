"""Every frozen Guard core must carry sigstore's embedded trust roots.

sigstore reads them with ``resources.files("sigstore._store")``, a string
PyInstaller cannot follow, so a freeze that omits them can never verify a
catalog publication (``No module named 'sigstore._store'``).
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUARD_FREEZE = "--collect-submodules codex_plugin_scanner --collect-data codex_plugin_scanner"
SIGSTORE_TRUST = "--hidden-import sigstore._store --collect-data sigstore"


def _freeze_commands() -> dict[str, list[str]]:
    tracked = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout.split("\0")
    commands: dict[str, list[str]] = {}
    for name in tracked:
        if not name or not name.endswith((".yml", ".yaml", ".sh", ".ps1")):
            continue
        text = (ROOT / name).read_text(encoding="utf-8")
        if GUARD_FREEZE not in text:
            continue
        # A freeze command is one logical line continued with `\` or a PowerShell backtick.
        joined = re.sub(r"\s*[\\`]\n\s*", " ", text)
        commands[name] = [line for line in joined.splitlines() if GUARD_FREEZE in line]
    return commands


def test_every_guard_freeze_carries_sigstore_trust_roots() -> None:
    commands = _freeze_commands()
    assert commands, "no PyInstaller freeze of the Guard core was found"
    missing = [name for name, lines in commands.items() for line in lines if SIGSTORE_TRUST not in line]
    assert missing == []
