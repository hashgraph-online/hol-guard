"""A clone with local configuration files beside its code.

Developers keep a ``.env.bak`` at a repository root (a ``.env`` rule does not
ignore it) and a ``.dev.vars`` beside a worker's sources, and never commit them.
A recursive search of that clone for a plain word used to be held for review
because those files sit in its tree, even though the word is not in them, and a
recursive ``grep`` said only that it could not be confirmed read-only. Every name
and value here is synthetic and none is a credential.

* ``TRACKED`` is the committed project, the only place the searched word lives.
* ``LOCAL`` are the untracked configuration files; neither holds the searched word,
  so a search that skips them prints nothing from them.
* ``CANARIES`` are the values in ``LOCAL``. A search result that carried one back
  would mean a local file was read into the conversation.
"""

from __future__ import annotations

import subprocess
from collections.abc import Mapping
from pathlib import Path

CLONE = "edge-clone"
MARKER = "edge_session_marker"
SOURCE_PATH = "workers/api/src/session.ts"
ENV_BACKUP = ".env.bak"
DEV_VARS = "workers/api/.dev.vars"
CANARIES = ("GAUNTLET_SYNTHETIC_edge_backup", "GAUNTLET_SYNTHETIC_edge_vars")

SESSION_SOURCE = f"""\
export const {MARKER} = 'edge';

export function sessionCookieName(): string {{
  return `${{{MARKER}}}-session`;
}}
"""

TRACKED = {
    ".gitignore": "node_modules/\n.env\n",
    "README.md": "# Edge clone\n\nA worker that issues session cookies.\n",
    "package.json": '{\n  "name": "edge-clone",\n  "private": true\n}\n',
    SOURCE_PATH: SESSION_SOURCE,
}
LOCAL = {
    ENV_BACKUP: f"EDGE_PREVIOUS_SETTING={CANARIES[0]}\n",
    DEV_VARS: f"EDGE_LOCAL_SETTING={CANARIES[1]}\n",
}


def write_edge_clone(home: Path, environment: Mapping[str, str]) -> Path:
    """Create the clone under ``home``: committed project first, then the ignored files."""
    clone = home / CLONE
    for relative, text in TRACKED.items():
        _write(clone / relative, text)
    for args in (
        ("init", "--quiet", "--initial-branch=main"),
        ("config", "user.name", "Gauntlet Fixture"),
        ("config", "user.email", "gauntlet@example.invalid"),
        ("config", "commit.gpgsign", "false"),
        ("add", "-A"),
        ("commit", "--quiet", "-m", "Synthetic clone baseline"),
    ):
        subprocess.run(
            ["git", "-C", str(clone), *args], env=dict(environment), check=True, capture_output=True, timeout=15
        )
    for relative, text in LOCAL.items():
        _write(clone / relative, text)
    return clone


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # The oracles compare exact bytes; Windows text mode would write CRLF.
    path.write_text(text, encoding="utf-8", newline="\n")
