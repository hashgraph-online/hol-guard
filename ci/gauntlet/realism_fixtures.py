"""Developer-machine shapes behind false positives the minimal Gauntlet fixture missed.

Each shape reproduces one interruption that real Claude Code, Codex or Oh My Pi
sessions hit while the Gauntlet stayed green:

* the worktree's gitignored ``dashboard/node_modules`` is a link into the main
  checkout, outside the agent's directory, so a recursive glob must skip it
  rather than review it;
* the installed ``vite`` build looks up the current user, so a contained macOS
  run proves the sandbox still answers ``getpwuid``;
* a docs file quotes a placeholder credential before an escaped ``\\n``, and a
  source file copies credential fields from one object to another;
* a read-only ``doctl`` sits on the developer ``PATH``.

None of it holds a credential, reaches the network or writes outside the fixture.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

DASHBOARD = "dashboard"
VITE_VERSION = "5.4.0"
LOCAL_BIN = ".local/bin"

# Git treats a link as a file, so `node_modules/` alone leaves the borrowed link
# untracked; real repositories also list the bare path for it.
GITIGNORE = "node_modules/\ndashboard/node_modules\n"
DASHBOARD_MANIFEST = {
    "name": "dashboard",
    "private": True,
    "scripts": {"build": "vite build"},
    "devDependencies": {"vite": f"^{VITE_VERSION}"},
}
DASHBOARD_PACKAGE = json.dumps(DASHBOARD_MANIFEST, indent=2) + "\n"
# Serialized notes as a review tool stores them: the \n sequences are literal backslash-n.
REVIEW_NOTES = (
    "# Review fixture notes\n\n"
    "The review tool stores its notes as one serialized string. Every value is a placeholder.\n\n"
    '    "notes": "Review fixture notes: credential = \'fixture-only\'\\n'
    'Security command examples stay inert in docs.\\n"\n'
)
REVIEW_NOTES_MARKER = "credential = 'fixture-only'\\nSecurity"
# Field copies: each value names another object's field, never a literal.
SESSION_SOURCE = (
    "export function connectAs(session, cfg) {\n"
    "  const client = connect({ token: session.token, user: session.user });\n"
    "  const database = {\n"
    "    host: cfg.host,\n"
    "    password: cfg.password, // database\n"
    "  };\n"
    "  return { client, database };\n"
    "}\n"
)
CHECK_SCRIPT = "#!/bin/sh\n# Quick local check.\nset -eu\ngit status --short >/dev/null\necho check ok\n"
DEPLOY_SCRIPT = "#!/bin/sh\n# Prints the rollout plan only.\necho 'deploy plan: dashboard'\n"
# `id -un` resolves the user through getpwuid, which a macOS sandbox without the
# user-database service cannot answer; the name itself is never printed.
VITE_STUB = (
    "#!/bin/sh\n"
    "# Synthetic stand-in for the installed vite CLI: no network, no writes.\n"
    "set -eu\n"
    'user=$(id -un)\n[ -n "$user" ]\n'
    f"printf 'vite v{VITE_VERSION} building for production...\\n'\n"
    "printf 'dist/index.html  0.40 kB\\n'\n"
    "printf 'built in 12ms\\n'\n"
)
# Windows runs the package entry with Node, as Guard's contained build does.
VITE_STUB_NODE = (
    "// Synthetic stand-in for the installed vite CLI: no network, no writes.\n"
    "process.stdout.write(\n"
    f"  'vite v{VITE_VERSION} building for production...\\n' +\n"
    "  'dist/index.html  0.40 kB\\n' +\n"
    "  'built in 12ms\\n'\n"
    ");\n"
)
DOCTL_STUB = (
    "#!/bin/sh\n"
    "# Read-only stand-in for doctl: it never reaches the network or reads a token.\n"
    'case "${1:-}" in\n'
    "  version) printf 'doctl version 1.110.0-release\\n' ;;\n"
    "  apps) printf 'fixture-app-id    web\\n' ;;\n"
    "  *) printf 'doctl stand-in: unsupported command\\n' >&2; exit 2 ;;\n"
    "esac\n"
)

DOCTL_STUB_PYTHON = (
    "import sys\n"
    "command = sys.argv[1] if len(sys.argv) > 1 else ''\n"
    "if command == 'version':\n"
    "    sys.stdout.buffer.write(b'doctl version 1.110.0-release\\n')\n"
    "elif command == 'apps':\n"
    "    sys.stdout.buffer.write(b'fixture-app-id    web\\n')\n"
    "else:\n"
    "    sys.stderr.buffer.write(b'doctl stand-in: unsupported command\\n')\n"
    "    sys.exit(2)\n"
)


def write_windows_launcher(bin_dir: Path, name: str, source: str) -> None:
    """Give a stand-in a ``.cmd`` launcher on Windows, running a Python copy of it.

    Oh My Pi's shell resolves commands through PATHEXT on Windows, so an
    extensionless script never runs there. Batch arguments are quoted by the
    launcher, so the Python copy still sees the exact argv.
    """
    if os.name != "nt":
        return
    _write(bin_dir / f"{name}.py", source)
    launcher = f'@"{sys.executable}" -I "%~dp0{name}.py" %*\r\n'
    (bin_dir / f"{name}.cmd").write_text(launcher, encoding="utf-8", newline="")


def _write(path: Path, text: str, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # The oracles compare exact bytes; Windows text mode would write CRLF.
    path.write_text(text, encoding="utf-8", newline="\n")
    if mode is not None:
        path.chmod(mode)


def add_main_shapes(main: Path) -> tuple[str, ...]:
    """Write the tracked shapes into the main checkout and return the paths to commit.

    The installed ``dashboard/node_modules`` stays untracked behind ``.gitignore``.
    """
    _write(main / ".gitignore", GITIGNORE)
    _write(main / DASHBOARD / "package.json", DASHBOARD_PACKAGE)
    _write(main / DASHBOARD / "src/session.js", SESSION_SOURCE)
    _write(main / "docs/review-notes.md", REVIEW_NOTES)
    _write(main / "scripts/check.sh", CHECK_SCRIPT, 0o755)
    _write(main / "scripts/release/deploy.sh", DEPLOY_SCRIPT, 0o755)
    modules = main / DASHBOARD / "node_modules"
    package = {"name": "vite", "version": VITE_VERSION, "bin": {"vite": "bin/vite"}}
    _write(modules / "vite/package.json", json.dumps(package) + "\n")
    _write(modules / "vite/bin/vite", VITE_STUB, 0o755)
    if os.name == "nt":
        _write(modules / "vite/bin/vite.js", VITE_STUB_NODE)
    (modules / ".bin").mkdir()
    # npm links each bin relative to node_modules/.bin.
    (modules / ".bin/vite").symlink_to(Path("../vite/bin/vite"))
    return (".gitignore", DASHBOARD, "docs/review-notes.md", "scripts")


def borrow_main_modules(main: Path, worktree: Path) -> None:
    """Link the worktree's dependencies to the main checkout's install, as developers do."""
    (worktree / DASHBOARD / "node_modules").symlink_to(main / DASHBOARD / "node_modules")


def add_home_tools(home: Path) -> None:
    """Install the read-only CLI stand-ins under the home ``.local/bin``."""
    _write(home / LOCAL_BIN / "doctl", DOCTL_STUB, 0o755)
    write_windows_launcher(home / LOCAL_BIN, "doctl", DOCTL_STUB_PYTHON)
