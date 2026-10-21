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
* a read-only ``doctl`` sits on the developer ``PATH``;
* a read-only ``docker`` answers one registry manifest query.
* token-handling source (a redirect route, a link-building worker, an HMAC
  helper) names credential-like identifiers on every line (see
  ``source_output_fixtures``);
* the worktree carries the ``.venv`` an ordinary Python project is worked in,
  whose generated ``bin/activate`` a test run sources before it starts;
* a sign-in folder named ``auth`` holds a README and a session helper (see
  ``feature_directory_fixtures``).

None of it holds a credential, reaches the network or writes outside the fixture.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from .feature_directory_fixtures import CONSOLE
from .feature_directory_fixtures import SOURCES as FEATURE_SOURCES
from .source_output_fixtures import PORTAL, SOURCES

DASHBOARD = "dashboard"
VITE_VERSION = "5.4.0"
LOCAL_BIN = ".local/bin"

# Git treats a link as a file, so `node_modules/` alone leaves the borrowed link
# untracked; real repositories also list the bare path for it.
GITIGNORE = "node_modules/\ndashboard/node_modules\n.venv/\n"
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


VENV = ".venv"
def base_interpreter() -> Path:
    """The real interpreter a ``uv venv`` links its own ``bin/python`` to.

    A virtualenv is a directory of links and generated scripts around an
    installed interpreter; the stand-ins below only look like the ones a
    developer works in if they point at a real one.
    """
    base = getattr(sys, "_base_executable", None) or sys.executable
    return Path(base).resolve()


def pyvenv_cfg(base: Path) -> str:
    """The marker ``uv venv`` writes, naming the interpreter it was built from."""
    version = ".".join(str(part) for part in sys.version_info[:3])
    return (
        f"home = {base.parent}\n"
        "implementation = CPython\n"
        "uv = 0.9.26\n"
        f"version_info = {version}\n"
        "include-system-site-packages = false\n"
        "prompt = project-feature\n"
    )
# The script a virtualenv generates, in its own shape: a `deactivate` function,
# a `pydoc` function that runs the interpreter the activation puts on PATH,
# command substitutions, and `hash -r` so the shell forgets the old lookups.
# Nothing here is written by hand, and a developer sources it all day long.
ACTIVATE = """# This file must be used with "source bin/activate" *from bash*
# you cannot run it directly

deactivate () {
    unset -f pydoc >/dev/null 2>&1 || true

    if ! [ -z "${_OLD_VIRTUAL_PATH:+_}" ] ; then
        PATH="$_OLD_VIRTUAL_PATH"
        export PATH
        unset _OLD_VIRTUAL_PATH
    fi
    if ! [ -z "${_OLD_VIRTUAL_PYTHONHOME+_}" ] ; then
        PYTHONHOME="$_OLD_VIRTUAL_PYTHONHOME"
        export PYTHONHOME
        unset _OLD_VIRTUAL_PYTHONHOME
    fi

    # The hash command must be called to get it to forget past commands.
    hash -r 2>/dev/null

    if ! [ -z "${_OLD_VIRTUAL_PS1+_}" ] ; then
        PS1="$_OLD_VIRTUAL_PS1"
        export PS1
        unset _OLD_VIRTUAL_PS1
    fi

    unset VIRTUAL_ENV
    unset VIRTUAL_ENV_PROMPT
    if [ ! "${1-}" = "nondestructive" ] ; then
        unset -f deactivate
    fi
}

# unset irrelevant variables
deactivate nondestructive

VIRTUAL_ENV='__VIRTUAL_ENV__'
if ([ "$OSTYPE" = "cygwin" ] || [ "$OSTYPE" = "msys" ]) && $(command -v cygpath &> /dev/null) ; then
    VIRTUAL_ENV=$(cygpath -u "$VIRTUAL_ENV")
fi
export VIRTUAL_ENV

_OLD_VIRTUAL_PATH="$PATH"
PATH="$VIRTUAL_ENV/bin:$PATH"
export PATH

if [ "xproject-feature" != x ] ; then
    VIRTUAL_ENV_PROMPT="project-feature"
else
    VIRTUAL_ENV_PROMPT=$(basename "$VIRTUAL_ENV")
fi
export VIRTUAL_ENV_PROMPT

# unset PYTHONHOME if set
if ! [ -z "${PYTHONHOME+_}" ] ; then
    _OLD_VIRTUAL_PYTHONHOME="$PYTHONHOME"
    unset PYTHONHOME
fi

if [ -z "${VIRTUAL_ENV_DISABLE_PROMPT-}" ] ; then
    _OLD_VIRTUAL_PS1="${PS1-}"
    PS1="(${VIRTUAL_ENV_PROMPT}) ${PS1-}"
    export PS1
fi

# Make sure to unalias pydoc if it's already there
alias pydoc 2>/dev/null >/dev/null && unalias pydoc || true

pydoc () {
    python -m pydoc "$@"
}

# The hash command must be called to get it to forget past commands.
hash -r 2>/dev/null || true
"""
def venv_pytest_stub(venv: Path) -> str:
    """The console script an installed pytest leaves in a virtualenv's ``bin``.

    Its shebang names the environment's own interpreter, the way every
    generated entry point does, and it refuses to report a pass unless that
    interpreter is the one running it. Activating the environment and running
    the environment's own ``bin/pytest`` are the same work, so a case proves
    the sourced script took effect either way.
    """
    return (
        f"#!{venv}/bin/python\n"
        '"""Synthetic stand-in for the installed pytest: no network, no writes."""\n'
        "import sys\n"
        "\n"
        f"if sys.prefix != {str(venv)!r}:\n"
        '    sys.stderr.write("pytest stand-in: not the virtualenv interpreter\\n")\n'
        "    raise SystemExit(1)\n"
        'print(".....")\n'
        'print("5 passed in 0.12s")\n'
    )


VENV_PYTEST_STUB_PYTHON = (
    "print('.....')\n"
    "print('5 passed in 0.12s')\n"
)


def activate_script(venv: Path) -> str:
    """The activation script a virtualenv generates for ``venv``."""
    return ACTIVATE.replace("__VIRTUAL_ENV__", str(venv))


DOCKER_DIGEST = "sha256:" + "0123456789abcdef" * 4
DOCKER_STUB = (
    "#!/bin/sh\n"
    "# Read-only stand-in for docker: it never reaches a registry or a daemon.\n"
    "# Only the options Guard admits for a manifest query are understood.\n"
    'if [ "${1:-}" = buildx ] && [ "${2:-}" = imagetools ] && [ "${3:-}" = inspect ]; then\n'
    "  shift 3\n"
    "  images=0\n"
    '  while [ "$#" -gt 0 ]; do\n'
    '    case "$1" in\n'
    "      --raw | --format=*) ;;\n"
    '      --format) [ "$#" -ge 2 ] || exit 2; shift ;;\n'
    "      -*) printf 'docker stand-in: unsupported option\\n' >&2; exit 2 ;;\n"
    "      *) images=$((images + 1)) ;;\n"
    "    esac\n"
    "    shift\n"
    "  done\n"
    '  [ "$images" -eq 1 ] || exit 2\n'
    f"  printf '{DOCKER_DIGEST}\\n'\n"
    "  exit 0\n"
    "fi\n"
    "printf 'docker stand-in: unsupported command\\n' >&2\n"
    "exit 2\n"
)
DOCKER_STUB_PYTHON = (
    "import sys\n"
    "args = sys.argv[1:]\n"
    "ok = args[:3] == ['buildx', 'imagetools', 'inspect']\n"
    "images = 0\n"
    "index = 3\n"
    "while ok and index < len(args):\n"
    "    word = args[index]\n"
    "    index += 1\n"
    "    if word == '--raw' or word.startswith('--format='):\n"
    "        continue\n"
    "    if word == '--format':\n"
    "        ok = index < len(args)\n"
    "        index += 1\n"
    "    elif word.startswith('-'):\n"
    "        ok = False\n"
    "    else:\n"
    "        images += 1\n"
    "if ok and images == 1:\n"
    f"    sys.stdout.buffer.write(b'{DOCKER_DIGEST}\\n')\n"
    "else:\n"
    "    sys.stderr.buffer.write(b'docker stand-in: unsupported command\\n')\n"
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


def _link(path: Path, target: Path) -> None:
    """Link an environment's ``bin`` entry at the interpreter it was built from.

    Windows virtualenvs copy the interpreter rather than link it, and creating a
    symlink there needs a privilege an ordinary developer does not run with, so
    the launchers written beside this carry the environment on that platform.
    """
    if os.name == "nt":
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or path.exists():
        path.unlink()
    path.symlink_to(target)


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
    for relative, text in SOURCES.items():
        _write(main / relative, text)
    for relative, text in FEATURE_SOURCES.items():
        _write(main / relative, text)
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
    return (".gitignore", CONSOLE, DASHBOARD, PORTAL, "docs/review-notes.md", "scripts")


def borrow_main_modules(main: Path, worktree: Path) -> None:
    """Link the worktree's dependencies to the main checkout's install, as developers do."""
    (worktree / DASHBOARD / "node_modules").symlink_to(main / DASHBOARD / "node_modules")


def add_home_tools(home: Path) -> None:
    """Install the read-only CLI stand-ins under the home ``.local/bin``."""
    _write(home / LOCAL_BIN / "doctl", DOCTL_STUB, 0o755)
    write_windows_launcher(home / LOCAL_BIN, "doctl", DOCTL_STUB_PYTHON)
    _write(home / LOCAL_BIN / "docker", DOCKER_STUB, 0o755)
    write_windows_launcher(home / LOCAL_BIN, "docker", DOCKER_STUB_PYTHON)


def add_worktree_venv(worktree: Path) -> None:
    """Write the project's ``.venv``, as `uv venv` leaves one in a worked checkout.

    The activation script is the generated one, interpreter and test runner
    included, so a case that sources it exercises the shapes a hand-written
    script never has.
    """
    venv = worktree / VENV
    base = base_interpreter()
    _write(venv / "pyvenv.cfg", pyvenv_cfg(base))
    _write(venv / "bin/activate", activate_script(venv))
    for name in ("python", "python3"):
        _link(venv / "bin" / name, base)
    _write(venv / "bin/pytest", venv_pytest_stub(venv), 0o755)
    write_windows_launcher(venv / "bin", "pytest", VENV_PYTEST_STUB_PYTHON)
