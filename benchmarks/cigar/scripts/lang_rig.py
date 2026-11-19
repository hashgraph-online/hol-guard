"""Shared setup for the non-Python language set (Go, Rust, TypeScript): bug steps only.

Each language has one pinned repo under $CIGAR_GAUNTLET_WORK/lang/<repo> (see lang_setup.sh) and a
"bin" folder holding python plus symlinks to the language's tools. The agent's login shell puts that
folder first on PATH, as the Python set does with a repo venv, so every arm finds the same tools
whatever HOME it runs with.
"""

import os
import re
import subprocess
from pathlib import Path

from rig import WORK

LANG = WORK / "lang"
CHECK_TIMEOUT = 600

LANGS = {
    "go": {
        "repo": "mux",
        "tools": ["go", "gofmt"],
        "test": ["go", "test", "-count=1", "./..."],
        "src": lambda p: p.suffix == ".go" and not p.name.endswith("_test.go") and "/" not in p.as_posix(),
        "tests": [":(glob)**/*_test.go"],
        "func": re.compile(r"^func (?:\([^)]*\) )?(\w+)\("),
        "failing": re.compile(r"^--- FAIL: (\S+)", re.M),
    },
    "rust": {
        "repo": "semver",
        "tools": ["cargo", "rustc", "rustfmt"],
        "test": ["cargo", "test", "--offline", "-q"],
        "src": lambda p: p.suffix == ".rs" and p.parts[0] == "src",
        "tests": ["tests"],
        "func": re.compile(r"^\s*(?:pub(?:\([^)]*\))? )?(?:const )?fn (\w+)"),
        "failing": re.compile(r"^---- (\S+) stdout ----", re.M),
    },
    "ts": {
        "repo": "ufo",
        "tools": ["node", "npm", "npx"],
        "test": ["npx", "vitest", "run"],
        "src": lambda p: p.suffix == ".ts" and p.parts[0] == "src",
        "tests": ["test"],
        "func": re.compile(r"^export (?:async )?function (\w+)|^(?:export )?const (\w+) = "),
        "failing": re.compile(r"^\s*(?:FAIL|×)\s+(test/\S+ > [^\n]+?)(?:\s+\d+ms)?$", re.M),
    },
}

TOOL_DIRS = [Path("/opt/homebrew/bin"), Path.home() / ".cargo" / "bin", Path("/usr/local/bin")]


def clean_path():
    """The operator's PATH without the host Guard's package shims: rig agents get only the arm's Guard."""
    return os.pathsep.join(d for d in os.environ.get("PATH", "").split(os.pathsep) if "package-shims" not in d)


def bin_dir(lang):
    return LANG / f"{LANGS[lang]['repo']}-bin" / "bin"


def python_of(lang):
    return bin_dir(lang) / "python"


def lang_env():
    """Tool settings every step and check shares. Rust's proxies need the real rustup home even when
    an arm runs with its own HOME; Go's build cache lives in the project, which every sandbox can write."""
    return {
        "PATH": clean_path(),
        "RUSTUP_HOME": os.environ.get("RUSTUP_HOME", str(Path.home() / ".rustup")),
        "CARGO_HOME": os.environ.get("CARGO_HOME", str(Path.home() / ".cargo")),
        "GOTOOLCHAIN": "local",
        "GOFLAGS": "-mod=mod",
        "CARGO_TERM_COLOR": "never",
        "NO_COLOR": "1",
    }


def project_env(project):
    return {"GOCACHE": str(project / ".gocache")}


def run_tests(lang, project, sandbox_home=None, timeout=CHECK_TIMEOUT):
    """(exit code, output tail) of the language's suite. With sandbox_home, inside the agent's sandbox."""
    command = list(LANGS[lang]["test"])
    if sandbox_home:
        import bench_guard_cigar_long_task as B

        command = B.sandboxed(command)
    env = dict(os.environ, **lang_env(), **project_env(project))
    env["PATH"] = str(bin_dir(lang)) + os.pathsep + env["PATH"]
    if sandbox_home:
        env["CODEX_HOME"] = str(sandbox_home)
    try:
        done = subprocess.run(command, cwd=project, capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        return 124, f"timed out after {timeout}s"
    return done.returncode, re.sub(r"\x1b\[[0-9;]*m", "", done.stdout + done.stderr)


def enclosing(lang, lines, index):
    pattern = LANGS[lang]["func"]
    for line in reversed(lines[: index + 1]):
        m = pattern.match(line)
        if m:
            return next(g for g in m.groups() if g)
    return None
