"""Clone the six pinned repos, make a pristine git copy and a venv for each, and record the green baseline.

Usage: setup_repos.py [repo ...]   (idempotent; writes $CIGAR_GAUNTLET_WORK/r/<repo>)
"""

import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rig import REFS, REPOS_DIR, pool_path

repos = json.loads((REFS / "repos.json").read_text())


def run(*a, **k):
    return subprocess.run(a, check=True, capture_output=True, text=True, **k)


for name, r in repos.items():
    if sys.argv[1:] and name not in sys.argv[1:]:
        continue
    base = REPOS_DIR / name
    clone, pristine, venv = base / "clone", base / "pristine", base / "venv"
    base.mkdir(parents=True, exist_ok=True)
    if not clone.exists():
        run("git", "clone", "-q", "--depth", "1", "--branch", r["tag"], r["url"], str(clone))
    if not pristine.exists():
        pristine.mkdir()
        tar = subprocess.run(["git", "-C", str(clone), "archive", "HEAD"], check=True, capture_output=True).stdout
        subprocess.run(["tar", "-x", "-C", str(pristine)], input=tar, check=True)
        env = dict(
            os.environ,
            GIT_AUTHOR_NAME="dev",
            GIT_AUTHOR_EMAIL="dev@example.test",
            GIT_COMMITTER_NAME="dev",
            GIT_COMMITTER_EMAIL="dev@example.test",
        )
        run("git", "init", "-q", "-b", "main", str(pristine))
        run("git", "-C", str(pristine), "add", "-A")
        run(
            "git",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-C",
            str(pristine),
            "commit",
            "-q",
            "-m",
            f"{name} {r['tag']}",
            env=env,
        )
    if not (venv / "bin" / "python").exists():
        run(sys.executable, "-m", "venv", str(venv))
        run(str(venv / "bin" / "python"), "-m", "pip", "-q", "install", "pytest==8.3.4", *r["deps"])
    deselect = json.loads(pool_path(name).read_text())["deselect"] if pool_path(name).exists() else []
    args = [str(venv / "bin" / "python"), "-m", "pytest", "-q", "-p", "no:cacheprovider", "--color=no", r["tests"]]
    for d in deselect:
        args += ["--deselect", d]
    done = subprocess.run(
        args, cwd=pristine, capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=str(pristine / "src"))
    )
    tail = done.stdout.strip().splitlines()[-1] if done.stdout.strip() else done.stderr[-300:]
    print(name, "green" if done.returncode == 0 else f"RED rc={done.returncode}", tail, flush=True)
