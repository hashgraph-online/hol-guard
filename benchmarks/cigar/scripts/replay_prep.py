"""Build the commit-replay set: tasks made from merged public pull requests.

    CIGAR_GAUNTLET_WORK=... GH_TOKEN=... python3 -I replay_prep.py [--repos a,b] [--per-repo 4]
                                                                   [--pages 3] [--out FILE]

A task is a merged pull request that changes both code and tests: the agent starts at the merge's
parent, the PR's title and description are the prompt, and the PR's own test files are the check.
A candidate is kept only when, run from the PR's tests at the parent, they fail, and at the merge
they pass, each run under two minutes. Kept tasks are pinned by commit in
references/replay.json (default --out). This set is the fresh set: never tune notes on it.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rig import REFS, WORK

import lang_rig

LIMIT = 120
MAX_CHANGED = 400
MAX_PROMPT = 2000
# Upstream, language, which paths are tests, and how to run some of them.
REPOS = {
    "click": ("pallets/click", "py"),
    "boltons": ("mahmoud/boltons", "py"),
    "toolz": ("pytoolz/toolz", "py"),
    "moreit": ("more-itertools/more-itertools", "py"),
    "jinja": ("pallets/jinja", "py"),
    "pluggy": ("pytest-dev/pluggy", "py"),
    "cachetools": ("tkem/cachetools", "py"),
    "tomli": ("hukkin/tomli", "py"),
    "sortedcontainers": ("grantjenks/python-sortedcontainers", "py"),
    "mux": ("gorilla/mux", "go"),
    "semver": ("dtolnay/semver", "rust"),
    "ufo": ("unjs/ufo", "ts"),
}
TEST_PATH = {
    "py": re.compile(r"(^|/)(tests?|testing)/|(^|/)test_[^/]+\.py$|_test\.py$"),
    "go": re.compile(r"_test\.go$"),
    "rust": re.compile(r"^tests/|(^|/)tests?\.rs$"),
    "ts": re.compile(r"^test/|\.test\.ts$"),
}
CODE = {"py": ".py", "go": ".go", "rust": ".rs", "ts": ".ts"}

ROOT = WORK / "replay"


def gh(path):
    out = subprocess.run(["gh", "api", path], capture_output=True, text=True, timeout=60)
    return json.loads(out.stdout) if out.returncode == 0 else []


def git(*args, cwd, check=True):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=check)


def env_for(lang, repo, tree):
    env = dict(os.environ, NO_COLOR="1")
    # Upstream tests are third-party code: they never see a GitHub token.
    for name in ("GH_TOKEN", "GITHUB_TOKEN"):
        env.pop(name, None)
    if lang == "py":
        env["PYTHONPATH"] = os.pathsep.join([str(tree / "src"), str(tree)])
        env["PYTHONDONTWRITEBYTECODE"] = "1"
    else:
        env.update(lang_rig.lang_env())
        env["PATH"] = os.pathsep.join([str(lang_rig.bin_dir(lang)), env["PATH"]])
        env["GOCACHE"] = str(ROOT / "gocache")
    return env


def command(lang, repo, tests):
    if lang == "py":
        python = WORK / "r" / repo / "venv" / "bin" / "python"
        return [str(python), "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", *tests]
    if lang == "go":
        return ["go", "test", "-count=1", "./..."]
    if lang == "rust":
        return ["cargo", "test", "-q"]
    return ["npx", "vitest", "run", *tests]


def run(lang, repo, tree, tests):
    if lang == "ts" and not (tree / "node_modules").exists():
        (tree / "node_modules").symlink_to(lang_rig.LANG / repo / "node_modules")
    started = time.monotonic()
    try:
        done = subprocess.run(command(lang, repo, tests), cwd=tree, env=env_for(lang, repo, tree),
                              capture_output=True, text=True, timeout=LIMIT)
    except subprocess.TimeoutExpired:
        return None, LIMIT
    return done.returncode == 0, round(time.monotonic() - started, 1)


def prompt_of(pr):
    body = re.sub(r"<!--.*?-->", "", pr.get("body") or "", flags=re.S).strip()
    return (pr["title"].strip() + ("\n\n" + body if body else ""))[:MAX_PROMPT]


def check(lang, repo, clone, pr, tests):
    tree = ROOT / repo / f"pr{pr['number']}"
    if tree.exists():
        git("worktree", "remove", "--force", str(tree), cwd=clone, check=False)
        shutil.rmtree(tree, ignore_errors=True)
    merge = pr["merge_commit_sha"]
    parent = git("rev-parse", "--verify", "-q", f"{merge}^", cwd=clone, check=False).stdout.strip()
    if not parent:  # the merge commit is gone upstream (force-pushed branch)
        return None
    git("worktree", "add", "--detach", str(tree), parent, cwd=clone)
    try:
        git("checkout", merge, "--", *tests, cwd=tree)
        before, secs_before = run(lang, repo, tree, tests)
        if before is not False:
            return None
        git("checkout", "--force", merge, cwd=tree)
        after, secs_after = run(lang, repo, tree, tests)
        if after is not True:
            return None
        return {"parent": parent, "merge": merge, "secs": max(secs_before, secs_after)}
    finally:
        git("worktree", "remove", "--force", str(tree), cwd=clone, check=False)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repos", default=",".join(REPOS))
    ap.add_argument("--per-repo", type=int, default=4)
    ap.add_argument("--pages", type=int, default=3)
    ap.add_argument("--out", default=str(REFS / "replay.json"))
    a = ap.parse_args()
    tasks = json.loads(Path(a.out).read_text())["tasks"] if Path(a.out).exists() else []
    have = {(t["repo"], t["pr"]) for t in tasks}
    for repo in a.repos.split(","):
        upstream, lang = REPOS[repo]
        clone = ROOT / repo / "git"
        if not clone.exists():
            clone.parent.mkdir(parents=True, exist_ok=True)
            git("clone", "-q", "--filter=blob:none", f"https://github.com/{upstream}.git", str(clone), cwd=ROOT)
        kept = sum(t["repo"] == repo for t in tasks)
        for page in range(1, a.pages + 1):
            if kept >= a.per_repo:
                break
            for pr in gh(f"repos/{upstream}/pulls?state=closed&per_page=50&page={page}"):
                if kept >= a.per_repo:
                    break
                if not pr.get("merged_at") or (repo, pr["number"]) in have:
                    continue
                files = gh(f"repos/{upstream}/pulls/{pr['number']}/files?per_page=100")
                names = [f["filename"] for f in files if f.get("status") != "removed"]
                tests = [n for n in names if TEST_PATH[lang].search(n)]
                code = [n for n in names if n.endswith(CODE[lang]) and n not in tests]
                changed = sum(f.get("changes", 0) for f in files)
                if not tests or not code or changed > MAX_CHANGED:
                    continue
                git("fetch", "-q", "origin", pr["merge_commit_sha"], cwd=clone, check=False)
                pinned = check(lang, repo, clone, pr, tests)
                print(f"{repo}#{pr['number']}: {'kept' if pinned else 'skipped'}", flush=True)
                if not pinned:
                    continue
                tasks.append({"repo": repo, "lang": lang, "upstream": upstream, "pr": pr["number"],
                              "prompt": prompt_of(pr), "tests": tests, **pinned})
                kept += 1
                Path(a.out).write_text(json.dumps({"tasks": tasks}, indent=1) + "\n")
    print(f"{len(tasks)} tasks; languages: {sorted({t['lang'] for t in tasks})}")


if __name__ == "__main__":
    main()
