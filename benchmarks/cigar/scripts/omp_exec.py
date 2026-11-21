"""Run one Oh My Pi step headless and read its usage.

Both omp arms run the same command; only ompcigar adds Guard's managed extension (the one
`hol-guard install omp` writes). omp reads the user's own agent dir for its model login, so no
credential is copied; everything else that dir could add (extensions, skills, rules, advisor,
prewalk, other tools) is turned off so the arms differ in Guard's extension and nothing else.
The tool set is the one Guard's own omp Gauntlet lane uses.
"""

import json
import os
import subprocess
from pathlib import Path

HARNESS = "omp"
MODEL = "gpt-6-luna"
EFFORT = "medium"
TOOLS = "read,write,edit,bash,grep,glob,eval,todo"
AGENT_DIR = Path(os.environ.get("CIGAR_GAUNTLET_OMP_AGENT_DIR", Path.home() / ".omp" / "agent"))
OVERLAY = "advisor:\n  enabled: false\nprewalk:\n  enabled: false\nautoResume: false\n"


def command(arm: Path, project: Path, sessions: Path, prompt: str, resume: bool) -> list[str]:
    overlay = arm / "omp-overlay.yml"
    overlay.write_text(OVERLAY)
    argv = [
        "omp",
        "--model",
        f"openai-codex/{MODEL}",
        "--thinking",
        EFFORT,
        "--cwd",
        str(project),
        "--no-extensions",
        "--no-skills",
        "--no-rules",
        "--no-lsp",
        "--no-title",
        "--config",
        str(overlay),
        "--tools",
        TOOLS,
        "--session-dir",
        str(sessions),
    ]
    if (arm / "hol-guard.ts").is_file():
        argv += ["--extension", str(arm / "hol-guard.ts")]
    if resume:
        argv.append("--continue")
    return argv + ["--mode", "json", "--print", prompt]


def env(base: dict, arm: Path) -> dict:
    # The arm's HOME already isolates the operator's Git setup, so the identity goes in its own
    # ~/.gitconfig. An exported GIT_CONFIG_GLOBAL is a value Guard's hook does not carry, which
    # leaves every git read in ompcigar waiting on an approval no one gives -- a cost ompbase,
    # with no Guard, never pays.
    home = arm / "home"
    home.mkdir(parents=True, exist_ok=True)
    shared = base.get("GIT_CONFIG_GLOBAL")
    if shared and Path(shared).is_file():
        (home / ".gitconfig").write_text(Path(shared).read_text())
    clean = {name: value for name, value in base.items() if name != "GIT_CONFIG_GLOBAL"}
    return dict(clean, HOME=str(home), PI_CODING_AGENT_DIR=str(AGENT_DIR), NO_COLOR="1")


def messages(out: Path) -> list[dict]:
    rows = []
    for line in out.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get("type") == "message_end" and (event.get("message") or {}).get("role") == "assistant":
            rows.append(event["message"])
    return rows


def answer(out: Path) -> str | None:
    for message in reversed(messages(out)):
        text = "".join(c.get("text", "") for c in message.get("content") or [] if c.get("type") == "text")
        if text.strip():
            return text
    return None


def usage(outs: list[Path]) -> dict:
    """Tokens in the shape bench_guard_cigar_usage scores, from every model request the steps streamed."""
    total = dict.fromkeys(
        (
            "input_tokens",
            "cached_input_tokens",
            "cache_write_tokens",
            "uncached_input_tokens",
            "output_tokens",
            "requests",
            "compactions",
        ),
        0,
    )
    for out in outs:
        for line in out.read_text(encoding="utf-8", errors="replace").splitlines():
            if '"type":"compaction' in line[:200] or '"type":"auto_compaction_start' in line[:200]:
                total["compactions"] += 1
        for message in messages(out):
            u = message.get("usage") or {}
            total["input_tokens"] += u.get("input", 0) + u.get("cacheRead", 0) + u.get("cacheWrite", 0)
            total["uncached_input_tokens"] += u.get("input", 0)
            total["cached_input_tokens"] += u.get("cacheRead", 0)
            total["cache_write_tokens"] += u.get("cacheWrite", 0)
            total["output_tokens"] += u.get("output", 0)
            total["requests"] += 1
    return total


def run(arm: Path, project: Path, sessions: Path, base_env: dict, prompt: str, resume: bool, out: Path, timeout: int):
    with out.open("w", encoding="utf-8") as stdout, out.with_suffix(".err").open("a", encoding="utf-8") as stderr:
        done = subprocess.run(
            command(arm, project, sessions, prompt, resume),
            cwd=project,
            env=env(base_env, arm),
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            timeout=timeout,
        )
    return done.returncode
