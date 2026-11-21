"""Install and then uninstall over a home that already has the user's own settings.

A user who removes Guard expects their harness configuration back as they left
it. This pass writes synthetic user settings into each harness's config file
(and a Claude Code project settings file, which ``--workspace`` must never
touch), runs the shipped ``install`` and ``uninstall`` for every harness, and
compares the bytes afterwards. A file that comes back reformatted but equal
when parsed is still a failure: the acceptance is unchanged user bytes. The
evidence records whether the parsed content matched so a formatting-only
difference is easy to tell from lost settings.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

import tomllib

from .installed_registration import assess_harness, install_harness, stop_daemon
from .installed_runtime import InstalledRuntime, isolated_environment, run_guard

# Synthetic settings a user might already have. Every value is invented; the
# Claude Code entry also carries a hook of the user's own that Guard must keep.
CLAUDE_USER_SETTINGS = (
    "{\n"
    '  "theme": "dark",\n'
    '  "env": {"SYNTHETIC_FLAG": "1"},\n'
    '  "hooks": {\n'
    '    "PreToolUse": [\n'
    '      {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo user-owned-hook"}]}\n'
    "    ]\n"
    "  }\n"
    "}\n"
)
CODEX_USER_CONFIG = (
    '# The user\'s own Codex settings.\nmodel = "synthetic-model"\n\n[profiles.synthetic]\nmodel = "synthetic-other"\n'
)
JSON_USER_SETTINGS = '{\n  "syntheticUserSetting": "keep-me",\n  "nested": {"value": 1}\n}\n'
# Muse refuses a settings file without a schema version, so a real Muse user's file always has one.
MUSE_USER_SETTINGS = '{\n  "schema_version": 1,\n  "syntheticUserSetting": "keep-me",\n  "nested": {"value": 1}\n}\n'
PROJECT_LOCAL_SETTINGS = '{\n  "permissions": {"allow": ["Bash(ls:*)"]}\n}\n'


def _seed_for(harness: str, relative: str) -> str:
    if harness == "claude-code":
        return CLAUDE_USER_SETTINGS
    if harness == "muse":
        return MUSE_USER_SETTINGS
    if relative.endswith(".toml"):
        return CODEX_USER_CONFIG
    return JSON_USER_SETTINGS


def _parsed(path: Path, text: str) -> object:
    try:
        return tomllib.loads(text) if path.suffix == ".toml" else json.loads(text)
    except (ValueError, tomllib.TOMLDecodeError):
        return None


def _check_project(path: Path, last: dict[str, bytes | None], step: str, failures: list[str]) -> None:
    """Record a change to the workspace's own settings by the command that made it.

    A later command could put the bytes back, so checking only at the end
    would miss an install that wrote the file and an uninstall that undid it.
    Comparing with the previous step blames only the command that changed it.
    """

    after = path.read_bytes() if path.is_file() else None
    if after != last["bytes"]:
        failures.append(f"workspace/.claude/settings.local.json: changed by {step}")
        last["bytes"] = after


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


def uninstall_harness(
    runtime: InstalledRuntime,
    harness: str,
    *,
    home: Path,
    guard_home: Path,
    workspace: Path,
    timeout: float = 300.0,
) -> dict[str, Any]:
    """Run the shipped uninstall command for ``harness`` in a lane-owned home."""

    environment = isolated_environment(home=home, guard_home=guard_home, native_runtime=runtime.native_runtime)
    completed = run_guard(
        runtime,
        [
            "uninstall",
            harness,
            "--home",
            str(home),
            "--guard-home",
            str(guard_home),
            "--workspace",
            str(workspace),
            "--json",
        ],
        environment=environment,
        timeout=timeout,
        cwd=workspace,
    )
    return {
        "harness": harness,
        "exit_code": completed.returncode,
        "stderr_tail": (completed.stderr or "").strip()[-600:],
    }


def compare_seeded(seeded: dict[str, tuple[Path, bytes]]) -> list[dict[str, Any]]:
    """One row per seeded file: whether its bytes, or at least its parsed content, came back."""

    rows: list[dict[str, Any]] = []
    for label, (path, before) in sorted(seeded.items()):
        after = path.read_bytes() if path.is_file() else None
        row: dict[str, Any] = {
            "path": label,
            "before": _digest(before),
            "after": None if after is None else _digest(after),
            "bytes_identical": after == before,
        }
        if after is not None and after != before:
            row["parsed_equal"] = _parsed(path, before.decode("utf-8")) == _parsed(
                path, after.decode("utf-8", errors="replace")
            )
        rows.append(row)
    return rows


def restore_pass(
    runtime: InstalledRuntime,
    harnesses: list[str],
    contract: dict[str, Any],
    *,
    home: Path,
    workspace: Path,
) -> dict[str, Any]:
    """Seed user settings, install and uninstall every harness, and compare the bytes."""

    guard_home = home / ".hol-guard"
    seeded: dict[str, tuple[Path, bytes]] = {}
    for harness in harnesses:
        relative = contract["harnesses"][harness]["config"]
        path = home / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_seed_for(harness, relative), encoding="utf-8", newline="\n")
        seeded[f"home/{relative}"] = (path, path.read_bytes())
    project_local = workspace / ".claude" / "settings.local.json"
    project_local.parent.mkdir(parents=True, exist_ok=True)
    project_local.write_text(PROJECT_LOCAL_SETTINGS, encoding="utf-8", newline="\n")
    seeded["workspace/.claude/settings.local.json"] = (project_local, project_local.read_bytes())

    failures: list[str] = []
    uninstalls: list[dict[str, Any]] = []
    last_project: dict[str, bytes | None] = {"bytes": project_local.read_bytes()}
    try:
        installs: list[dict[str, Any]] = []
        for harness in harnesses:
            # A hung install is a failed result, so the lane still uninstalls,
            # compares and writes its evidence.
            try:
                installs.append(
                    install_harness(runtime, harness, home=home, guard_home=guard_home, workspace=workspace)
                )
            except subprocess.TimeoutExpired:
                installs.append({"harness": harness, "exit_code": None, "stderr_tail": "install timed out"})
            _check_project(project_local, last_project, f"{harness} install", failures)
        # An installer that skipped the seeded file and still exited 0 would
        # leave every seed untouched, so the byte check below would pass
        # without testing removal. Require Guard to be registered first.
        registered = {
            harness: assess_harness(home, harness, contract["harnesses"][harness])["registered"]
            for harness in harnesses
        }
        for entry in installs:
            if entry["exit_code"] != 0:
                failures.append(f"{entry['harness']}: install exited {entry['exit_code']}: {entry['stderr_tail']}")
            elif not registered[entry["harness"]]:
                failures.append(f"{entry['harness']}: install exited 0 but Guard is not registered in the seeded home")
        for harness in harnesses:
            try:
                entry = uninstall_harness(runtime, harness, home=home, guard_home=guard_home, workspace=workspace)
            except subprocess.TimeoutExpired:
                entry = {"harness": harness, "exit_code": None, "stderr_tail": "uninstall timed out"}
            uninstalls.append(entry)
            _check_project(project_local, last_project, f"{harness} uninstall", failures)
            if entry["exit_code"] != 0:
                failures.append(f"{harness}: uninstall exited {entry['exit_code']}: {entry['stderr_tail']}")
    finally:
        daemon_stop = stop_daemon(runtime, home=home, guard_home=guard_home)

    files = compare_seeded(seeded)
    for row in files:
        if not row["bytes_identical"]:
            detail = "missing" if row["after"] is None else f"parsed_equal={row.get('parsed_equal')}"
            failures.append(f"{row['path']}: user bytes changed after install and uninstall ({detail})")
    return {
        "install": [entry["exit_code"] for entry in installs],
        "registered": registered,
        "uninstall": uninstalls,
        "daemon_stop_exit_code": daemon_stop,
        "files": files,
        "failures": failures,
        "passed": not failures,
    }


__all__ = ["compare_seeded", "restore_pass", "uninstall_harness"]
