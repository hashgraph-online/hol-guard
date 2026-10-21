"""The installed-acceptance lane: run the shipped build the way a machine runs it.

Qualification answers "does Guard decide correctly when driven as a library".
This lane answers the question underneath it — "is Guard actually installed,
and does it answer the same way twice" — which is what the user hits first and
what qualification structurally cannot see. It is deliberately not a merge gate
and is never added to GitHub's required checks.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .installed_registration import (
    GateBlockedError,
    assess_harness,
    install_harness,
    load_contract,
    read_config,
)
from .installed_replay import registered_argv, replay_harness
from .installed_runtime import InstalledRuntime, InstalledRuntimeError, resolve_runtime
from .installed_store import age_home, assess_aged

EVIDENCE_VERSION = "hol-guard-installed-acceptance.v1"


def build_workspace(root: Path) -> Path:
    """A small, ordinary repository: the kind of place real work happens."""

    workspace = root / "workspace"
    (workspace / "src").mkdir(parents=True, exist_ok=True)
    (workspace / "README.md").write_text("# project\n\nOrdinary work happens here.\n", encoding="utf-8")
    (workspace / "src" / "main.py").write_text("# TODO: finish the parser\n", encoding="utf-8")
    subprocess.run(["git", "init", "--quiet"], cwd=workspace, check=False, capture_output=True)
    return workspace


def build_home(root: Path, name: str) -> Path:
    """A lane-owned home carrying the credential files an attack would target.

    They are decoys written here so the attack cases name a path that exists,
    the way they would on a real machine. Nothing reads the operator's own.
    """

    home = root / name
    (home / ".ssh").mkdir(parents=True, exist_ok=True)
    (home / ".aws").mkdir(parents=True, exist_ok=True)
    (home / ".ssh" / "id_rsa").write_text("DECOY NOT A KEY\n", encoding="utf-8")
    (home / ".aws" / "credentials").write_text("[default]\naws_access_key_id = DECOY\n", encoding="utf-8")
    return home


def harness_pass(
    runtime: InstalledRuntime,
    harness: str,
    expectation: dict[str, Any],
    contract: dict[str, Any],
    *,
    root: Path,
    repeat: int,
) -> dict[str, Any]:
    """Install one harness into a fresh home, then check and replay it."""

    home = build_home(root, f"home-{harness}")
    guard_home = home / ".hol-guard"
    workspace = build_workspace(root / harness)
    install = install_harness(runtime, harness, home=home, guard_home=guard_home, workspace=workspace)
    registration = assess_harness(home, harness, expectation)
    result: dict[str, Any] = {"install": install, "registration": registration}
    failures = list(registration["failures"])
    if install["exit_code"] != 0:
        failures.append(f"{harness}: install exited {install['exit_code']}: {install['stderr_tail']}")
    if expectation.get("replay") and not failures:
        config = read_config(home / expectation["config"]) or {}
        argv = registered_argv(home, expectation, config)
        if argv is None:
            failures.append(f"{harness}: registration carries no runnable hook argv to replay")
        else:
            replay = replay_harness(
                harness,
                argv,
                contract["replay_cases"],
                home=home,
                guard_home=guard_home,
                workspace=workspace,
                repeat=repeat,
            )
            result["replay"] = replay
            failures.extend(replay["failures"])
    elif not expectation.get("replay"):
        result["replay_gap"] = expectation.get("replay_gap")
    result["failures"] = failures
    result["passed"] = not failures
    return result


def aged_pass(
    runtime: InstalledRuntime,
    harnesses: list[str],
    contract: dict[str, Any],
    *,
    root: Path,
) -> dict[str, Any]:
    """Install once, age the home, install again, and look for leftovers."""

    home = build_home(root, "home-aged")
    guard_home = home / ".hol-guard"
    workspace = build_workspace(root / "aged")
    first = [
        install_harness(runtime, harness, home=home, guard_home=guard_home, workspace=workspace)
        for harness in harnesses
    ]
    ageing = age_home(home)
    second = [
        install_harness(runtime, harness, home=home, guard_home=guard_home, workspace=workspace)
        for harness in harnesses
    ]
    registration = [assess_harness(home, harness, contract["harnesses"][harness]) for harness in harnesses]
    relative_paths: list[str] = []
    for harness in harnesses:
        expectation = contract["harnesses"][harness]
        relative_paths.append(expectation["config"])
        # Codex keeps a legacy hooks.json beside config.toml. Ageing writes the
        # stale handler there, and a reinstall may leave it or fold it into the
        # TOML. Checking only the primary file misses whichever one survived.
        alternate = expectation.get("alternate_config")
        if isinstance(alternate, str) and alternate:
            relative_paths.append(alternate)
    assessment = assess_aged(home, relative_paths, registration)
    assessment["first_install"] = [entry["exit_code"] for entry in first]
    assessment["second_install"] = [entry["exit_code"] for entry in second]
    assessment["ageing"] = ageing
    for entry in second:
        if entry["exit_code"] != 0:
            assessment["failures"].append(
                f"{entry['harness']}: reinstall over an aged home exited {entry['exit_code']}: {entry['stderr_tail']}"
            )
    assessment["passed"] = not assessment["failures"]
    return assessment


def run_lane(
    *,
    runtime_path: Path,
    harnesses: list[str],
    repeat: int,
    require_frozen: bool,
    aged_store: bool,
    output: Path,
    work_root: Path | None = None,
) -> dict[str, Any]:
    """Run the whole lane and return its evidence."""

    contract = load_contract()
    unknown = [harness for harness in harnesses if harness not in contract["harnesses"]]
    if unknown:
        raise InstalledRuntimeError(f"no installed-acceptance expectations for {', '.join(unknown)}")
    output.mkdir(parents=True, exist_ok=True)
    root = work_root or (output / "work")
    root.mkdir(parents=True, exist_ok=True)
    runtime = resolve_runtime(runtime_path, require_frozen=require_frozen)
    evidence: dict[str, Any] = {
        "version": EVIDENCE_VERSION,
        "started": datetime.now(timezone.utc).isoformat(),
        "runtime": runtime.as_evidence(),
        "contract_version": contract["version"],
        "repeat": repeat,
        "harnesses": {},
    }
    failures: list[str] = []
    try:
        for harness in harnesses:
            result = harness_pass(
                runtime,
                harness,
                contract["harnesses"][harness],
                contract,
                root=root,
                repeat=repeat,
            )
            evidence["harnesses"][harness] = result
            failures.extend(result["failures"])
        if aged_store:
            replayable = [harness for harness in harnesses if contract["harnesses"][harness].get("replay")]
            evidence["aged_store"] = aged_pass(runtime, replayable or harnesses, contract, root=root)
            failures.extend(evidence["aged_store"]["failures"])
    except GateBlockedError as blocked:
        evidence["gate_blocked"] = str(blocked)
        evidence["accepted"] = False
        evidence["failures"] = [str(blocked)]
        _write(evidence, output)
        return evidence
    evidence["failures"] = failures
    evidence["accepted"] = not failures
    evidence["finished"] = datetime.now(timezone.utc).isoformat()
    _write(evidence, output)
    if evidence["accepted"] and work_root is None:
        shutil.rmtree(root, ignore_errors=True)
    return evidence


def _write(evidence: dict[str, Any], output: Path) -> None:
    (output / "installed-acceptance.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")


__all__ = ["EVIDENCE_VERSION", "aged_pass", "build_home", "build_workspace", "harness_pass", "run_lane"]
