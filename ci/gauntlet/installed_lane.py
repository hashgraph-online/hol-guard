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
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .installed_registration import (
    GateBlockedError,
    assess_harness,
    install_harness,
    load_contract,
    read_config,
    stop_daemon,
)
from .installed_replay import EXPECTATIONS, argv_for_event, registered_argv, replay_harness
from .installed_restore import restore_pass
from .installed_runtime import InstalledRuntime, InstalledRuntimeError, resolve_runtime
from .installed_startup import startup_timeline
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


def undeclared_case_events(contract: dict[str, Any]) -> list[str]:
    """Events a case names that no replayable harness declares.

    A case whose event is declared nowhere is skipped by every harness and the
    lane still passes, which is the shape of the gap this per-event replay
    exists to close. Refusing to start is the only way that stays visible.
    """

    declared = {
        str(event)
        for expectation in contract["harnesses"].values()
        if expectation.get("replay")
        for event in expectation.get("replay_events", [])
    }
    wanted = {str(case["event"]) for case in contract["replay_cases"] if case.get("event")}
    return sorted(wanted - declared)


def unreplayed_cases(contract: dict[str, Any]) -> list[str]:
    """Cases that no replayable harness would run.

    A case limited to ``harnesses`` that do not replay, or that do not declare
    the case's event, is skipped everywhere while the lane passes. Like an
    undeclared event, that is coverage the lane does not have.
    """

    missing: list[str] = []
    for case in contract["replay_cases"]:
        only = case.get("harnesses")
        names = contract["harnesses"] if only is None else only
        event = case.get("event")
        runs = any(
            (expectation := contract["harnesses"].get(str(name))) is not None
            and expectation.get("replay")
            and (event is None or event in expectation.get("replay_events", []))
            for name in names
        )
        if not runs:
            missing.append(str(case["id"]))
    return missing


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
    install_started_ns = time.time_ns()
    install = install_harness(runtime, harness, home=home, guard_home=guard_home, workspace=workspace)
    installed_ns = time.time_ns()
    registration = assess_harness(home, harness, expectation)
    result: dict[str, Any] = {"install": install, "registration": registration}
    failures = list(registration["failures"])
    if install["exit_code"] != 0:
        failures.append(f"{harness}: install exited {install['exit_code']}: {install['stderr_tail']}")
    replay_started_ns: int | None = None
    if expectation.get("replay") and not failures:
        replay_started_ns = time.time_ns()
        config = read_config(home / expectation["config"]) or {}
        argv = registered_argv(home, expectation, config)
        if argv is None:
            failures.append(f"{harness}: registration carries no runnable hook argv to replay")
        else:
            # Cases that name their own event need that event's own argv, and
            # only the events this harness declares are resolved. Guard prunes
            # Claude Code's prompt hook on purpose, so a prompt case has
            # nothing to replay there and the contract declares no such event
            # for it; a declared event with no argv stays a failure below.
            declared = [str(event) for event in expectation.get("replay_events", [])]
            replay = replay_harness(
                harness,
                argv,
                contract["replay_cases"],
                home=home,
                guard_home=guard_home,
                workspace=workspace,
                repeat=repeat,
                argv_by_event={event: argv_for_event(expectation, config, event) for event in declared},
                native_runtime=runtime.native_runtime,
            )
            result["replay"] = replay
            failures.extend(replay["failures"])
    elif not expectation.get("replay"):
        result["replay_gap"] = expectation.get("replay_gap")
    # Read after the replay, so a daemon the first hook outran still shows when it came up.
    result["startup"] = startup_timeline(guard_home, since_ns=installed_ns, not_before_ns=install_started_ns)
    if replay_started_ns is not None:
        result["startup"]["replay_started_ms"] = round((replay_started_ns - installed_ns) / 1_000_000, 1)
    # A user runs one daemon. Left running, this home's daemon would compete
    # with every later harness's cold start and inflate its readiness timings.
    result["startup"]["daemon_stop_exit_code"] = stop_daemon(runtime, home=home, guard_home=guard_home)
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


PREWARM_WAIT_SECONDS = 60.0


def prewarm_probe(runtime: InstalledRuntime, harness: str, *, root: Path) -> dict[str, Any]:
    """How long the install's own prewarm takes to bring the daemon up, with no hook in the way.

    The harness passes replay straight after install, so their first hook races the
    prewarm and may start a daemon of its own. This pass installs into a fresh home,
    sends no hook and waits for the daemon's ``ready`` journal entry. It is evidence,
    not a verdict: a slow or absent prewarm shows up in the harness passes already.
    """

    home = build_home(root, f"prewarm-{harness}")
    guard_home = home / ".hol-guard"
    workspace = build_workspace(root / f"prewarm-{harness}")
    install_started_ns = time.time_ns()
    install = install_harness(runtime, harness, home=home, guard_home=guard_home, workspace=workspace)
    installed_ns = time.time_ns()
    deadline = time.monotonic() + PREWARM_WAIT_SECONDS
    timeline = startup_timeline(guard_home, since_ns=installed_ns, not_before_ns=install_started_ns)
    while timeline["ready_ms"] is None and time.monotonic() < deadline:
        time.sleep(0.25)
        timeline = startup_timeline(guard_home, since_ns=installed_ns, not_before_ns=install_started_ns)
    # The probe's daemon would otherwise keep running beside the harness passes
    # and skew their cold-start timings.
    timeline["daemon_stop_exit_code"] = stop_daemon(runtime, home=home, guard_home=guard_home)
    timeline["harness"] = harness
    timeline["install_exit_code"] = install["exit_code"]
    timeline["waited_seconds"] = PREWARM_WAIT_SECONDS
    return timeline


def run_lane(
    *,
    runtime_path: Path,
    harnesses: list[str],
    repeat: int,
    require_frozen: bool,
    aged_store: bool,
    output: Path,
    uninstall_restore: bool = False,
    work_root: Path | None = None,
) -> dict[str, Any]:
    """Run the whole lane and return its evidence."""

    contract = load_contract()
    unknown = [harness for harness in harnesses if harness not in contract["harnesses"]]
    if unknown:
        raise InstalledRuntimeError(f"no installed-acceptance expectations for {', '.join(unknown)}")
    undeclared = undeclared_case_events(contract)
    if undeclared:
        raise InstalledRuntimeError(
            "no harness declares replay_events for "
            f"{', '.join(undeclared)}; a case no harness replays is coverage the lane does not have"
        )
    unexpected = sorted(case["id"] for case in contract["replay_cases"] if case.get("expect") not in EXPECTATIONS)
    if unexpected:
        raise InstalledRuntimeError(
            f"{', '.join(unexpected)} expect an outcome the lane cannot judge; "
            f"use one of {', '.join(sorted(EXPECTATIONS))}"
        )
    unreplayed = unreplayed_cases(contract)
    if unreplayed:
        raise InstalledRuntimeError(
            f"no replayable harness runs {', '.join(unreplayed)}; "
            "a case no harness replays is coverage the lane does not have"
        )
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
        evidence["prewarm_probe"] = prewarm_probe(runtime, harnesses[0], root=root)
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
        if uninstall_restore:
            # Removing Guard must hand the user's own settings back unchanged.
            evidence["uninstall_restore"] = restore_pass(
                runtime,
                harnesses,
                contract,
                home=build_home(root, "home-restore"),
                workspace=build_workspace(root / "restore"),
            )
            failures.extend(evidence["uninstall_restore"]["failures"])
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


__all__ = [
    "EVIDENCE_VERSION",
    "aged_pass",
    "build_home",
    "build_workspace",
    "harness_pass",
    "prewarm_probe",
    "run_lane",
    "undeclared_case_events",
    "unreplayed_cases",
]
