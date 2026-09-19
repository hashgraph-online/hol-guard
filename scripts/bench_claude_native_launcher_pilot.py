#!/usr/bin/env python3
"""Compare private native/Python Claude registrations in an actual installed wheel.

This is a Linux pilot investigation, never a release qualification gate. Every
sample executes the registered process and requires the existing native daemon
receipt. A failed setup retains bounded evidence and cannot become a measured
native no-go. Run within the shared measurement lock on shared hosts.
"""

from __future__ import annotations

# Standalone benchmark entry point: append only scripts, never the source package.
# ruff: noqa: E402
import argparse
import hashlib
import importlib.metadata
import json
import statistics
import sys
from pathlib import Path
from typing import cast

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.claude_code import ClaudeCodeHarnessAdapter
from codex_plugin_scanner.guard.adapters.claude_native_pilot_record import EVENTS, bounded_read, load_record
from scripts.native_claude_launcher_pilot import (
    _installed_runtime,
    activate_private_pilot,
    install_private_pilot,
    restore_private_pilot,
)
from scripts.native_slo_artifact import installed_package_digest, wheel_package_digest
from scripts.native_slo_contract import assert_privacy_safe, summarize
from scripts.native_slo_daemon_fixture import DaemonFixture
from scripts.native_slo_failure import FixtureFailureError, failure_evidence
from scripts.native_slo_observation_failure import contextual_failure, verdict_evidence
from scripts.native_slo_priority_launchers import (
    LauncherSession,
    RegisteredLauncher,
    _require_native_count,
    _route_snapshot,
    observe_priority_launcher,
    registered_launcher,
)
from scripts.native_slo_resources import ResourceSampler


def _children_cpu() -> float:
    import resource

    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    return usage.ru_utime + usage.ru_stime


def _native_launcher(record_path: Path, event: str) -> RegisteredLauncher:
    record = load_record(record_path, event)
    if record.get("require_native_transport") is not True:
        raise RuntimeError("qualification native launcher permits Python handoff")
    return RegisteredLauncher(
        "claude-code",
        event,
        tuple(record["argv"][event]),
        (),
        record["registration_sha256"],
        Path(record["configuration"]),
    )


def _launcher_session(session: DaemonFixture) -> LauncherSession:
    # DaemonFixture exposes the same route-metrics protocol through its private
    # control pipe; its concrete daemon field is a nested SimpleNamespace.
    return cast(LauncherSession, cast(object, session))


def _failed_native_attempt(session: DaemonFixture) -> dict[str, object]:
    try:
        evidence = session.control("case_result")
        return {
            "native_call_diagnostic": evidence.get("native_call_diagnostic"),
            "native_call_count": evidence.get("native_call_count"),
            "native_completed_call_count": evidence.get("native_completed_call_count"),
            "last_native_semantics": verdict_evidence(native=evidence.get("native_result"))["native"],
            "routes_after_failure": dict(_route_snapshot(_launcher_session(session))),
        }
    except Exception:
        return {"native_detail_collection_failed": True}


def _preflight(session: DaemonFixture, launcher: RegisteredLauncher, *, case: str) -> None:
    session.control("case_before")
    measured = _launcher_session(session)
    before = _route_snapshot(measured)
    try:
        observe_priority_launcher(measured, launcher, sample=-1, case=case)
        after = _route_snapshot(measured, expected=sum(before.values()) + 1)
        _require_native_count(before, after, 1)
    except Exception as error:
        raise contextual_failure(
            error, excluded_from_comparison=True, routes_before=dict(before), **_failed_native_attempt(session)
        ) from error


def _series(session: DaemonFixture, launcher: RegisteredLauncher, count: int) -> dict[str, object]:
    measured = _launcher_session(session)
    before = _route_snapshot(measured)
    observations = []
    attempted = 0
    cpu_before = _children_cpu()
    daemon: ResourceSampler | None = None
    # The daemon sampler excludes the load generator and launcher children.
    # Linux RUSAGE_CHILDREN includes reaped launchers and contained children.
    try:
        with ResourceSampler(pid=session.pid, interval_seconds=0.01) as daemon:
            for index in range(count):
                # Reset outside the launcher's timer so a child that fails
                # before reaching the daemon cannot inherit a prior trace.
                # Daemon CPU retains this fixture-control overhead in both arms.
                session.control("case_before")
                attempted += 1
                observations.append(observe_priority_launcher(measured, launcher, sample=index))
        launch_cpu = _children_cpu() - cpu_before
        after = _route_snapshot(measured, expected=sum(before.values()) + count)
        _require_native_count(before, after, count)
    except Exception as error:
        detail = failure_evidence(error)
        detail.update(
            attempted=attempted,
            completed=len(observations),
            excluded_from_comparison=True,
            partial_latency_ms=[item.latency_ms for item in observations],
            routes_before=dict(before),
            **_failed_native_attempt(session),
        )
        try:
            partial_launch_cpu = _children_cpu() - cpu_before
            detail["partial_launcher_cpu_seconds"] = partial_launch_cpu if partial_launch_cpu >= 0 else None
            if daemon is not None:
                detail["partial_daemon_resources"] = daemon.report(attempted=attempted)
        except Exception:
            detail["partial_resource_collection_failed"] = True
        raise FixtureFailureError(detail) from error
    assert daemon is not None
    resources = daemon.report(attempted=count)
    daemon_cpu = resources.get("cpu_seconds")
    complete_cpu = (
        isinstance(daemon_cpu, (int, float))
        and resources.get("short_exited_descendants_cpu_complete") is True
        and launch_cpu >= 0
    )
    values = [observation.latency_ms for observation in observations]
    return {
        "attempted": count,
        "completed": count,
        "exact_contract": True,
        "routes": {"native_resident": count},
        "latency": summarize(values),
        "latency_ms": values,
        "launcher_cpu_seconds": launch_cpu,
        "daemon_resources": resources,
        "combined_cpu_complete": complete_cpu,
        "cpu_ms_per_attempt": (launch_cpu + float(cast(float, daemon_cpu))) * 1000 / count if complete_cpu else None,
        "registration_digest": launcher.registration_sha256,
    }


def _comparison(cells: list[dict[str, object]], *, blocks: int) -> dict[str, object]:
    """Report finite point estimates; never treat small diagnostics as tail gates."""
    result: dict[str, object] = {}
    for event in EVENTS:
        rows = {
            arm: [cell for cell in cells if cell["event"] == event and cell["arm"] == arm]
            for arm in ("python", "native")
        }
        if any(len(values) != blocks for values in rows.values()):
            result[event] = {"complete": False}
            continue
        totals = {
            arm: summarize([value for cell in values for value in cast(list[float], cell["latency_ms"])])
            for arm, values in rows.items()
        }
        ratio = totals["native"]["p95_ms"] / totals["python"]["p95_ms"]
        all_cpu = all(cell["combined_cpu_complete"] is True for values in rows.values() for cell in values)
        cpu_ratio = None
        if all_cpu:
            means = {
                arm: statistics.mean(cast(float, cell["cpu_ms_per_attempt"]) for cell in values)
                for arm, values in rows.items()
            }
            if means["python"] > 0:
                cpu_ratio = means["native"] / means["python"]
        point_gate = cpu_ratio is not None and (
            (ratio <= 0.70 and cpu_ratio <= 1.05) or (cpu_ratio <= 0.70 and ratio <= 1.05)
        )
        result[event] = {
            "complete": True,
            "latency_p95_ratio": ratio,
            "cpu_mean_ratio": cpu_ratio,
            "point_improvement_gate": point_gate,
            "uncertainty_gate_evaluated": False,
            "activation_qualified": False,
        }
    return result


def run_probe(wheel: Path, *, blocks: int, samples: int, report: dict[str, object], checkpoint) -> None:
    if sys.platform != "linux" or not 1 <= blocks <= 5 or not 1 <= samples <= 100:
        raise ValueError("claude_pilot_probe_scope_invalid")
    report["phase"] = "installed_identity"
    cells = cast(list[dict[str, object]], report["cells"])
    runtime = _installed_runtime()
    distribution = importlib.metadata.distribution("hol-guard")
    installed_digest = installed_package_digest(distribution)
    if installed_digest != wheel_package_digest(wheel):
        raise RuntimeError("qualification installed package differs from supplied wheel")
    capability = json.loads(runtime.with_name("runtime-manifest.json").read_text())
    report.update(
        installed_artifact=True,
        artifact_sha256=hashlib.sha256(wheel.read_bytes()).hexdigest(),
        package_digest=installed_digest,
        build_id=capability["source_sha"],
        runtime_digest=capability["runtime_sha256"],
        blocks=blocks,
        samples_per_arm=samples,
    )
    for block in range(blocks):
        report.update(phase="daemon_setup", active_block=block)
        checkpoint()
        with DaemonFixture(runtime, setup="normal") as session:
            context = HarnessContext(
                home_dir=session.root, workspace_dir=session.workspace, guard_home=session.guard_home
            )
            configured = ClaudeCodeHarnessAdapter().install(context)
            config_path = Path(str(configured["config_path"]))
            baseline = {event: registered_launcher(config_path, "claude-code", event) for event in EVENTS}
            # Establish the exact existing allow/deny contracts before selection.
            for event in EVENTS:
                for case in ("benign", "block"):
                    report.update(phase="preflight", active_arm="python", active_event=event, active_case=case)
                    _preflight(session, baseline[event], case=case)
            record = install_private_pilot(context, qualification_root=session.root, require_native_transport=True)
            try:
                for event in EVENTS:
                    for case in ("benign", "block"):
                        launcher = _native_launcher(record, event)
                        report.update(phase="preflight", active_arm="native", active_event=event, active_case=case)
                        _preflight(session, launcher, case=case)
                restore_private_pilot(record)
                active = False
                for event in EVENTS:
                    for arm in ("python", "native") if block % 2 == 0 else ("native", "python"):
                        report.update(phase="paired_series", active_event=event, active_arm=arm, active_case="benign")
                        if arm == "native" and not active:
                            activate_private_pilot(record)
                            active = True
                        elif arm == "python" and active:
                            restore_private_pilot(record)
                            active = False
                        launcher = (
                            _native_launcher(record, event)
                            if active
                            else registered_launcher(config_path, "claude-code", event)
                        )
                        if not active and launcher != baseline[event]:
                            raise RuntimeError("qualification original launcher changed during restore")
                        cell = {"block": block, "event": event, "arm": arm, **_series(session, launcher, samples)}
                        cells.append(cell)
                        checkpoint()
            finally:
                current = load_record(record, EVENTS[0], require_registration=False)
                digest = hashlib.sha256(bounded_read(config_path)).hexdigest()
                if digest == current["registration_sha256"]:
                    restore_private_pilot(record)
                elif digest != current["original_registration_sha256"]:
                    raise RuntimeError("qualification private registration changed before restore")
                for event in EVENTS:
                    if registered_launcher(config_path, "claude-code", event) != baseline[event]:
                        raise RuntimeError("qualification original launcher restore failed")
            report["completed_blocks"] = block + 1
            checkpoint()
    report.update(phase="complete", scope_complete=True, comparison=_comparison(cells, blocks=blocks))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--blocks", type=int, default=5)
    parser.add_argument("--samples", type=int, default=30)
    args = parser.parse_args()
    report: dict[str, object] = {
        "schema": "guard-claude-installed-launcher-pilot.v1",
        "scope": "linux_c1_two_events",
        "installed_artifact": False,
        "scope_complete": False,
        "qualification_complete": False,
        "activation_qualified": False,
        "completed_blocks": 0,
        "cells": [],
        "phase": "initialize",
        "missing_scopes": [
            "c16",
            "cold_cache",
            "all_platforms",
            "frozen_signed",
            "approval_faults",
            "watch_availability_faults",
            "reference_review_faults",
            "release_tail_gates",
        ],
    }

    def checkpoint() -> None:
        sanitized = assert_privacy_safe(report)
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(sanitized, sort_keys=True, indent=2) + "\n")

    try:
        run_probe(args.wheel, blocks=args.blocks, samples=args.samples, report=report, checkpoint=checkpoint)
    except Exception as error:
        report["failure"] = failure_evidence(error)
        checkpoint()
        return 1
    checkpoint()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
