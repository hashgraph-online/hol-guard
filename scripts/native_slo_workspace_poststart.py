"""Bounded Linux poststart workspace and same-home service replacement diagnostic.

Initial compilation is excluded. The two service instances share one Python
process and one owned home. Full typed observations stay in the private ledger;
this diagnostic does not provide installed SLO or platform qualification.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.bench_guard_native_installed_slo_runtime import _clear_proof_overrides, _runtime_summary
from scripts.native_slo_workspace_poststart_evidence import RetainedLedger, encode_retained
from scripts.native_slo_workspace_poststart_observation import PostStartObservation, stricter_overlay
from scripts.native_slo_workspace_poststart_session import COUNTS, PersistentWorkspaceHome, diagnostic_failure
from scripts.native_slo_workspace_trace import validate_trace


def service(home: PersistentWorkspaceHome, ordinal: int, ledger: RetainedLedger) -> dict[str, Any]:
    count = len(home.workspaces)
    result: dict[str, Any] = {
        "index": ordinal,
        "status": "offered",
        "passed": False,
        "phase_results": [],
        "qualification_complete": False,
    }
    session = observation = None
    try:
        if not ledger.write(
            {
                "kind": "poststart_service_offer",
                "registered_workspaces": count,
                "instance": ordinal,
            }
        ):
            raise RuntimeError("poststart service offer retention unavailable")
        session = home.start_instance()
        result["status"] = "constructed"
        result["ready"] = session.ready()
        result["status"] = "ready"
        phases = ("poststart_registration", "public_policy") if ordinal == 0 else ("explicit_reregistration",)
        observation = PostStartObservation(session, instance=ordinal)
        with observation:
            for name in phases:
                phase: dict[str, Any] = {"name": name, "status": "offered", "passed": False}
                result["phase_results"].append(phase)
                try:
                    if not ledger.write(
                        {
                            "kind": "poststart_phase_offer",
                            "registered_workspaces": count,
                            "instance": ordinal,
                            "phase": name,
                        }
                    ):
                        raise RuntimeError("poststart phase offer retention unavailable")
                    phase.update(observation.phase(name))
                except BaseException as error:
                    phase.update(status="failed", failure=diagnostic_failure(error))
                finally:
                    ledger.write(
                        {
                            "kind": "poststart_phase_terminal",
                            "registered_workspaces": count,
                            "instance": ordinal,
                            "phase": phase,
                        }
                    )
                if phase["passed"] is not True:
                    break
        if observation.final is None:
            raise RuntimeError("poststart observer final record is missing")
        for row in observation.final["rows"]:
            ledger.write(
                {
                    "kind": "poststart_publisher_event",
                    "registered_workspaces": count,
                    "instance": ordinal,
                    "event": row,
                }
            )
        validate_trace(observation.final["rows"], observation.final["observer"])
    except BaseException as error:
        result["failure"] = diagnostic_failure(error)
    finally:
        if observation is not None:
            if observation.final is None:
                try:
                    observation.close()
                except BaseException as error:
                    result["observation_final_failure"] = diagnostic_failure(error)
            result["observation"] = observation.final
        if session is not None:
            try:
                result["retirement"] = session.stop()
            except BaseException as error:
                result["retirement"] = {
                    "passed": False,
                    "status": "stop_observation_incomplete",
                    "retained": session.retirement,
                    "failure": diagnostic_failure(error),
                }
        else:
            result["retirement"] = {"passed": False, "status": "construction_not_complete"}
        result["status"] = "finished"
        result["passed"] = (
            "failure" not in result
            and "observation_final_failure" not in result
            and observation is not None
            and observation.final is not None
            and observation.final["passed"] is True
            and result["retirement"]["passed"] is True
            and not ledger.errors
        )
        try:
            ledger.write(
                {
                    "kind": "poststart_service_terminal",
                    "registered_workspaces": count,
                    "instance": result,
                }
            )
        except BaseException as error:
            result.update(passed=False, retention_failure=diagnostic_failure(error))
    return result


def cell(runtime: Path, count: int, ledger: RetainedLedger) -> dict[str, Any]:
    result: dict[str, Any] = {
        "registered_workspaces": count,
        "passed": False,
        "instances": [],
        "qualification_complete": False,
        "scope": "poststart registration and same-process service replacement on one owned home",
    }
    home = None
    try:
        if not ledger.write({"kind": "poststart_cell_offer", "registered_workspaces": count}):
            raise RuntimeError("poststart cell offer retention unavailable")
        home = PersistentWorkspaceHome(runtime, count)
        for ordinal in (0, 1):
            if ordinal == 1:
                result["stricter_overlay"] = stricter_overlay(home)
                ledger.write(
                    {
                        "kind": "poststart_stricter_overlay",
                        "registered_workspaces": count,
                        **result["stricter_overlay"],
                    }
                )
            instance = service(home, ordinal, ledger)
            result["instances"].append(instance)
            if instance["passed"] is not True:
                break
        result["passed"] = len(result["instances"]) == 2 and all(row["passed"] is True for row in result["instances"])
    except BaseException as error:
        result.update(passed=False, failure=diagnostic_failure(error))
    finally:
        if home is not None:
            try:
                result["home_cleanup"] = home.finish()
                if result["home_cleanup"]["contained"] is not True:
                    result["passed"] = False
            except BaseException as error:
                result["passed"] = False
                result["home_cleanup_failure"] = diagnostic_failure(error)
        else:
            result["home_cleanup"] = {
                "contained": False,
                "status": "home_construction_not_complete",
                "root_removal_observed": False,
            }
        result["unoffered_service_instances"] = 2 - len(result["instances"])
        result["unconstructed_service_instances"] = 2 - (len(home.instances) if home is not None else 0)
        try:
            ledger.write(
                {
                    "kind": "poststart_cell_terminal",
                    "registered_workspaces": count,
                    "passed": result["passed"],
                    "result": result,
                }
            )
        except BaseException as error:
            result.update(passed=False, retention_failure=diagnostic_failure(error))
    return result


def run(runtime: Path, *, raw_file: Path, counts: tuple[int, ...] = COUNTS) -> dict[str, Any]:
    if sys.flags.optimize:
        raise ValueError("poststart diagnostic requires active invariant checks")
    if counts != COUNTS:
        raise ValueError("poststart diagnostic requires the complete ordered 1/10/100 matrix")
    _clear_proof_overrides()
    identity = _runtime_summary(runtime)
    ledger = RetainedLedger(raw_file)
    cells = []
    failure = None
    try:
        ledger.write(
            {
                "kind": "poststart_matrix_offer",
                "counts": counts,
                "identity": identity,
                "qualification_complete": False,
            }
        )
        for count in counts:
            observed = cell(runtime, count, ledger)
            cells.append(observed)
            if observed["passed"] is not True or ledger.errors:
                break
    except BaseException as error:
        failure = diagnostic_failure(error)
    finally:
        raw = ledger.finish()
    result = {
        "scope": "bounded Linux poststart workspace observation",
        "identity": identity,
        "declared_counts": counts,
        "cells": cells,
        "unvisited_counts": list(counts[len(cells) :]),
        "failure": failure,
        "ledger": raw,
        "implemented_diagnostic_passed": (
            failure is None
            and raw["complete"] is True
            and len(cells) == len(counts)
            and all(row["passed"] is True for row in cells)
        ),
        "initial_compilation_observed": False,
        "same_process_service_replacement": True,
        "python_process_restart_tested": False,
        "automatic_workspace_restore_tested": False,
        "headline_timing_eligible": False,
        "qualification_complete": False,
        "pending": [
            "full installed sampling and paired baselines",
            "lost metadata hints",
            "key rotation",
            "expiry fault",
            "first admission fault",
            "Python process restart",
            "matched platform hardware",
        ],
    }
    encode_retained(result)
    return result


def main() -> int:
    from codex_plugin_scanner.guard.native_runtime import native_runtime_status

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    _clear_proof_overrides()
    status = native_runtime_status()
    if status.identity is None:
        raise RuntimeError("installed native runtime is unavailable")
    args.ledger.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        result = run(status.identity.path, raw_file=args.ledger)
    except BaseException as error:
        result = {
            "implemented_diagnostic_passed": False,
            "qualification_complete": False,
            "failure": diagnostic_failure(error),
            "complete_report_available": False,
        }
    descriptor = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as destination:
        destination.write(encode_retained(result) + b"\n")
        destination.flush()
        os.fsync(destination.fileno())
    print(
        json.dumps(
            {
                "implemented_diagnostic_passed": result["implemented_diagnostic_passed"],
                "qualification_complete": False,
            }
        )
    )
    return 0 if result["implemented_diagnostic_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
