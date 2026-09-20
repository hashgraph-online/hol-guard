"""Run the existing installed phase workload with optional Rust diagnostics.

The native binary must already be the exact installed runtime. This entry
point does not select an ingress, replace a binary, reuse a connection, alter a
deadline or extend native shutdown. All samples are diagnostic and incomplete.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, cast

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.append(str(_ROOT))

from scripts.native_slo_daemon_fixture import DaemonFixture  # noqa: E402
from scripts.native_slo_phase_run import measure_installed_phases  # noqa: E402
from scripts.native_slo_rust_phase_receiver import NativePhaseReceiver, supported  # noqa: E402

_REQUIRED_PHASES = frozenset(
    {
        "client_connect_inclusive",
        "client_authenticate",
        "client_request_write_flush",
        "client_committed_response_read",
        "resident_evaluate_inclusive",
    }
)


def _observed_phases(native: dict[str, Any]) -> set[str]:
    return {
        phase["phase"]
        for process in native["processes"]
        if process["snapshot"] is not None
        for phase in process["snapshot"]["phases"]
        if phase["statistics"] is not None
    }


def measure_native_phases(runtime: Path, count: int, evidence_file: Path) -> dict[str, Any]:
    if type(count) is not int or not 1 <= count <= 100:
        raise ValueError("native_phase_count_outside_original_bound")
    result: dict[str, Any] = {
        "schema": "hol-guard-native-and-python-phase-run.v1",
        "scope": "diagnostic_instrumented_existing_installed_workload",
        "headline_timing_eligible": False,
        "qualification_complete": False,
        "complete_run": False,
        "status": "platform_unsupported",
        "workload_passed": False,
        "workload_failure_observed": False,
        "workload_started": False,
        "existing_fixture_failure_observed": False,
        "native_phase_error_observed": False,
        "original_phase_count_bound": 100,
        "requested_count_per_case": count,
        "original_semantic_workload": None,
        "native": None,
    }
    if not supported():
        return result
    receiver: NativePhaseReceiver | None = None
    try:
        receiver = NativePhaseReceiver(runtime)
    except Exception:
        result["native_phase_error_observed"] = True
    try:
        if receiver is not None:
            try:
                with DaemonFixture(
                    runtime, setup="normal", _native_phase_environment=receiver.environment()
                ) as session:
                    try:
                        receiver.attach(session.pid)
                    except Exception:
                        result["native_phase_error_observed"] = True
                    else:
                        result["workload_started"] = True
                        try:
                            result["original_semantic_workload"] = measure_installed_phases(
                                session, count, evidence_file
                            )
                            result["workload_passed"] = True
                        except Exception:
                            # The existing journal retains original failures;
                            # never export an exception or request value here.
                            result["workload_failure_observed"] = True
            except Exception:
                result["existing_fixture_failure_observed"] = True
    finally:
        if receiver is not None:
            try:
                receiver.close()
                result["native"] = receiver.report()
            except Exception:
                result["native_phase_error_observed"] = True
    native = cast(dict[str, Any] | None, result["native"])
    if result["existing_fixture_failure_observed"]:
        result["status"] = "existing_fixture_failed"
    elif result["workload_failure_observed"]:
        result["status"] = "workload_failed"
    elif not result["workload_started"]:
        result["status"] = "diagnostic_setup_failed"
    elif native is None or result["native_phase_error_observed"]:
        result["status"] = "diagnostic_incomplete"
    elif _REQUIRED_PHASES <= _observed_phases(native) and any(  # noqa: SIM300 - preserve operand evaluation order
        phase["phase"] in {"unix_socket_creation", "loopback_connect_handle"}
        and phase["statistics"] is not None
        and phase["statistics"]["returned_ok"] > 0
        for process in native["processes"]
        if process["snapshot"] is not None
        for phase in process["snapshot"]["phases"]
    ):
        result["status"] = "diagnostic_phases_observed"
    else:
        result["status"] = "diagnostic_incomplete"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--evidence-file", type=Path, required=True)
    parser.add_argument("--json", type=Path, required=True)
    arguments = parser.parse_args()
    report = measure_native_phases(arguments.runtime.resolve(strict=True), arguments.count, arguments.evidence_file)
    rendered = json.dumps(report, sort_keys=True, indent=2) + "\n"
    if len(rendered.encode("utf-8")) > 1024 * 1024:
        raise ValueError("native_phase_report_exceeded_bound")
    with arguments.json.open("x", encoding="utf-8") as output:
        output.write(rendered)
    print(
        json.dumps(
            {
                "schema": report["schema"],
                "status": report["status"],
                "headline_timing_eligible": False,
                "qualification_complete": False,
            },
            sort_keys=True,
        )
    )
    return 0 if report["status"] == "diagnostic_phases_observed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
