"""Installed RSP-034 posture transition evidence, separate from latency samples."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from scripts.native_slo_contract import assert_privacy_safe
from scripts.native_slo_daemon_fixture import DaemonFixture
from scripts.native_slo_failure import failure_evidence
from scripts.native_slo_mixed_load import PrivateLedger
from scripts.native_slo_posture_witness import MAX_POSTURE_ATTEMPTS

_GROUPS = {
    "mode_round_trip": ("enforce_to_watch", "watch_restart", "watch_to_enforce"),
    "workspace_first_use": ("first_strict_workspace",),
    "publication_failure": ("failed_publication",),
    "expired_authority": ("expiry",),
}


def _pages(session: Any, ledger: PrivateLedger, group: str) -> int:
    offset = 0
    while True:
        page = session.control("posture_page", offset=offset)
        rows, total = page.get("rows"), page.get("total")
        if (
            page.get("status") != "completed"
            or not isinstance(rows, list)
            or type(total) is not int
            or not offset <= total <= MAX_POSTURE_ATTEMPTS
            or len(rows) > 32
            or offset + len(rows) > total
        ):
            raise RuntimeError("posture evidence page invalid")
        for index, row in enumerate(rows, offset):
            if not isinstance(row, Mapping) or row.get("attempt") != f"mixed-load-{index}":
                raise RuntimeError("posture evidence row invalid")
            ledger.write({"group": group, **assert_privacy_safe(row)})
        offset += len(rows)
        if offset == total:
            return offset
        if not rows:
            raise RuntimeError("posture evidence page made no progress")


def run_posture_scenarios(
    runtime: Path,
    *,
    evidence_file: Path,
    receipt_profile: str = "candidate",
    fixture_factory: Callable[..., Any] = DaemonFixture,
) -> dict[str, object]:
    """Retain each failed/unsupported arm without classifying it as a pass.

    The factory seam is for source orchestration tests only. Qualification uses
    its default real installed daemon, exact arm receipt reader and normal policy.
    Four fresh private homes isolate physical faults; only the mode round trip
    intentionally shares the same daemon across three transitions.
    """
    if receipt_profile not in {"candidate", "baseline_2e672d2"}:
        raise ValueError("posture receipt profile unsupported")
    evidence_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    ledger = PrivateLedger(evidence_file)
    proofs: dict[str, dict[str, object]] = {}
    groups: dict[str, dict[str, object]] = {}
    try:
        for group, operations in _GROUPS.items():
            result: dict[str, object] = {"passed": False, "completed_transitions": 0}
            groups[group] = result
            try:
                with fixture_factory(runtime, policy="normal") as session:
                    start = session.control("posture_start", receipt_profile=receipt_profile)
                    if start.get("status") != "completed" or start.get("starting_authority_authenticated") is not True:
                        result["start"] = start
                        raise RuntimeError("posture installed starting authority unavailable")
                    transitions = 0
                    phase_attempts = phase_native = 0
                    for operation in operations:
                        ledger.write({"group": group, "operation": operation, "state": "offered"})
                        observed = dict(session.control("posture_phase", transition=operation))
                        proofs[operation] = assert_privacy_safe(observed)
                        ledger.write({"group": group, "state": "terminal", **proofs[operation]})
                        attempted, native = observed.get("attempted"), observed.get("native_receipts")
                        if type(attempted) is not int or type(native) is not int or not 0 <= native <= attempted:
                            break
                        phase_attempts += attempted
                        phase_native += native
                        if observed.get("status") != "completed" or observed.get("passed") is not True:
                            break
                        transitions += 1
                    final = dict(session.control("posture_finish"))
                    result.update(final)
                    result["completed_transitions"] = transitions
                    result["retained_attempts"] = _pages(session, ledger, group)
                    result["phase_attempts"] = phase_attempts
                    result["phase_native_receipts"] = phase_native
                    result["passed"] = (
                        transitions == len(operations)
                        and final.get("status") == "completed"
                        and final.get("passed") is True
                        and final.get("attempted") == result["retained_attempts"]
                        and final.get("attempted") == phase_attempts
                        and final.get("native_receipts") == final.get("committed") == phase_native
                    )
                    ledger.write({"group": group, "state": "finish", **result})
            except Exception as error:
                result.update(passed=False, failure=failure_evidence(error))
                ledger.write({"group": group, "state": "failed", **result})
        return {
            "schema": "hol-guard.installed-posture-transitions.v1",
            "scope": "ordinary_http_posture_transitions",
            "passed": all(result.get("passed") is True for result in groups.values()),
            "headline_timing_eligible": False,
            "receipt_profile": receipt_profile,
            # Required proof stays flat enough to survive the actual outer
            # run_block/additional_scenarios aggregate privacy depth bound.
            "proofs": proofs,
            "groups": groups,
            "coverage": [
                "acknowledged_mode_round_trip",
                "watch_resident_restart",
                "stricter_workspace_first_use",
                "publication_generation_lock_failure",
                "authenticated_expiry",
                "concurrent_ordinary_http",
            ],
            "ordinary_tool_execution_claimed": False,
            "lock_fault_scope": "real_private_generation_lock_not_native_ack_rejection",
            "evidence": ledger.finish(),
        }
    except BaseException:
        ledger.finish()
        raise
