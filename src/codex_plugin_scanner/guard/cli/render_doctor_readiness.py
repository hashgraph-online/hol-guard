"""Doctor readiness rendering, separate from general harness detection output."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from .doctor_readiness import doctor_runtime_readiness

if TYPE_CHECKING:
    from rich.table import Table
    from rich.text import Text


def readiness_text(readiness: Mapping[str, str]) -> Text:
    from rich.text import Text

    if readiness["state"] == "fail":
        return Text("Setup broken", style="red")
    return Text("Unverified", style="yellow")


def build_doctor_harness_table(detections: list[dict[str, object]]) -> Table:
    from rich import box
    from rich.table import Table
    from rich.text import Text

    table = Table(box=box.SIMPLE_HEAVY, show_header=True)
    table.add_column("Harness", style="bold")
    table.add_column("Detection")
    table.add_column("Registration")
    table.add_column("Runtime readiness")
    table.add_column("Warnings", justify="right")
    registration_labels = {"active": "Active", "broken": "Broken", "partial": "Partial", "not_found": "Not found"}
    reason_labels = {
        "guard_setup_broken": "Check setup warnings",
        "hook_registration_unconfirmed": "Registration incomplete",
        "harness_probe_failed": "CLI check failed",
        "harness_probe_timed_out": "CLI check timed out",
        "harness_probe_not_run": "CLI check not run",
        "hook_evaluation_unverified": "No Guard decision verified",
    }
    for detection in detections:
        readiness = doctor_runtime_readiness(detection)
        reason_code = readiness["reason_code"]
        # Global JSON keeps the classified result; it omits raw CLI output.
        projected = detection.get("runtime_readiness")
        if readiness["state"] == "unknown" and isinstance(projected, Mapping) and projected.get("state") == "unknown":
            reason = projected.get("reason_code")
            if isinstance(reason, str) and reason in reason_labels:
                reason_code = reason
        value = readiness_text(readiness)
        label = reason_labels.get(reason_code)
        if label:
            value.append(f"\n{label}")
        warnings = detection.get("warnings")
        table.add_row(
            Text(str(detection.get("harness", "unknown"))),
            "Found" if detection.get("installed") else "Not found",
            registration_labels.get(str(detection.get("setup_status")), "Not checked"),
            value,
            str(len(warnings) if isinstance(warnings, list) else 0),
        )
    return table
