"""Doctor readiness rendering, separate from general harness detection output."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING

from .doctor_readiness import doctor_runtime_readiness

if TYPE_CHECKING:
    from rich.table import Table
    from rich.text import Text


# Labels for the native runtime's per-event protection proof states. They must
# match tests/fixtures/harness-protection-states.v1.json, which the dashboard
# and the runtime also test against. Anything else renders as unknown.
PROTECTION_STATE_LABELS: dict[str, tuple[str, str]] = {
    "configured": ("Configured, not proven", "yellow"),
    "transport_ready": ("Hook answers, block not proven", "yellow"),
    "live_block_proven": ("Live block proven", "green"),
    "live_allow_proven": ("Live allow proven, block not proven", "yellow"),
    "observe_only": ("Observe only", "cyan"),
    "partial": ("Partly proven", "yellow"),
    "unsupported": ("Not supported", "red"),
    "stale": ("Evidence out of date", "red"),
}
UNKNOWN_PROTECTION_LABEL = "Protection unknown"


def protection_state_text(state: object) -> Text:
    from rich.text import Text

    known = PROTECTION_STATE_LABELS.get(state) if isinstance(state, str) else None
    label, style = known or (UNKNOWN_PROTECTION_LABEL, "yellow")
    return Text(label, style=style)


def _event_name(entry: Mapping[str, object]) -> str:
    """The event name, with its tools when the contract splits the event by tool."""

    tools = entry.get("tools")
    named = [tool for tool in tools if isinstance(tool, str) and tool] if isinstance(tools, list) else []
    return f"{entry['event']} [{', '.join(named)}]" if named else str(entry["event"])


def protection_proof_rows(compatibility: object) -> list[tuple[str, Text]]:
    """Summary rows for one harness: the overall proof state, then each event."""

    payload = compatibility if isinstance(compatibility, Mapping) else {}
    rows = [("Protection proof", protection_state_text(payload.get("protection_state")))]
    events = payload.get("event_states")
    entries = [
        entry
        for entry in (events if isinstance(events, list) else [])
        if isinstance(entry, Mapping) and isinstance(entry.get("event"), str)
    ]
    names = [_event_name(entry) for entry in entries]
    repeated = {name for name in names if names.count(name) > 1}
    for entry, name in zip(entries, names, strict=True):
        transport = entry.get("transport")
        if name in repeated and isinstance(transport, str) and transport:
            name = f"{name} ({transport})"
        rows.append((f"  {name}", protection_state_text(entry.get("state"))))
    return rows


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
