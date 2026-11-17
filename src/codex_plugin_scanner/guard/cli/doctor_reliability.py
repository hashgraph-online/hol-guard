"""`hol-guard doctor reliability`: the native daemon reliability report, rendered.

The native runtime reads the lifecycle journal, the failed-launch log and the
crash reports and does all of the counting; this module only names the crash
report directory for the platform and turns the answer into text.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO, cast

from ..native_daemon_manage import daemon_reliability_report

DEFAULT_DAYS = 30
_COUNTED_CRASH_STATUSES = frozenset({"ok", "scan_limit", "incomplete"})
_LAUNCH_NOTES = {
    "no_failures_recorded": " (no failures recorded)",
    "log_unreadable": " (a failure log could not be read safely; counts are partial)",
}


def crash_reports_directory(home_dir: Path) -> Path | None:
    """Where macOS keeps crash reports for this user; other platforms have none Guard reads."""

    if sys.platform != "darwin":
        return None
    return home_dir / "Library" / "Logs" / "DiagnosticReports"


def reliability_report(guard_home: Path, *, home_dir: Path, days: int = DEFAULT_DAYS) -> dict[str, object]:
    return daemon_reliability_report(
        guard_home,
        days=days,
        crash_reports_dir=crash_reports_directory(home_dir),
        processes=True,
    )


def _section(report: Mapping[str, object], key: str) -> Mapping[str, object]:
    value = report.get(key)
    return cast("Mapping[str, object]", value) if isinstance(value, Mapping) else {}


def _counts(value: object) -> list[tuple[str, int]]:
    if not isinstance(value, Mapping):
        return []
    items = cast("Mapping[str, object]", value).items()
    return [(str(name), count) for name, count in items if isinstance(count, int)]


def _day(value: object) -> str:
    if not isinstance(value, int) or value <= 0:
        return "none"
    return datetime.fromtimestamp(value / 1_000_000_000, tz=timezone.utc).strftime("%Y-%m-%d")


def _block(lines: list[str], title: str, total: object, rows: list[tuple[str, int]], empty: str = "") -> None:
    lines.append(f"{title}: {total if isinstance(total, int) else 0}{empty}")
    lines.extend(f"  {name}  {count}" for name, count in rows)


def render_reliability_report(report: Mapping[str, object]) -> str:
    window = _section(report, "window")
    lines = [f"Guard daemon reliability, last {window.get('days', DEFAULT_DAYS)} days", ""]

    exits = _section(report, "daemon_exits")
    _block(lines, "Daemon exits", exits.get("total"), _counts(exits.get("by_cause")))
    starts = _counts(report.get("ready_per_day"))
    lines.append(f"Daemon starts: {sum(count for _, count in starts)}")
    lines.extend(f"  {day}  {count}" for day, count in starts)

    launches = _section(report, "failed_launches")
    _block(
        lines,
        "Failed launches",
        launches.get("total"),
        _counts(launches.get("by_code")),
        _LAUNCH_NOTES.get(str(launches.get("status")), ""),
    )

    crashes = _section(report, "crash_reports")
    if crashes.get("status") in _COUNTED_CRASH_STATUSES:
        # A partial scan still shows what it counted, marked so it is not
        # read as the whole directory.
        partial = "" if crashes.get("status") == "ok" else f" ({crashes.get('status')}, partial)"
        lines.append(f"Crash reports: {crashes.get('total', 0)}{partial}")
        for label, key in (("by origin", "by_origin"), ("by stack", "by_stack")):
            rows = _counts(crashes.get(key))
            if rows:
                lines.append(f"  {label}: " + ", ".join(f"{name} {count}" for name, count in rows))
    else:
        lines.append(f"Crash reports: {crashes.get('status', 'not_checked')}")

    repairs = _section(report, "repairs")
    lines.append(f"Repairs run: {repairs.get('total', 0)}")
    recovery = _section(report, "recovery_requests")
    _block(lines, "Recovery requests", recovery.get("total"), _counts(recovery.get("by_reason")))

    orphaned = _section(report, "orphaned_daemons")
    pids = orphaned.get("pids")
    if orphaned.get("status") == "known":
        known = [str(pid) for pid in cast("list[object]", pids)] if isinstance(pids, list) else []
        listed = ", ".join(known) or "none"
        lines.append(f"Daemons besides the published one: {listed}")
    else:
        lines.append(f"Daemons besides the published one: {orphaned.get('status', 'unknown')}")

    journal = _section(report, "journal")
    lines.extend(
        [
            "",
            (
                f"Journal: {journal.get('status', 'journal_unavailable')}; "
                + f"lifecycle records from {_day(journal.get('lifecycle_oldest_ns'))}, "
                + f"recovery records from {_day(journal.get('recovery_oldest_ns'))}"
            ),
        ]
    )
    return "\n".join(lines) + "\n"


def run_reliability_command(
    args: argparse.Namespace,
    *,
    guard_home: Path,
    home_dir: Path,
    output_stream: TextIO | None = None,
) -> int:
    """Reads only: nothing is started, repaired or signalled, so it runs before the lifecycle gate."""

    report = reliability_report(guard_home, home_dir=home_dir, days=int(getattr(args, "days", DEFAULT_DAYS)))
    stream = output_stream if output_stream is not None else sys.stdout
    if getattr(args, "json", False):
        _ = stream.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    else:
        _ = stream.write(render_reliability_report(report))
    return 0


__all__ = [
    "crash_reports_directory",
    "reliability_report",
    "render_reliability_report",
    "run_reliability_command",
]
