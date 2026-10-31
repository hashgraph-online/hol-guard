"""``hol-guard runtime``: what tools launch, and what Guard's own runtime looks like.

``runtime posture`` describes the runtimes configured tools would launch.
``runtime status`` describes Guard's own native runtime: whether it is
available here and whether a resident is already running on this account.
Both are read only.

Prints the executables configured MCP servers launch with their inferred family,
version and identity assurance, matched against runtime advisories from the
locally cached, signed supply-chain bundle when one is present. Nothing is
started, no Cloud call is made, and no setting, approval or policy changes.
Unknown stays unknown.

``--instances`` additionally asks the native probe which of those runtimes are
running here and carries what it saw into the Guard home, so a later probe can
still name a process whose launch path it no longer covers. That reads other
processes and writes a file, so it is left off by default and reviewed like any
other command that does.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from typing import TYPE_CHECKING, TextIO

from ...argparse_utils import FriendlyArgumentParser
from .commands_parser_helpers import _add_guard_common_args

if TYPE_CHECKING:
    from ..adapters.base import HarnessContext


def configure_runtime_parser(guard_subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    runtime_parser = guard_subparsers.add_parser(
        "runtime",
        help="Inspect the runtimes configured tools launch with (read only)",
    )
    _add_guard_common_args(runtime_parser)
    runtime_parser.add_argument("--json", action="store_true")
    runtime_parser.add_argument("--instances", action="store_true")
    runtime_subparsers = runtime_parser.add_subparsers(dest="runtime_command", parser_class=FriendlyArgumentParser)
    posture_parser = runtime_subparsers.add_parser(
        "posture",
        help="Show observed runtime identities and advisory coverage without running them",
    )
    _add_guard_common_args(posture_parser, suppress_defaults=True)
    posture_parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    posture_parser.add_argument("--instances", action="store_true", default=argparse.SUPPRESS)
    status_parser = runtime_subparsers.add_parser(
        "status",
        help="Show whether Guard's own native runtime is available and whether a resident is running",
    )
    _add_guard_common_args(status_parser, suppress_defaults=True)
    status_parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS)


def run_runtime_posture_command(
    args: argparse.Namespace,
    *,
    context: HarnessContext,
    output_stream: TextIO | None = None,
) -> int:
    from ..adapters.harness_mcp_discovery import configured_harness_detections
    from ..runtime_advisory_bundle import BUNDLE_UNREADABLE, cached_advisory_bundle
    from ..runtime_posture import build_runtime_posture
    from ..store import GuardStore

    stream = output_stream if output_stream is not None else sys.stdout
    runtime_command = getattr(args, "runtime_command", None)
    if runtime_command == "status":
        return run_runtime_status_command(args, context=context, output_stream=stream)
    if runtime_command not in (None, "posture"):
        raise ValueError(f"unsupported runtime command: {runtime_command}")
    skipped: list[str] = []
    detections = configured_harness_detections(
        context.home_dir, context.guard_home, context.workspace_dir, skipped=skipped
    )
    try:
        advisory_bundle, bundle_reason = cached_advisory_bundle(GuardStore(context.guard_home))
    except Exception:
        # A locked or damaged store costs the advisories, not the observation.
        advisory_bundle, bundle_reason = None, BUNDLE_UNREADABLE
    payload = build_runtime_posture(
        detections,
        generated_at=datetime.now(timezone.utc).isoformat(),
        workspace_dir=context.workspace_dir,
        skipped_harnesses=skipped,
        advisory_bundle=advisory_bundle,
        advisory_bundle_reason=bundle_reason,
        # Enumerating running processes and keeping what was seen is a read of
        # more than this command's own subject, so it waits to be asked for.
        instance_home=context.guard_home if getattr(args, "instances", False) else None,
    )
    if getattr(args, "json", False):
        stream.write(json.dumps(payload, indent=2, sort_keys=True))
        stream.write("\n")
    else:
        stream.write(render_runtime_posture(payload))
    # Anything short of a complete observation is a failure for automation.
    return 0 if payload["status"] == "ok" else 1


def render_runtime_posture(payload: dict[str, object]) -> str:
    coverage = payload.get("coverage")
    reason = coverage.get("reason") if isinstance(coverage, dict) else None
    lines = ["Runtime posture (read only)"]
    if payload["status"] == "unavailable":
        lines.append(f"Unavailable: {payload.get('error')}. The native runtime could not inspect executables.")
    elif payload["status"] == "partial":
        lines.append(f"Partial: {payload.get('error')}. Some of what follows could not be determined.")
    skipped = payload.get("skipped_harnesses")
    if isinstance(skipped, list) and skipped:
        lines.append(f"  Configuration could not be read for: {', '.join(str(name) for name in skipped)}")
    runtimes = payload.get("runtimes")
    rows = runtimes if isinstance(runtimes, list) else []
    if not rows and payload["status"] == "ok":
        lines.append("No configured MCP server launch executables were found.")
    for row in rows:
        lines.extend(_render_row(row))
    unresolved = payload.get("unresolved_launches")
    for item in unresolved if isinstance(unresolved, list) else []:
        label = "configured path not found" if item.get("lookup") == "configured_path" else "not found on PATH"
        lines.append(f"  {label}: {item['command']} ({item['harness']} / {item['server']})")
    if payload.get("candidate_limit_reached"):
        lines.append("  Candidate limit reached; some launch executables were not inspected.")
    lines.extend(_render_instances(payload.get("instances")))
    available = isinstance(coverage, dict) and coverage.get("advisories_available") is True
    advisories = f"cached bundle {_bundle_label(payload)}" if available else f"unavailable ({reason})"
    lines.append(f"Coverage: observed_only; scope complete: no; advisories: {advisories}.")
    lines.extend(_render_advisories(payload.get("advisories")))
    lines.append("Unknown versions stay unknown. No runtime is reported safe.")
    return "\n".join(lines) + "\n"


def _render_instances(summary: object) -> list[str]:
    if not isinstance(summary, dict) or summary.get("enumerated") is not True:
        return []
    line = f"  Running processes seen: {summary['running']}"
    if summary.get("unidentified"):
        line += f", {summary['unidentified']} started from a file replaced since (version unknown)"
    if summary.get("exited"):
        line += f"; {summary['exited']} seen earlier have exited"
    lines = [line + "."]
    if summary.get("unbound_processes"):
        lines.append(f"  {summary['unbound_processes']} processes could not be identified by start time.")
    if summary.get("limit_reached"):
        lines.append("  Instance limit reached; some processes were not listed.")
    if summary.get("assessed") is not True:
        reason = summary.get("assessment_error") or "not assessed"
        lines.append(f"  Processes could not be assessed against advisories ({reason}); files were assessed alone.")
    return lines


def _render_row(row: object) -> list[str]:
    if not isinstance(row, dict):
        return []
    family = row.get("family") or "unknown"
    version = row.get("version") or "unknown version"
    detail = f"{family} {version}, assurance {row['identity_assurance']}"
    if row["location_state"] != "present":
        detail = f"{row['location_state']}" + (f" ({row['reason']})" if row.get("reason") else "")
    lines = [f"  {row['path']}", f"    {detail}"]
    launched = row.get("launched_by")
    users = sorted({f"{item['harness']}/{item['server']}" for item in launched}) if isinstance(launched, list) else []
    if users:
        lines.append(f"    launched by: {', '.join(users)}")
    return lines


def _bundle_label(payload: dict[str, object]) -> str:
    source = payload.get("advisory_source")
    version = source.get("bundle_version") if isinstance(source, dict) else None
    return str(version) if version else "(unversioned)"


def _render_advisories(advisories: object) -> list[str]:
    rows = [row for row in advisories if isinstance(row, dict)] if isinstance(advisories, list) else []
    lines: list[str] = []
    for row in rows:
        verdict = row.get("verdict")
        # Only advisories that still need attention are listed.
        if verdict in ("not_affected", "not_observed", "fixed_verified"):
            continue
        severity = f" [{row['severity']}]" if row.get("severity") else ""
        exploited = " known exploited" if row.get("known_exploited") else ""
        reasons = row.get("reasons")
        why = ", ".join(str(item) for item in reasons) if isinstance(reasons, list) and reasons else "unknown"
        label = f"undetermined ({why})" if verdict == "unknown" else str(verdict).replace("_", " ")
        title = f": {row['title']}" if row.get("title") else ""
        lines.append(f"  {row['advisory_id']}{severity}{exploited} {label}{title}")
    return lines


__all__ = [
    "configure_runtime_parser",
    "render_runtime_posture",
    "render_runtime_status",
    "run_runtime_posture_command",
    "run_runtime_status_command",
]


def run_runtime_status_command(
    args: argparse.Namespace,
    *,
    context: HarnessContext,
    output_stream: TextIO | None = None,
) -> int:
    """``hol-guard runtime status``: what Guard's own native runtime looks like from here.

    This reads the installed binary's identity, the passive availability probe
    and the shared resident state files. It starts nothing, stops nothing and
    reaches no network, and it produces no verdict of its own.
    """

    from ..adapters.diagnostic_probes import without_command_probes
    from .doctor_native_runtime import native_runtime_section

    stream = output_stream if output_stream is not None else sys.stdout
    # The read-only contract is enforced here, not assumed: inside this scope a
    # probe is recorded as skipped instead of launching the runtime, so neither
    # the capabilities call nor the execute-bit repair behind it can run.
    with without_command_probes():
        section = native_runtime_section(context.guard_home)
    payload = {"generated_at": datetime.now(timezone.utc).isoformat(), "native_runtime": section}
    if getattr(args, "json", False):
        stream.write(json.dumps(payload, indent=2, sort_keys=True))
        stream.write("\n")
    else:
        stream.write(render_runtime_status(section))
    availability = section["availability"]
    # No runtime binary installed is a real failure; an unknown compatibility is not.
    return 1 if isinstance(availability, dict) and availability.get("available") is False else 0


def render_runtime_status(section: dict[str, object]) -> str:
    availability = section.get("availability")
    availability = availability if isinstance(availability, dict) else {}
    lines = ["Native runtime status (read only)"]
    lines.append(
        f"  Mode: {availability.get('mode', 'unknown')}; "
        f"available: {_tristate(availability.get('available'))}; "
        f"compatible: {_tristate(availability.get('compatible'))} "
        f"({availability.get('reason_code', 'unknown')})"
    )
    if availability.get("compatible") is None:
        # Say why the answer stops here rather than leaving a bare "unknown".
        lines.append(
            "  Compatibility is not reported: this command reads the installed files and "
            "never runs them. Run `hol-guard doctor <harness>` for the full check."
        )
    message = availability.get("message")
    if isinstance(message, str) and message:
        lines.append(f"  {message}")
    lines.extend(_render_diagnosis(section.get("diagnosis"), reported=message if isinstance(message, str) else None))
    lines.extend(_render_resident(section.get("resident")))
    lines.extend(_render_restart(section.get("restart")))
    bundled = section.get("bundled")
    if isinstance(bundled, dict):
        lines.append(f"  Bundled runtime: {bundled.get('status', 'unknown')}")
        bundled_message = bundled.get("message")
        if isinstance(bundled_message, str) and bundled_message:
            lines.append(f"    {bundled_message}")
    lines.append(f"  Daemon HTTP gate, this process: {_render_counters(section.get('daemon_http'))}")
    lines.append("Those counters cover this command only. The hook and the daemon keep their own.")
    return "\n".join(lines) + "\n"


def _render_diagnosis(diagnosis: object, *, reported: str | None) -> list[str]:
    """Print the plain-language diagnosis under the reason code it explains.

    The summary is skipped only when the availability line above it already
    carried that same text, so a shared resident is explained once rather than
    twice while a diagnosis that says something else is still printed. The
    action and the per-slot evidence are printed either way.
    """

    if not isinstance(diagnosis, dict):
        return []
    lines: list[str] = []
    summary = diagnosis.get("summary")
    if isinstance(summary, str) and summary and summary != reported:
        lines.append(f"  {summary}")
    action = diagnosis.get("action")
    if isinstance(action, str) and action:
        lines.append(f"  What to do: {action}")
    candidates = diagnosis.get("candidates")
    rows = [item for item in candidates if isinstance(item, dict)] if isinstance(candidates, list) else []
    if rows:
        found = ", ".join(f"{row.get('slot', 'unknown')} {row.get('state', 'unknown')}" for row in rows)
        lines.append(f"  Runtime binary, by install slot: {found}.")
    return lines


def _render_resident(resident: object) -> list[str]:
    if not isinstance(resident, dict):
        return []
    live = resident.get("live")
    if live is None:
        return ["  Resident on this account: unknown (no runtime identity to match)"]
    state = "running" if live else "not running"
    lock = resident.get("owner_lock_held")
    owner = "owner lock unreadable" if lock is None else ("owner lock held" if lock else "owner lock free")
    return [f"  Resident on this account: {state} ({owner}, {resident.get('generations', 0)} recorded generations)"]


def _render_restart(restart: object) -> list[str]:
    """Say whether the shared restart budget is currently refusing a respawn.

    Printed whichever way it answers. A clean budget is worth a line because
    the absence of one is ambiguous -- a home where no resident ever restarted
    and a home whose budget could not be read both print nothing -- while a
    paused one is the reason an otherwise healthy install is enforcing nothing.
    """

    if not isinstance(restart, dict):
        return []
    attempts = restart.get("attempts", 0)
    if not restart.get("paced"):
        return [f"  Restarts on this account: not paused ({attempts} recorded in this window)"]
    return [
        f"  Restarts on this account: paused ({attempts} recorded in this window); "
        f"the next one is allowed in {restart.get('retry_in_seconds', 0)}s"
    ]


def _render_counters(counters: object) -> str:
    if not isinstance(counters, dict) or not counters:
        return "no counters recorded"
    return ", ".join(f"{key} {counters[key]}" for key in sorted(counters))


def _tristate(value: object) -> str:
    if value is None:
        return "unknown"
    return "yes" if value else "no"
