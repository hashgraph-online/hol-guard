"""``hol-guard runtime posture``: runtimes configured tools would launch, read only.

Prints the executables configured MCP servers launch with their inferred family,
version and identity assurance, matched against runtime advisories from the
locally cached, signed supply-chain bundle when one is present. Nothing is
started, no running process is enumerated, no Cloud call is made, and no
setting, approval or policy changes. Unknown stays unknown.
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
    runtime_subparsers = runtime_parser.add_subparsers(dest="runtime_command", parser_class=FriendlyArgumentParser)
    posture_parser = runtime_subparsers.add_parser(
        "posture",
        help="Show observed runtime identities and advisory coverage without running them",
    )
    _add_guard_common_args(posture_parser, suppress_defaults=True)
    posture_parser.add_argument("--json", action="store_true", default=argparse.SUPPRESS)


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
    if getattr(args, "runtime_command", None) not in (None, "posture"):
        raise ValueError(f"unsupported runtime command: {args.runtime_command}")
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
    available = isinstance(coverage, dict) and coverage.get("advisories_available") is True
    advisories = f"cached bundle {_bundle_label(payload)}" if available else f"unavailable ({reason})"
    lines.append(f"Coverage: observed_only; scope complete: no; advisories: {advisories}.")
    lines.extend(_render_advisories(payload.get("advisories")))
    lines.append("Unknown versions stay unknown. No runtime is reported safe.")
    return "\n".join(lines) + "\n"


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


__all__ = ["configure_runtime_parser", "render_runtime_posture", "run_runtime_posture_command"]
