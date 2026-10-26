"""Project the native agent plugin check into workspace findings and coverage.

The native snapshot finds every Claude Code or Codex plugin manifest and Gemini
CLI extension in the worktree, reads the hooks and MCP servers each one ships
and runs them through the shared hook and MCP launch rules. It decides each
finding's stable ``finding_id``, the rule's severity and whether the check was
complete. A finding carries only the rule's fixed title and reason, the
root-relative path of the file that holds the hook or server, and the hook
event or server name, never the command, its arguments or a URL. This module
checks that shape and copies it into the stored finding; a finding that does
not match is dropped and leaves the detector incomplete instead of silently
complete.

Plugin findings are dashboard warnings. They never block or ask.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Final

PLUGIN_MANIFEST_DETECTOR: Final = "plugin_manifest_v1"
PLUGIN_MANIFEST_SOURCE_KIND: Final = "workspace_source"
PLUGINS_RESULT_SCHEMA: Final = "guard.workspace-plugins.v1"
MAX_PLUGIN_MANIFEST_FINDINGS: Final = 200

_FINDING_ID = re.compile(r"[0-9a-f]{32}")
_RULE_IDS: Final = {
    "hook": re.compile(r"hook\.config\.[a-z0-9.-]{1,120}"),
    "mcp_server": re.compile(r"mcp\.config\.[a-z0-9.-]{1,120}"),
}
_NAME_FIELDS: Final = {"hook": "event", "mcp_server": "server"}
_REASON = re.compile(r"[a-z0-9_]{1,40}")
_NAME = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
_SEVERITIES: Final = frozenset({"critical", "high", "medium", "low", "info"})
_CONFIDENCES: Final = frozenset({"weak", "likely", "strong"})
_CATEGORY = re.compile(r"[a-z_]{1,32}")
_MANIFEST_DIRECTORIES: Final = frozenset({".claude-plugin", ".codex-plugin"})
_MAX_PATH_CHARS: Final = 4096
_MAX_TEXT_CHARS: Final = 1024
_SKIP_KINDS: Final = ("oversize", "not_text", "unparsed", "unread")


def project_plugin_manifest_findings(result: object) -> list[dict[str, object]]:
    """Return the well-formed findings of a native plugin result."""

    return _projection(result)[0]


def with_plugin_manifest_coverage(coverage: dict[str, object], result: object) -> dict[str, object]:
    """Add the agent plugin detector to a run's coverage.

    A runtime without the check leaves the detector not run; a check that
    could not read every plugin file, or a malformed reply, leaves it
    incomplete. Both make the run partial. A worktree without plugins has no
    inputs.
    """

    reasons = list(_list(coverage.get("reasons")))
    summary: dict[str, object] = {}
    if result is None:
        status = "not_run"
        reasons.append(f"detector_not_run:{PLUGIN_MANIFEST_DETECTOR}")
    else:
        status, summary, truncation = _status(result)
        if status != "complete":
            reasons.append("plugin_manifest_incomplete")
        if "max_findings" in truncation and "finding_cap" not in reasons:
            reasons.append("finding_cap")
        if status == "complete" and summary.get("plugins_scanned") == 0:
            status = "no_inputs"
    detectors = coverage.get("detectors")
    return {
        **coverage,
        "status": "partial" if reasons else "complete",
        "reasons": reasons,
        "detectors": {**(detectors if isinstance(detectors, Mapping) else {}), PLUGIN_MANIFEST_DETECTOR: status},
        **({"plugin_manifest": summary} if summary else {}),
    }


def _status(result: object) -> tuple[str, dict[str, object], list[str]]:
    if not isinstance(result, Mapping) or result.get("schema") != PLUGINS_RESULT_SCHEMA:
        return "error", {}, ["unreadable_result"]
    status = result.get("status")
    # A reply without its findings list cannot show that nothing was found.
    if (
        not isinstance(status, str)
        or status not in {"complete", "incomplete"}
        or not isinstance(result.get("findings"), list)
    ):
        return "error", {}, ["unreadable_result"]
    reasons = _reasons(result.get("truncation_reasons"))
    if _projection(result)[1]:
        reasons = sorted({*reasons, "invalid_finding"})
    if status == "incomplete" and not reasons:
        reasons = ["incomplete"]
    skipped = result.get("skipped")
    summary: dict[str, object] = {
        "plugins_scanned": _count(result.get("plugins_scanned")),
        "files_scanned": _count(result.get("files_scanned")),
        "commands_scanned": _count(result.get("commands_scanned")),
        "servers_scanned": _count(result.get("servers_scanned")),
        "skipped": {kind: _count(skipped.get(kind)) if isinstance(skipped, Mapping) else 0 for kind in _SKIP_KINDS},
        "truncation_reasons": reasons,
    }
    return ("incomplete" if reasons else "complete"), summary, reasons


def _projection(result: object) -> tuple[list[dict[str, object]], int]:
    raw = result.get("findings") if isinstance(result, Mapping) else None
    if not isinstance(raw, list):
        return [], 0
    kept = raw[:MAX_PLUGIN_MANIFEST_FINDINGS]
    findings = [finding for item in kept if (finding := _finding(item)) is not None]
    return findings, len(kept) - len(findings) + max(0, len(raw) - MAX_PLUGIN_MANIFEST_FINDINGS)


def _finding(item: object) -> dict[str, object] | None:
    if not isinstance(item, Mapping):
        return None
    finding_id = item.get("finding_id")
    rule_id = item.get("rule_id")
    path = item.get("path")
    kind = item.get("kind")
    name = item.get("name")
    category = item.get("category")
    severity = item.get("severity")
    confidence = item.get("confidence")
    title = _text(item.get("title"))
    reason = _text(item.get("reason"))
    hint = item.get("false_positive_hint")
    if (
        not isinstance(finding_id, str)
        or not _FINDING_ID.fullmatch(finding_id)
        or not isinstance(kind, str)
        or kind not in _RULE_IDS
        or not isinstance(rule_id, str)
        or not _RULE_IDS[kind].fullmatch(rule_id)
        or not _is_plugin_file(path)
        or not isinstance(name, str)
        or not _NAME.fullmatch(name)
        or not isinstance(category, str)
        or not _CATEGORY.fullmatch(category)
        or not isinstance(severity, str)
        or severity not in _SEVERITIES
        or not isinstance(confidence, str)
        or confidence not in _CONFIDENCES
        or title is None
        or reason is None
        or (hint is not None and _text(hint) is None)
    ):
        return None
    return {
        "finding_id": finding_id,
        "source_kind": PLUGIN_MANIFEST_SOURCE_KIND,
        "detector": PLUGIN_MANIFEST_DETECTOR,
        "severity": severity,
        "decision": "warn",
        "ecosystem": None,
        "package_name": None,
        "package_version": None,
        "fix_version": None,
        "rule_ids": [rule_id],
        "advisory_ids": [],
        "path": path,
        "line": None,
        "component": kind,
        _NAME_FIELDS[kind]: name,
        "category": category,
        "confidence": confidence,
        "title": title,
        "reason": reason,
        "false_positive_hint": _text(hint),
        "validation_state": "unvalidated",
        "lifecycle_state": "open",
    }


def _is_plugin_file(value: object) -> bool:
    """A root-relative manifest or plugin hook or MCP file the native check keeps."""

    if not isinstance(value, str) or not 1 <= len(value) <= _MAX_PATH_CHARS or not value.isprintable() or "\\" in value:
        return False
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        return False
    name = parts[-1]
    directory = parts[-2] if len(parts) > 1 else None
    return (
        name == "gemini-extension.json"
        or (name == "plugin.json" and directory in _MANIFEST_DIRECTORIES)
        or (name == ".mcp.json" and directory is not None)
        or (directory == "hooks" and name.endswith(".json"))
    )


def _text(value: object) -> str | None:
    """Fixed rule text: one bounded printable line."""

    if not isinstance(value, str) or not 1 <= len(value) <= _MAX_TEXT_CHARS:
        return None
    return value if value.isprintable() else None


def _reasons(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({item for item in value if isinstance(item, str) and _REASON.fullmatch(item)})


def _count(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _list(value: object) -> list[object]:
    return list(value) if isinstance(value, (list, tuple)) else []


__all__ = [
    "MAX_PLUGIN_MANIFEST_FINDINGS",
    "PLUGIN_MANIFEST_DETECTOR",
    "PLUGIN_MANIFEST_SOURCE_KIND",
    "project_plugin_manifest_findings",
    "with_plugin_manifest_coverage",
]
