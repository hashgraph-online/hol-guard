"""Project the native MCP configuration check into workspace findings and coverage.

The runtime decides each finding's stable ``finding_id`` and the rule's
severity. A finding carries only the rule's fixed title and reason, the
root-relative path of the configuration file and the server's name, never the
server's command or URL. This module checks that shape and copies it into the
stored finding; a finding that does not match is dropped and leaves the
detector incomplete instead of silently complete.

MCP configuration findings are dashboard warnings. They never block or ask.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

MCP_CONFIG_DETECTOR: Final = "mcp_config_v1"
MCP_CONFIG_SOURCE_KIND: Final = "workspace_source"
MCP_CONFIG_RESULT_SCHEMA: Final = "guard.workspace-mcp-config.v1"
MAX_MCP_CONFIG_FINDINGS: Final = 200

_FINDING_ID = re.compile(r"[0-9a-f]{32}")
_RULE_ID = re.compile(r"mcp\.config\.[a-z0-9.-]{1,120}")
_REASON = re.compile(r"[a-z0-9_]{1,40}")
_SEVERITIES: Final = frozenset({"critical", "high", "medium", "low", "info"})
_CONFIDENCES: Final = frozenset({"weak", "likely", "strong"})
_CATEGORY = re.compile(r"[a-z_]{1,32}")
_MAX_PATH_CHARS: Final = 4096
_MAX_TEXT_CHARS: Final = 1024
_LOGGER = logging.getLogger(__name__)


def assess_workspace_mcp_configs(store: Any, root: Path) -> dict[str, object] | None:
    """The MCP configuration result for ``root``, or ``None`` when the runtime lacks the check.

    Harnesses Guard could not read are added as a truncation reason, since a
    server they configure went unchecked. A failure is an unreadable result.
    """

    from .native_workspace_mcp_config import McpConfigUnavailableError, assess_mcp_servers, workspace_mcp_servers

    try:
        found = workspace_mcp_servers(store, root)
        result = assess_mcp_servers(found)
    except McpConfigUnavailableError:
        return None
    except Exception as error:
        _LOGGER.debug("workspace MCP configuration check failed: %s", type(error).__name__)
        return {"schema": "unreadable"}
    reasons = result.get("truncation_reasons")
    if found.skipped_harnesses and isinstance(reasons, list):
        result = {**result, "status": "incomplete", "truncation_reasons": [*reasons, "harness_unreadable"]}
    return result


def project_mcp_config_findings(result: object) -> list[dict[str, object]]:
    """Return the well-formed findings of a native MCP configuration result."""

    return _projection(result)[0]


def with_mcp_config_coverage(coverage: dict[str, object], result: object) -> dict[str, object]:
    """Add the MCP configuration detector to a run's coverage.

    A runtime without the check leaves the detector not run; a check that
    could not read every server, or a malformed reply, leaves it incomplete.
    Both make the run partial. A worktree that configures no servers has no
    inputs.
    """

    reasons = list(_list(coverage.get("reasons")))
    summary: dict[str, object] = {}
    if result is None:
        status = "not_run"
        reasons.append(f"detector_not_run:{MCP_CONFIG_DETECTOR}")
    else:
        status, summary, truncation = _status(result)
        if status != "complete":
            reasons.append("mcp_config_incomplete")
        if "max_findings" in truncation and "finding_cap" not in reasons:
            reasons.append("finding_cap")
        if status == "complete" and summary.get("servers_scanned") == 0:
            status = "no_inputs"
    detectors = coverage.get("detectors")
    return {
        **coverage,
        "status": "partial" if reasons else "complete",
        "reasons": reasons,
        "detectors": {**(detectors if isinstance(detectors, Mapping) else {}), MCP_CONFIG_DETECTOR: status},
        **({"mcp_config": summary} if summary else {}),
    }


def _status(result: object) -> tuple[str, dict[str, object], list[str]]:
    if not isinstance(result, Mapping) or result.get("schema") != MCP_CONFIG_RESULT_SCHEMA:
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
        "servers_scanned": _count(result.get("servers_scanned")),
        "skipped": {"oversize": _count(skipped.get("oversize")) if isinstance(skipped, Mapping) else 0},
        "truncation_reasons": reasons,
    }
    return ("incomplete" if reasons else "complete"), summary, reasons


def _projection(result: object) -> tuple[list[dict[str, object]], int]:
    raw = result.get("findings") if isinstance(result, Mapping) else None
    if not isinstance(raw, list):
        return [], 0
    kept = raw[:MAX_MCP_CONFIG_FINDINGS]
    findings = [finding for item in kept if (finding := _finding(item)) is not None]
    return findings, len(kept) - len(findings) + max(0, len(raw) - MAX_MCP_CONFIG_FINDINGS)


def _finding(item: object) -> dict[str, object] | None:
    if not isinstance(item, Mapping):
        return None
    finding_id = item.get("finding_id")
    rule_id = item.get("rule_id")
    path = item.get("path")
    server = _text(item.get("server"))
    category = item.get("category")
    severity = item.get("severity")
    confidence = item.get("confidence")
    title = _text(item.get("title"))
    reason = _text(item.get("reason"))
    hint = item.get("false_positive_hint")
    if (
        not isinstance(finding_id, str)
        or not _FINDING_ID.fullmatch(finding_id)
        or not isinstance(rule_id, str)
        or not _RULE_ID.fullmatch(rule_id)
        or not _is_relative_path(path)
        or server is None
        or not isinstance(category, str)
        or not _CATEGORY.fullmatch(category)
        or severity not in _SEVERITIES
        or confidence not in _CONFIDENCES
        or title is None
        or reason is None
        or (hint is not None and _text(hint) is None)
    ):
        return None
    return {
        "finding_id": finding_id,
        "source_kind": MCP_CONFIG_SOURCE_KIND,
        "detector": MCP_CONFIG_DETECTOR,
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
        "server": server,
        "category": category,
        "confidence": confidence,
        "title": title,
        "reason": reason,
        "false_positive_hint": _text(hint),
        "validation_state": "unvalidated",
        "lifecycle_state": "open",
    }


def _is_relative_path(value: object) -> bool:
    """A normalized root-relative path, never one that leaves the root."""

    if not isinstance(value, str) or len(value) > _MAX_PATH_CHARS or "\0" in value or "\\" in value:
        return False
    parts = value.split("/")
    return all(part not in {"", ".", ".."} for part in parts) and not parts[0].endswith(":")


def _text(value: object) -> str | None:
    """One bounded printable line."""

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
    "MAX_MCP_CONFIG_FINDINGS",
    "MCP_CONFIG_DETECTOR",
    "MCP_CONFIG_SOURCE_KIND",
    "assess_workspace_mcp_configs",
    "project_mcp_config_findings",
    "with_mcp_config_coverage",
]
