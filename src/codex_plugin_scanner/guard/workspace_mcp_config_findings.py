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

from .workspace_rule_findings import (
    MAX_RULE_FINDINGS,
    WORKSPACE_SOURCE_KIND,
    RuleScan,
    is_relative_path,
    project_rule_findings,
    rule_text,
    with_rule_coverage,
)

MCP_CONFIG_DETECTOR: Final = "mcp_config_v1"
MCP_CONFIG_SOURCE_KIND: Final = WORKSPACE_SOURCE_KIND
MCP_CONFIG_RESULT_SCHEMA: Final = "guard.workspace-mcp-config.v1"
MAX_MCP_CONFIG_FINDINGS: Final = MAX_RULE_FINDINGS

_RULE_ID = re.compile(r"mcp\.config\.[a-z0-9.-]{1,120}")
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

    return project_rule_findings(_SCAN, result)


def with_mcp_config_coverage(coverage: dict[str, object], result: object) -> dict[str, object]:
    """Add the MCP configuration detector to a run's coverage.

    A runtime without the check leaves the detector not run; a check that
    could not read every server, or a malformed reply, leaves it incomplete.
    Both make the run partial. A worktree that configures no servers has no
    inputs.
    """

    return with_rule_coverage(_SCAN, coverage, result)


def _mcp_fields(item: Mapping[str, object]) -> dict[str, object] | None:
    rule_id = item.get("rule_id")
    server = rule_text(item.get("server"))
    if not isinstance(rule_id, str) or not _RULE_ID.fullmatch(rule_id) or not is_relative_path(item.get("path")):
        return None
    return None if server is None else {"server": server}


_SCAN: Final = RuleScan(
    detector=MCP_CONFIG_DETECTOR,
    result_schema=MCP_CONFIG_RESULT_SCHEMA,
    summary_key="mcp_config",
    incomplete_reason="mcp_config_incomplete",
    counters=("servers_scanned",),
    inputs_counter="servers_scanned",
    skip_kinds=("oversize",),
    finding_fields=_mcp_fields,
)


__all__ = [
    "MAX_MCP_CONFIG_FINDINGS",
    "MCP_CONFIG_DETECTOR",
    "MCP_CONFIG_SOURCE_KIND",
    "assess_workspace_mcp_configs",
    "project_mcp_config_findings",
    "with_mcp_config_coverage",
]
