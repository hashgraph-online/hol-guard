"""Project the native MCP configuration check into workspace findings and coverage.

The runtime decides each finding's stable ``finding_id`` and the rule's
severity. A finding carries only the rule's fixed title and reason, the
root-relative path of the configuration file and the server's name, never the
server's command or URL. The native ``workspace_rule_findings`` kind checks
that shape and copies it into the stored finding; a finding that does not
match is dropped and leaves the detector incomplete instead of silently
complete.

MCP configuration findings are dashboard warnings. They never block or ask.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Final

MCP_CONFIG_DETECTOR: Final = "mcp_config_v1"

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


__all__ = [
    "MCP_CONFIG_DETECTOR",
    "assess_workspace_mcp_configs",
]
