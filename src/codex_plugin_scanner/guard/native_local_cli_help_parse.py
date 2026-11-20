"""Whether the resident can say if a script serves MCP.

Discovering a local CLI's commands is the native ``local-cli-discover``
command (``runtime/local_cli_help.py``); the resident's ``local_cli_help_parse``
op remains for the MCP evidence read in ``runtime/local_mcp_source_evidence.py``.
"""

from __future__ import annotations

from .native_runtime import native_runtime_status

# A resident whose source read also says whether the script serves MCP, so a
# pasted script is launched as an MCP server only when its code says it is one.
LOCAL_CLI_HELP_MCP_EVIDENCE_FEATURE = "local-cli-help-mcp-evidence-v1"


def resident_reads_mcp_evidence() -> bool | None:
    """Whether the resident can say if a script serves MCP.

    None when the runtime's status cannot be read: a resident that is busy or
    unavailable says nothing about what it lacks, so it is never taken for an
    older one.
    """

    return _resident_has(LOCAL_CLI_HELP_MCP_EVIDENCE_FEATURE)


def _resident_has(feature: str) -> bool | None:
    try:
        status = native_runtime_status()
    except Exception:
        return None
    capabilities = status.capabilities
    if not status.available or not status.compatible or capabilities is None:
        return None
    return feature in capabilities.features
