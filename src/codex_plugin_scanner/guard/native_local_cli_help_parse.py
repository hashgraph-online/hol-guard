"""Resident bridge for the ``local_cli_help_parse`` op.

Python probes an unlisted CLI with ``--help`` -- that is where the process
isolation lives -- and hands the text here for the parse. The text is whatever
a third-party program printed, so nothing in it is trusted: the op reports only
the command names Rust recognized, and an answer that is not bound to this
request is discarded. When the resident cannot answer, the caller sees nothing
and the CLI's commands stay undiscovered.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import Path
from typing import Literal, NamedTuple
from uuid import uuid4

from .native_context import ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_runtime import native_runtime_status
from .native_runtime_resilience import native_record_resident_failure
from .native_store_policy import _payload

LOCAL_CLI_HELP_PARSE_FEATURE = "local-cli-help-parse-v1"
# A resident that reads options and script sources. Older ones refuse the
# `script_source` field, so it is sent only to a resident that advertises this.
LOCAL_CLI_HELP_VARIATIONS_FEATURE = "local-cli-help-variations-v1"
# A resident whose source read also says whether the script handles --help and
# which local modules it imports, so a script can be read before it is run.
LOCAL_CLI_HELP_SOURCE_FIRST_FEATURE = "local-cli-help-source-first-v1"
# A resident whose source read also says whether the script serves MCP, so a
# pasted script is launched as an MCP server only when its code says it is one.
LOCAL_CLI_HELP_MCP_EVIDENCE_FEATURE = "local-cli-help-mcp-evidence-v1"
_REQUEST_SCHEMA = "guard-local-cli-help-parse-request.v1"
_RESULT_SCHEMA = "guard-local-cli-help-parse-result.v1"
_TIMEOUT_SECONDS = 5.0
_MAX_REQUEST_BYTES = 256 * 1024

_FIELDS = ("command_id", "name", "usage", "description", "parent_id")
_HELP_HANDLERS = ("none", "script", "framework")
_MODULE_NAME = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*")
_MAX_IMPORTS = 32

HelpHandler = Literal["none", "script", "framework"]


class SourceRead(NamedTuple):
    """What the resident read out of a script's source without running it."""

    rows: tuple[dict[str, object], ...]
    # Whether running the script with --help prints help: "none" when nothing
    # in it looks for --help, "script" when its own code does, "framework" when
    # a parser library it imports answers it, for each subcommand too.
    help_handler: HelpHandler
    imports: tuple[str, ...]
    # Whether the code imports an MCP server library or answers tools/list.
    # Read only when the request asked for it; False otherwise.
    mcp_server: bool = False
    # When the whole script is a generated wrapper for an installed package's
    # entry point, the module it imports. Read with mcp_server; None otherwise.
    entry_point: str | None = None


def resident_reads_sources_first() -> bool | None:
    """Whether the resident can say what a script does with --help.

    None when the runtime's status cannot be read: a resident that is busy or
    unavailable says nothing about what it lacks, so it is never taken for an
    older one that would let Guard run the script unread.
    """

    return _resident_has(LOCAL_CLI_HELP_SOURCE_FIRST_FEATURE)


def resident_reads_mcp_evidence() -> bool | None:
    """Whether the resident can say if a script serves MCP; None as above."""

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


def native_local_cli_help_commands(
    *,
    guard_home: Path,
    text: str,
    parent_id: str | None,
    invocation: Sequence[str],
    script_source: bool = False,
) -> tuple[dict[str, object], ...] | None:
    """The commands the resident read out of ``text``; None when it cannot say.

    ``script_source`` marks ``text`` as a script's own source rather than its
    help output: the resident then reads only its comments and help text.
    """

    feature = LOCAL_CLI_HELP_VARIATIONS_FEATURE if script_source else LOCAL_CLI_HELP_PARSE_FEATURE
    home = Path(guard_home)
    payload = _request(home, text, parent_id, invocation, script_source=script_source, feature=feature)
    if payload is None:
        return None
    return _rows(payload, home)


def native_local_cli_source_read(
    *,
    guard_home: Path,
    text: str,
    invocation: Sequence[str],
    mcp_evidence: bool = False,
) -> SourceRead | None:
    """Read a script's source before anything runs it; None when the resident cannot.

    Besides the commands, the answer says whether the script handles --help
    and which local modules it imports, and with ``mcp_evidence`` whether it
    serves MCP and which installed module an entry-point wrapper runs. Each decides
    what Guard runs next, so a reply whose fields are missing or malformed is
    discarded whole.
    """

    home = Path(guard_home)
    feature = LOCAL_CLI_HELP_MCP_EVIDENCE_FEATURE if mcp_evidence else LOCAL_CLI_HELP_SOURCE_FIRST_FEATURE
    payload = _request(home, text, None, invocation, script_source=True, feature=feature)
    if payload is None:
        return None
    rows = _rows(payload, home)
    if rows is None:
        return None
    handler = payload.get("help_handler")
    imports = payload.get("imports")
    if handler not in _HELP_HANDLERS or not isinstance(imports, list) or len(imports) > _MAX_IMPORTS:
        return _unusable(home)
    if any(not isinstance(entry, str) or not entry.startswith("./") for entry in imports):
        return _unusable(home)
    mcp_server = payload.get("mcp_server") if mcp_evidence else False
    entry_point = payload.get("entry_point") if mcp_evidence else None
    if not isinstance(mcp_server, bool) or not (entry_point is None or _is_module_name(entry_point)):
        return _unusable(home)
    return SourceRead(
        rows=rows,
        help_handler=handler,
        imports=tuple(imports),
        mcp_server=mcp_server,
        entry_point=entry_point,
    )


def _is_module_name(value: object) -> bool:
    return isinstance(value, str) and len(value) <= 200 and _MODULE_NAME.fullmatch(value) is not None


def _request(
    home: Path,
    text: str,
    parent_id: str | None,
    invocation: Sequence[str],
    *,
    script_source: bool,
    feature: str,
) -> dict[str, object] | None:
    try:
        if not ensure_resident_prerequisite(home):
            return None
    except (OSError, RuntimeError, ValueError):
        return None
    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"local-cli-help-parse-{uuid4().hex}",
        "text": text,
        "parent_id": parent_id,
        "invocation": [str(word) for word in invocation],
    }
    if script_source:
        wire["script_source"] = True
    try:
        response = _resident_request(
            operation="local_cli_help_parse",
            request=wire,
            guard_home=home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=feature,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError):
        return None
    payload = _payload(response, wire, home)
    return payload if isinstance(payload, dict) else None


def _rows(payload: dict[str, object], home: Path) -> tuple[dict[str, object], ...] | None:
    commands = payload.get("commands")
    if not isinstance(commands, list):
        return _unusable(home)
    read: list[dict[str, object]] = []
    for entry in commands:
        if not isinstance(entry, dict) or any(field not in entry for field in _FIELDS):
            return _unusable(home)
        row = {field: entry[field] for field in _FIELDS}
        if any(not isinstance(row[field], str) for field in _FIELDS[:4]):
            return _unusable(home)
        if not isinstance(row["parent_id"], (str, type(None))):
            return _unusable(home)
        read.append(row)
    return tuple(read)


def _unusable(guard_home: Path) -> None:
    """Record the failure ``_payload`` could not see, and discover nothing.

    ``_payload`` counts a bound ``ok`` reply as a healthy answer as soon as its
    payload is a dict, which is before the commands inside it are read. A
    resident that answers every request with rows this bridge discards would
    otherwise keep a clean streak while discovering nothing, so the failure is
    recorded here, where the rows are actually checked.
    """

    identity = native_runtime_status().identity
    if identity is not None:
        native_record_resident_failure(identity.sha256, guard_home, reason="native_local_cli_help_parse_payload")
    return None
