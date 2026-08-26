"""Read stored MCP observations when live probing is unavailable."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from ..runtime.local_cli_identity import UnlistedCliIdentity
from ..runtime.local_mcp_probe import mcp_launch_tokens
from ..runtime.mcp_protection import build_mcp_server_identity

RecognizePayload = Callable[[str, dict[str, object], str, str], dict[str, object]]
RecognizeSummary = Callable[[str, str, int], str]


def stored_mcp_has_tools(payload: dict[str, object]) -> bool:
    item = payload.get("item")
    if not isinstance(item, dict):
        return False
    commands = item.get("commands")
    if not isinstance(commands, list) or not commands:
        return False
    return any(isinstance(entry, dict) and entry.get("command_id") for entry in commands)


def stored_mcp_recognition(
    store: object,
    command: str,
    *,
    cli_id: str | None,
    recognize_payload: RecognizePayload,
    recognize_summary: RecognizeSummary,
) -> dict[str, object] | None:
    tokens = mcp_launch_tokens(command, cwd=Path.home(), home_dir=Path.home())
    launch_command = None
    args_hash = None
    if tokens is not None:
        identity = build_mcp_server_identity(
            config_path="",
            command=tokens[0],
            args=tuple(tokens[1:]),
            transport="stdio",
        )
        launch_command = identity.command
        args_hash = identity.args_hash
    finder = getattr(store, "find_local_mcp_observation", None)
    found = finder(cli_id=cli_id, command=launch_command, args_hash=args_hash) if callable(finder) else None
    if found is None:
        return None
    found_id = found.get("cli_id")
    if not isinstance(found_id, str):
        return None
    lister = getattr(store, "list_local_cli_items", None)
    listed = next(
        (item for item in (lister() if callable(lister) else []) if item.get("cli_id") == found_id),
        None,
    )
    if listed is None:
        return None
    help_status = listed.get("help_status")
    status = help_status if help_status in {"ok", "empty", "failed"} else "failed"
    raw_commands = listed.get("commands")
    count = len(raw_commands) if isinstance(raw_commands, list) else 0
    name = listed.get("name")
    label = name if isinstance(name, str) and name.strip() else found_id
    return recognize_payload(found_id, listed, status, recognize_summary(label, status, count))


def bound_mcp_observation(
    store: object,
    probed_identity: UnlistedCliIdentity,
    server_identity: object,
) -> tuple[UnlistedCliIdentity, str, str, str]:
    identity_hash = getattr(server_identity, "identity_hash", "")
    command = getattr(server_identity, "command", "")
    args_hash = getattr(server_identity, "args_hash", "")
    finder = getattr(store, "find_local_mcp_observation", None)
    existing = (
        finder(server_identity_hash=identity_hash, command=command, args_hash=args_hash) if callable(finder) else None
    )
    if not isinstance(existing, dict):
        return probed_identity, str(identity_hash), str(command), str(args_hash)
    cli_id = existing.get("cli_id")
    stored_hash = existing.get("identity_hash")
    if not isinstance(cli_id, str) or not isinstance(stored_hash, str):
        return probed_identity, str(identity_hash), str(command), str(args_hash)
    name = existing.get("name")
    stored_label = existing.get("example_label")
    identity = UnlistedCliIdentity(
        cli_id=cli_id,
        name=name if isinstance(name, str) and name.strip() else probed_identity.name,
        kind="executable",
        identity_hash=stored_hash,
        example_label=stored_label
        if isinstance(stored_label, str) and stored_label.strip()
        else probed_identity.example_label,
    )
    return (
        identity,
        _string_field(existing.get("server_identity_hash"), identity_hash),
        _string_field(existing.get("server_command"), command),
        _string_field(existing.get("server_args_hash"), args_hash),
    )


def _string_field(value: object, fallback: object) -> str:
    if isinstance(value, str) and value:
        return value
    return str(fallback)
