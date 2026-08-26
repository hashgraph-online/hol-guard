"""Bounded daemon API for unlisted CLI observation and this-device grants."""

from __future__ import annotations

import time
from pathlib import Path
from typing import TYPE_CHECKING

from ..adapters.harness_mcp_discovery import (
    DiscoveredHarnessMcpServer,
    apply_source_labels,
    discover_harness_mcp_servers,
    discovered_server_for_observation,
    persist_discovered_harness_mcp_servers,
)
from ..approval_gate import (
    ApprovalGateError,
    consume_local_cli_trust_grant,
    input_from_mapping,
    require_local_cli_trust,
)
from ..local_cli_trust import utc_now
from ..runtime.custom_extension_continuity import (
    record_local_custom_extension_mutation,
)
from ..runtime.local_cli_commands import (
    MAX_LOCAL_CLI_COMMANDS,
    LocalCliCommand,
    LocalCliCommandState,
    default_local_cli_commands,
    is_local_cli_command_id,
)
from ..runtime.local_cli_help import (
    discover_local_cli_commands,
    help_invocation_for_command,
)
from ..runtime.local_cli_identity import (
    LocalCliKind,
    UnlistedCliIdentity,
    is_local_cli_id,
    local_cli_recognition_candidates,
    recognize_operator_cli,
)
from ..runtime.local_mcp_probe import (
    is_package_mcp_launcher,
    is_strict_package_mcp_launcher,
    looks_like_mcp_launch,
    mcp_launch_tokens,
    probe_stdio_mcp_server,
)
from ..runtime.package_json_script_memory import (
    _package_item_available,
    operator_working_directory,
    public_local_cli_item,
    recognize_operator_package_scripts,
    refresh_package_script_catalogs,
)
from ..runtime.package_json_scripts import looks_like_package_script_paste
from .local_cli_continuity_api import decorate_local_cli_continuity

if TYPE_CHECKING:
    from ..store import GuardStore

_LOCAL_CLI_API_SCHEMA = "guard.daemon.local-clis.v1"
_VALID_STATES = frozenset({"allowed", "blocked", "unset"})
_DISCOVERY_TTL_SECONDS = 30.0


class LocalCliApiError(Exception):
    def __init__(self, status: int, code: str, message: str | None = None) -> None:
        self.status = status
        self.code = code
        super().__init__(message or code)

    def to_payload(self) -> dict[str, object]:
        return {"error": self.code, "message": str(self)}


class LocalCliApiService:
    def __init__(self, *, store: GuardStore) -> None:
        self._store = store
        self._discovery_cache: tuple[float, tuple[DiscoveredHarnessMcpServer, ...]] | None = None

    def list_items(self) -> dict[str, object]:
        stored = self._store.list_local_cli_items()
        try:
            labels = self._observe_harness_mcp_servers()
            items = apply_source_labels(
                refresh_package_script_catalogs(self._store, home_dir=Path.home()),
                labels,
            )
        except (OSError, RuntimeError, TypeError, ValueError, KeyError, UnicodeError):
            items = [public_local_cli_item(item) for item in stored if _package_item_available(item)]
        revision = self._store.read_local_cli_revision()
        return {
            "schema_version": _LOCAL_CLI_API_SCHEMA,
            "revision": revision,
            "items": items,
            "cloud": decorate_local_cli_continuity(self._store, items),
        }

    def recognize(self, payload: dict[str, object]) -> dict[str, object]:
        command = self._required_string(payload, "command")
        home_dir = Path.home()
        live_command = None
        cli_id = payload.get("cli_id")
        tokens = mcp_launch_tokens(command, cwd=home_dir, home_dir=home_dir)
        if isinstance(cli_id, str) and is_local_cli_id(cli_id):
            _ = self._observe_harness_mcp_servers()
            live_command = self._live_mcp_launch_command(payload)
        elif tokens is not None and is_package_mcp_launcher(tokens):
            _ = self._observe_harness_mcp_servers()
        mcp_item = self._recognize_mcp(live_command or command, home_dir)
        if mcp_item is not None:
            return mcp_item
        operator_cwd = operator_working_directory(payload, home_dir=home_dir)
        package_scripts = recognize_operator_package_scripts(
            command,
            cwd=operator_cwd,
            home_dir=home_dir,
            store=self._store,
        )
        if package_scripts is not None:
            identity = package_scripts.identity
            self._store.record_local_cli_observation(
                identity,
                seen_at=utc_now(),
                source_path=identity.source_path,
                help_status="ok",
                surface="package-scripts",
            )
            self._store.replace_local_cli_commands(identity.cli_id, package_scripts.commands)
            return self._recognize_payload(identity.cli_id, identity.to_dict(), "ok", package_scripts.summary)
        identity, code, message = recognize_operator_cli(command, cwd=operator_cwd, home_dir=home_dir)
        if identity is None and looks_like_package_script_paste(command):
            raise LocalCliApiError(
                400,
                "missing_package_json",
                "Guard could not find package.json. Paste a project folder, package.json, or npm --prefix <dir> run.",
            )
        if identity is None:
            raise LocalCliApiError(400, code, message)
        commands, help_status, source_path = _discover_from_command(command, identity, operator_cwd, home_dir)
        self._store.record_local_cli_observation(
            identity,
            seen_at=utc_now(),
            source_path=source_path,
            help_status=help_status,
            surface="cli",
        )
        self._store.replace_local_cli_commands(identity.cli_id, commands)
        return self._recognize_payload(
            identity.cli_id,
            identity.to_dict(),
            help_status,
            _recognize_summary(identity.name, help_status, len(commands)),
        )

    def _recognize_mcp(self, command: str, home_dir: Path) -> dict[str, object] | None:
        tokens = mcp_launch_tokens(command, cwd=home_dir, home_dir=home_dir)
        if tokens is None or not looks_like_mcp_launch(tokens, command_text=command, cwd=home_dir, home_dir=home_dir):
            return None
        probed = probe_stdio_mcp_server(command, cwd=home_dir, home_dir=home_dir)
        if probed is None:
            if is_strict_package_mcp_launcher(tokens):
                launcher = Path(tokens[0]).name
                raise LocalCliApiError(
                    400,
                    "already_built_in",
                    (
                        f"{launcher} is already a built-in Guard extension. "
                        "Guard could not list MCP tools from that command."
                    ),
                )
            return None
        identity, server_hash, server_command, server_args_hash = _bound_mcp_observation(
            self._store,
            probed.identity,
            probed.server_identity,
        )
        self._store.record_local_cli_observation(
            identity,
            seen_at=utc_now(),
            source_path=None,
            help_status=probed.status,
            surface="mcp",
            server_identity_hash=server_hash,
            server_command=server_command,
            server_args_hash=server_args_hash,
        )
        self._store.replace_local_cli_commands(identity.cli_id, probed.tools)
        return self._recognize_payload(
            identity.cli_id,
            identity.to_dict(),
            probed.status,
            _recognize_mcp_summary(identity.name, probed.status, len(probed.tools)),
        )

    def _observe_harness_mcp_servers(self) -> dict[str, str]:
        try:
            return persist_discovered_harness_mcp_servers(
                self._store,
                self._discovered_servers(),
                seen_at=utc_now(),
            )
        except (OSError, RuntimeError, TypeError, ValueError):
            return {}

    def _discovered_servers(self) -> tuple[DiscoveredHarnessMcpServer, ...]:
        now = time.monotonic()
        cached = self._discovery_cache
        if cached is not None and now - cached[0] < _DISCOVERY_TTL_SECONDS:
            return cached[1]
        try:
            servers = discover_harness_mcp_servers(home_dir=Path.home(), guard_home=self._store.guard_home)
        except (OSError, RuntimeError, TypeError, ValueError, KeyError, UnicodeError):
            return ()
        self._discovery_cache = (now, servers)
        return servers

    def _live_mcp_launch_command(self, payload: dict[str, object]) -> str | None:
        cli_id = payload.get("cli_id")
        if not isinstance(cli_id, str) or not is_local_cli_id(cli_id):
            return None
        existing = self._store.find_local_mcp_observation(cli_id=cli_id)
        server_command = existing.get("server_command") if isinstance(existing, dict) else None
        args_hash = existing.get("server_args_hash") if isinstance(existing, dict) else None
        server = discovered_server_for_observation(
            self._discovered_servers(),
            cli_id=cli_id,
            server_command=server_command if isinstance(server_command, str) else None,
            args_hash=args_hash if isinstance(args_hash, str) else None,
        )
        return None if server is None else server.launch_command

    def _recognize_payload(
        self,
        cli_id: str,
        fallback: dict[str, object],
        help_status: str,
        summary: str,
    ) -> dict[str, object]:
        listed = next(
            (item for item in self._store.list_local_cli_items() if item.get("cli_id") == cli_id),
            None,
        )
        return {
            "schema_version": _LOCAL_CLI_API_SCHEMA,
            "revision": self._store.read_local_cli_revision(),
            "item": public_local_cli_item(listed or fallback),
            "help_status": help_status,
            "summary": summary,
        }

    def preview(self, payload: dict[str, object]) -> dict[str, object]:
        identity, state = self._mutation_from_payload(payload)
        current = self._store.read_local_cli_revision()
        expected = self._required_int(payload, "previous_revision")
        if expected != current:
            raise LocalCliApiError(409, "revision_conflict")
        summary = _preview_summary(identity.name, state)
        return {
            "schema_version": _LOCAL_CLI_API_SCHEMA,
            "previous_revision": current,
            "next_revision": current + 1,
            "cli_id": identity.cli_id,
            "identity_hash": identity.identity_hash,
            "state": state,
            "summary": summary,
        }

    def apply(self, payload: dict[str, object]) -> dict[str, object]:
        identity, state = self._mutation_from_payload(payload)
        expected = self._required_int(payload, "previous_revision")
        session_nonce = self._required_string(payload, "session_nonce")
        action = f"local-cli-{state}"
        subject = f"{identity.cli_id}:{identity.identity_hash}:{state}:{expected}"
        try:
            grant = require_local_cli_trust(
                self._store.guard_home,
                approval_gate_input=input_from_mapping(payload),
                action=action,
                subject=subject,
                session_nonce=session_nonce,
            )
            consume_local_cli_trust_grant(
                self._store.guard_home,
                grant,
                action=action,
                subject=subject,
                session_nonce=session_nonce,
            )
        except ApprovalGateError as exc:
            raise LocalCliApiError(exc.status, exc.code, str(exc)) from exc
        command_states = self._command_states_from_payload(payload)
        try:
            revision = record_local_custom_extension_mutation(
                self._store,
                identity=identity,
                state=state,
                expected_revision=expected,
                command_states=command_states,
                now=utc_now(),
            )
        except ValueError as exc:
            if str(exc) == "local_cli_revision_conflict":
                raise LocalCliApiError(409, "revision_conflict") from exc
            raise LocalCliApiError(400, "invalid_local_cli_mutation", str(exc)) from exc
        return {
            "schema_version": _LOCAL_CLI_API_SCHEMA,
            "status": "applied",
            "revision": revision,
            "cli_id": identity.cli_id,
            "state": state,
        }

    def _mutation_from_payload(self, payload: dict[str, object]) -> tuple[UnlistedCliIdentity, str]:
        cli_id = self._required_string(payload, "cli_id")
        identity_hash = self._required_string(payload, "identity_hash")
        name = self._required_string(payload, "name")
        kind = self._required_string(payload, "kind")
        state = self._required_string(payload, "state")
        if not is_local_cli_id(cli_id):
            raise LocalCliApiError(400, "invalid_cli_id")
        if len(identity_hash) != 64 or any(character not in "0123456789abcdef" for character in identity_hash):
            raise LocalCliApiError(400, "invalid_identity_hash")
        typed_kind = _cli_kind(kind)
        if typed_kind is None:
            raise LocalCliApiError(400, "invalid_cli_kind")
        if state not in _VALID_STATES:
            raise LocalCliApiError(400, "invalid_cli_state")
        example_label = payload.get("example_label")
        interpreter_name = payload.get("interpreter_name")
        if example_label is not None and not isinstance(example_label, str):
            raise LocalCliApiError(400, "invalid_example_label")
        if interpreter_name is not None and not isinstance(interpreter_name, str):
            raise LocalCliApiError(400, "invalid_interpreter_name")
        identity = UnlistedCliIdentity(
            cli_id=cli_id,
            name=name[:120],
            kind=typed_kind,
            identity_hash=identity_hash,
            example_label=(example_label or name)[:160],
            interpreter_name=interpreter_name,
        )
        return identity, state

    def _command_states_from_payload(self, payload: dict[str, object]) -> dict[str, LocalCliCommandState]:
        raw = payload.get("commands")
        if raw is None:
            return {}
        if not isinstance(raw, list) or len(raw) > MAX_LOCAL_CLI_COMMANDS:
            raise LocalCliApiError(400, "invalid_commands")
        states: dict[str, LocalCliCommandState] = {}
        for entry in raw:
            if not isinstance(entry, dict):
                raise LocalCliApiError(400, "invalid_commands")
            command_id = entry.get("command_id")
            state = entry.get("state")
            if not isinstance(command_id, str) or not is_local_cli_command_id(command_id):
                raise LocalCliApiError(400, "invalid_command_id")
            if state != "inherit" and state != "allow" and state != "block":
                raise LocalCliApiError(400, "invalid_command_state")
            states[command_id] = state
        return states

    def _required_string(self, payload: dict[str, object], key: str) -> str:
        value = payload.get(key)
        if not isinstance(value, str) or not value.strip():
            raise LocalCliApiError(400, f"missing_{key}")
        return value.strip()

    def _required_int(self, payload: dict[str, object], key: str) -> int:
        value = payload.get(key)
        if type(value) is not int:
            raise LocalCliApiError(400, f"missing_{key}")
        return value


def _bound_mcp_observation(
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


def _preview_summary(name: str, state: str) -> str:
    if state == "allowed":
        return (
            f"Add {name} as a custom extension. Recommended commands stay on Guard's usual review. "
            "Allow or block applies only to the commands you set."
        )
    if state == "blocked":
        return f"Keep {name} as a custom extension and block every command from this file."
    return f"Remove the {name} custom extension from this device."


def _recognize_mcp_summary(name: str, help_status: str, tool_count: int) -> str:
    if help_status == "ok":
        return (
            f"Guard listed {tool_count} tools from this MCP server. "
            "Recommended keeps the usual review. Allow or block each tool like a built-in."
        )
    if help_status == "empty":
        return (
            f"{name} did not list tools. You can still allow or block this server, or set Recommended for other tools."
        )
    return (
        f"Guard could not list tools from {name}. You can still add the server. "
        "Tools stay on Recommended until listing works."
    )


def _recognize_summary(name: str, help_status: str, command_count: int) -> str:
    if help_status == "ok":
        return (
            f"Guard read {command_count} commands from {name} --help. "
            "Recommended keeps the usual review. Allow or block each command like a built-in tool."
        )
    if help_status == "empty":
        return (
            f"{name} did not list subcommands. You can still allow or block this file, "
            "or set Recommended for other commands."
        )
    return (
        f"Guard could not read {name} --help. You can still add the tool. "
        "Commands stay on Recommended until --help works."
    )


def _discover_from_command(
    command: str,
    identity: UnlistedCliIdentity,
    cwd: Path,
    home_dir: Path,
) -> tuple[tuple[LocalCliCommand, ...], str, str | None]:
    source_path: str | None = None
    for candidate in local_cli_recognition_candidates(command, cwd=cwd, home_dir=home_dir):
        invocation = help_invocation_for_command(candidate, cwd=cwd, home_dir=home_dir)
        if invocation is None:
            continue
        matched, argv = invocation
        if matched.cli_id != identity.cli_id:
            continue
        tool_path = next(iter(argv), None)
        if tool_path is None:
            continue
        source_path = argv[1] if matched.kind == "script" and len(argv) >= 2 else tool_path
        commands, help_status = discover_local_cli_commands(matched, argv)
        return commands, help_status, source_path
    return default_local_cli_commands(identity.name), "failed", source_path


def _cli_kind(value: str) -> LocalCliKind | None:
    if value == "executable":
        return "executable"
    if value == "script":
        return "script"
    return None
