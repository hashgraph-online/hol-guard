"""Complete typed inventory for executable Codex hook configuration."""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .codex_hook_identity import (
    CODEX_HOOK_IDENTITY_SCHEMA,
    canonical_codex_command_argv,
    canonical_codex_hook_conflict_keys,
    canonical_codex_hook_group_identity,
    canonical_codex_hook_identity,
)

CODEX_HOOK_INVENTORY_UNMANAGED_EXECUTABLE = "codex_hook_inventory_unmanaged_executable"
CODEX_HOOK_INVENTORY_UNSUPPORTED_EVENT = "codex_hook_inventory_unsupported_event_shape"
CODEX_HOOK_INVENTORY_MALFORMED_GROUP = "codex_hook_inventory_malformed_group"
CODEX_HOOK_INVENTORY_MALFORMED_HANDLER = "codex_hook_inventory_malformed_handler"
CODEX_HOOK_INVENTORY_UNKNOWN_HANDLER = "codex_hook_inventory_unknown_handler_type"
CODEX_HOOK_INVENTORY_SOURCE_DUPLICATE = "codex_hook_inventory_source_duplicate_key"
CODEX_HOOK_INVENTORY_SOURCE_MALFORMED = "codex_hook_inventory_source_malformed"
CODEX_HOOK_INVENTORY_SOURCE_UNREADABLE = "codex_hook_inventory_source_unreadable"
CODEX_HOOK_INVENTORY_SOURCE_CHANGED = "codex_hook_inventory_source_changed"
HookSourceFormat = Literal["json", "toml"]
HookOwnership = Literal["authenticated_manifest", "exact_legacy_adoption", "unmanaged"]


@dataclass(frozen=True, slots=True)
class CodexHookInventoryRecord:
    """One handler with exact source coordinates and execution-affecting fields."""

    source_path: str
    source_scope: str
    source_format: HookSourceFormat
    source_hooks_enabled: bool
    event_name: str
    group_index: int
    matcher: object
    handler_index: int
    handler_type: str | None
    command: str | None
    command_argv: tuple[str, ...] | None
    timeout: int | float | None
    environment_keys: tuple[str, ...]
    active: bool
    executable: bool
    ownership: HookOwnership
    canonical_identity: str

    @property
    def coordinate(self) -> str:
        return f"{self.event_name}/group[{self.group_index}]/handler[{self.handler_index}]"


@dataclass(frozen=True, slots=True)
class CodexHookInventoryIssue:
    """Stable fail-closed reason tied to one source coordinate."""

    reason_code: str
    message: str
    source_path: str
    event_name: str | None = None
    group_index: int | None = None
    handler_index: int | None = None

    @property
    def coordinate(self) -> str:
        if self.event_name is None:
            return self.source_path
        coordinate = self.event_name
        if self.group_index is not None:
            coordinate += f"/group[{self.group_index}]"
        if self.handler_index is not None:
            coordinate += f"/handler[{self.handler_index}]"
        return coordinate


@dataclass(frozen=True, slots=True)
class CodexHookInventory:
    """Complete inventory result for one JSON or TOML source."""

    source_path: str
    records: tuple[CodexHookInventoryRecord, ...]
    issues: tuple[CodexHookInventoryIssue, ...]

    @property
    def complete(self) -> bool:
        return not self.issues

    @property
    def unmanaged_active_executables(self) -> tuple[CodexHookInventoryRecord, ...]:
        return tuple(
            record for record in self.records if record.active and record.executable and record.ownership == "unmanaged"
        )


def enumerate_codex_hooks(
    payload: Mapping[str, object],
    *,
    source_path: Path,
    source_scope: str,
    source_format: HookSourceFormat,
    source_hooks_enabled: bool,
    authenticated_bindings: Sequence[Mapping[str, object]] = (),
    legacy_bindings: Sequence[Mapping[str, object]] = (),
) -> CodexHookInventory:
    """Walk every event, group, and handler accepted by the Codex hook shape."""

    hooks = payload.get("hooks")
    if hooks is None:
        return CodexHookInventory(str(source_path), (), ())
    if not isinstance(hooks, Mapping):
        issue = CodexHookInventoryIssue(
            CODEX_HOOK_INVENTORY_UNSUPPORTED_EVENT,
            "Codex hooks must be an event table. Repair the hook configuration before retrying install.",
            str(source_path),
        )
        return CodexHookInventory(str(source_path), (), (issue,))

    records: list[CodexHookInventoryRecord] = []
    issues: list[CodexHookInventoryIssue] = []
    for event_name, groups in hooks.items():
        if _is_codex_hook_state_metadata(event_name, groups, source_format):
            continue
        if not isinstance(event_name, str) or not isinstance(groups, list):
            issues.append(
                CodexHookInventoryIssue(
                    CODEX_HOOK_INVENTORY_UNSUPPORTED_EVENT,
                    "Each Codex hook event must contain a list of matcher groups. Repair the event shape before "
                    "retrying install.",
                    str(source_path),
                    event_name if isinstance(event_name, str) else None,
                )
            )
            continue
        for group_index, group in enumerate(groups):
            if not isinstance(group, Mapping):
                issues.append(
                    CodexHookInventoryIssue(
                        CODEX_HOOK_INVENTORY_MALFORMED_GROUP,
                        "Each Codex hook matcher group must be an object. Repair the group before retrying install.",
                        str(source_path),
                        event_name,
                        group_index,
                    )
                )
                continue
            if not _activation_fields_are_valid(group) or not isinstance(group.get("matcher"), (str, type(None))):
                issues.append(
                    CodexHookInventoryIssue(
                        CODEX_HOOK_INVENTORY_MALFORMED_GROUP,
                        "A Codex hook matcher and activation fields must use supported scalar types. Repair the "
                        "group before retrying install.",
                        str(source_path),
                        event_name,
                        group_index,
                    )
                )
            handlers = group.get("hooks")
            if handlers is None:
                continue
            if not isinstance(handlers, list):
                issues.append(
                    CodexHookInventoryIssue(
                        CODEX_HOOK_INVENTORY_MALFORMED_GROUP,
                        "A Codex hook group's handlers must be a list. Repair the group before retrying install.",
                        str(source_path),
                        event_name,
                        group_index,
                    )
                )
                continue
            group_active = _entry_is_active(group)
            for handler_index, handler in enumerate(handlers):
                record, handler_issues = _handler_record(
                    handler,
                    source_path=source_path,
                    source_scope=source_scope,
                    source_format=source_format,
                    source_hooks_enabled=source_hooks_enabled,
                    event_name=event_name,
                    group_index=group_index,
                    matcher=group.get("matcher"),
                    handler_index=handler_index,
                    group_active=group_active,
                    authenticated_bindings=authenticated_bindings,
                    legacy_bindings=legacy_bindings,
                    group=group,
                )
                if record is not None:
                    records.append(record)
                issues.extend(handler_issues)
    return CodexHookInventory(str(source_path), tuple(records), tuple(issues))


def _is_codex_hook_state_metadata(
    event_name: object,
    value: object,
    source_format: HookSourceFormat,
) -> bool:
    """Recognize Codex's reserved TOML hook-state metadata table."""

    return (
        source_format == "toml"
        and event_name == "state"
        and isinstance(value, Mapping)
        and all(
            isinstance(coordinate, str)
            and isinstance(state_entry, Mapping)
            and len(state_entry) == 1
            and "trusted_hash" in state_entry
            and _is_trusted_hook_hash(state_entry.get("trusted_hash"))
            for coordinate, state_entry in value.items()
        )
    )


def _is_trusted_hook_hash(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("sha256:")
        and len(value) == 71
        and all(character in "0123456789abcdefABCDEF" for character in value[7:])
    )


def _handler_record(
    handler: object,
    *,
    source_path: Path,
    source_scope: str,
    source_format: HookSourceFormat,
    source_hooks_enabled: bool,
    event_name: str,
    group_index: int,
    matcher: object,
    handler_index: int,
    group_active: bool,
    authenticated_bindings: Sequence[Mapping[str, object]],
    legacy_bindings: Sequence[Mapping[str, object]],
    group: Mapping[str, object],
) -> tuple[CodexHookInventoryRecord | None, tuple[CodexHookInventoryIssue, ...]]:
    if not isinstance(handler, Mapping):
        return None, (
            _handler_issue(
                CODEX_HOOK_INVENTORY_MALFORMED_HANDLER,
                "Each Codex hook handler must be an object. Repair the handler before retrying install.",
                source_path,
                event_name,
                group_index,
                handler_index,
            ),
        )
    raw_type = handler.get("type")
    handler_type = raw_type if isinstance(raw_type, str) and raw_type.strip() else None
    raw_command = handler.get("command")
    command = raw_command if isinstance(raw_command, str) and raw_command.strip() else None
    executable = raw_command is not None or handler_type == "command"
    issues: list[CodexHookInventoryIssue] = []
    if not _activation_fields_are_valid(handler):
        issues.append(
            _handler_issue(
                CODEX_HOOK_INVENTORY_MALFORMED_HANDLER,
                "Codex hook activation fields must be booleans. Repair the handler before retrying install.",
                source_path,
                event_name,
                group_index,
                handler_index,
            )
        )
    if executable and command is None:
        issues.append(
            _handler_issue(
                CODEX_HOOK_INVENTORY_MALFORMED_HANDLER,
                "An executable Codex command hook must contain a non-empty string command. Repair the handler "
                "before retrying install.",
                source_path,
                event_name,
                group_index,
                handler_index,
            )
        )
    if handler_type not in {None, "command"}:
        issues.append(
            _handler_issue(
                CODEX_HOOK_INVENTORY_UNKNOWN_HANDLER,
                "Guard found an executable Codex hook type it cannot model. Remove or convert the handler to a "
                "supported command hook before retrying install.",
                source_path,
                event_name,
                group_index,
                handler_index,
            )
        )
    timeout = _timeout(handler.get("timeout"))
    if handler.get("timeout") is not None and timeout is None and executable:
        issues.append(
            _handler_issue(
                CODEX_HOOK_INVENTORY_MALFORMED_HANDLER,
                "An executable Codex hook timeout must be a finite non-negative number. Repair the handler before "
                "retrying install.",
                source_path,
                event_name,
                group_index,
                handler_index,
            )
        )
    environment_keys, environment_valid = _environment_keys(handler)
    if not environment_valid and executable:
        issues.append(
            _handler_issue(
                CODEX_HOOK_INVENTORY_MALFORMED_HANDLER,
                "An executable Codex hook environment must be a string-keyed object. Repair the handler before "
                "retrying install.",
                source_path,
                event_name,
                group_index,
                handler_index,
            )
        )
    ownership = _ownership(
        event_name,
        group,
        handler,
        authenticated_bindings=authenticated_bindings,
        legacy_bindings=legacy_bindings,
    )
    command_argv = canonical_codex_command_argv(command)
    canonical_identity = canonical_codex_hook_identity(
        source_scope=source_scope,
        source_hooks_enabled=source_hooks_enabled,
        event_name=event_name,
        group=group,
        handler=handler,
    )
    record = CodexHookInventoryRecord(
        source_path=str(source_path),
        source_scope=source_scope,
        source_format=source_format,
        source_hooks_enabled=source_hooks_enabled,
        event_name=event_name,
        group_index=group_index,
        matcher=matcher,
        handler_index=handler_index,
        handler_type=handler_type,
        command=command,
        command_argv=command_argv,
        timeout=timeout,
        environment_keys=environment_keys,
        active=group_active and _entry_is_active(handler),
        executable=executable,
        ownership=ownership,
        canonical_identity=canonical_identity,
    )
    return record, tuple(issues)


def _handler_issue(
    reason_code: str,
    message: str,
    source_path: Path,
    event_name: str,
    group_index: int,
    handler_index: int,
) -> CodexHookInventoryIssue:
    return CodexHookInventoryIssue(
        reason_code,
        message,
        str(source_path),
        event_name,
        group_index,
        handler_index,
    )


def _entry_is_active(entry: Mapping[str, object]) -> bool:
    return entry.get("enabled") is not False and entry.get("disabled") is not True


def _activation_fields_are_valid(entry: Mapping[str, object]) -> bool:
    return all(key not in entry or isinstance(entry[key], bool) for key in ("enabled", "disabled"))


def _timeout(value: object) -> int | float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    if value < 0 or not math.isfinite(value):
        return None
    return value


def _environment_keys(handler: Mapping[str, object]) -> tuple[tuple[str, ...], bool]:
    raw_environment = handler.get("env", handler.get("environment"))
    if raw_environment is None:
        return (), True
    if not isinstance(raw_environment, Mapping) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in raw_environment.items()
    ):
        return (), False
    return tuple(sorted(raw_environment)), True


def _ownership(
    event_name: str,
    group: Mapping[str, object],
    handler: Mapping[str, object],
    *,
    authenticated_bindings: Sequence[Mapping[str, object]],
    legacy_bindings: Sequence[Mapping[str, object]],
) -> HookOwnership:
    if _bindings_contain_handler(authenticated_bindings, event_name, group, handler):
        return "authenticated_manifest"
    if _bindings_contain_handler(legacy_bindings, event_name, group, handler):
        return "exact_legacy_adoption"
    return "unmanaged"


def _bindings_contain_handler(
    bindings: Sequence[Mapping[str, object]],
    event_name: str,
    group: Mapping[str, object],
    handler: Mapping[str, object],
) -> bool:
    for binding in bindings:
        expected_group = binding.get("group")
        if (
            binding.get("event") == event_name
            and isinstance(expected_group, Mapping)
            and expected_group.get("matcher") == group.get("matcher")
            and binding.get("handler") == handler
        ):
            return True
    return False


__all__ = [
    "CODEX_HOOK_IDENTITY_SCHEMA",
    "CODEX_HOOK_INVENTORY_MALFORMED_GROUP",
    "CODEX_HOOK_INVENTORY_MALFORMED_HANDLER",
    "CODEX_HOOK_INVENTORY_SOURCE_CHANGED",
    "CODEX_HOOK_INVENTORY_SOURCE_DUPLICATE",
    "CODEX_HOOK_INVENTORY_SOURCE_MALFORMED",
    "CODEX_HOOK_INVENTORY_SOURCE_UNREADABLE",
    "CODEX_HOOK_INVENTORY_UNKNOWN_HANDLER",
    "CODEX_HOOK_INVENTORY_UNMANAGED_EXECUTABLE",
    "CODEX_HOOK_INVENTORY_UNSUPPORTED_EVENT",
    "CodexHookInventory",
    "CodexHookInventoryIssue",
    "CodexHookInventoryRecord",
    "canonical_codex_command_argv",
    "canonical_codex_hook_conflict_keys",
    "canonical_codex_hook_group_identity",
    "canonical_codex_hook_identity",
    "enumerate_codex_hooks",
]
