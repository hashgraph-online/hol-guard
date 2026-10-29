"""Complete typed inventory for executable Codex hook configuration."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from .codex_hook_identity import (
    CodexHookDefinitionTooDeepError,
    CodexHookIdentityUnavailableError,
)
from .native_codex_hook_identity import CODEX_HOOK_INVENTORY_FEATURE, native_codex_hook_identity

CODEX_HOOK_INVENTORY_UNMANAGED_EXECUTABLE = "codex_hook_inventory_unmanaged_executable"
CODEX_HOOK_INVENTORY_UNSUPPORTED_EVENT = "codex_hook_inventory_unsupported_event_shape"
CODEX_HOOK_INVENTORY_MALFORMED_GROUP = "codex_hook_inventory_malformed_group"
CODEX_HOOK_INVENTORY_MALFORMED_HANDLER = "codex_hook_inventory_malformed_handler"
CODEX_HOOK_INVENTORY_UNKNOWN_HANDLER = "codex_hook_inventory_unknown_handler_type"
CODEX_HOOK_INVENTORY_SOURCE_DUPLICATE = "codex_hook_inventory_source_duplicate_key"
CODEX_HOOK_INVENTORY_SOURCE_MALFORMED = "codex_hook_inventory_source_malformed"
CODEX_HOOK_INVENTORY_SOURCE_UNREADABLE = "codex_hook_inventory_source_unreadable"
CODEX_HOOK_INVENTORY_SOURCE_CHANGED = "codex_hook_inventory_source_changed"
# The identity failures a source can carry, named here for callers that match
# on a reason code. Each is the ``code`` of the error the bridge raises.
CODEX_HOOK_INVENTORY_IDENTITY_UNAVAILABLE = CodexHookIdentityUnavailableError.code
CODEX_HOOK_INVENTORY_DEFINITION_TOO_DEEP = CodexHookDefinitionTooDeepError.code
HookSourceFormat = Literal["json", "toml"]
HookOwnership = Literal["authenticated_manifest", "exact_legacy_adoption", "self_install_binding", "unmanaged"]


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
    self_bindings: Sequence[Mapping[str, object]] = (),
) -> CodexHookInventory:
    """Every event, group, and handler accepted by the Codex hook shape.

    The resident walks the source, the same walk native detection runs, and
    answers with each handler's record and identity and every shape it cannot
    model. A source without hooks has nothing to walk.
    """

    hooks = payload.get("hooks")
    if hooks is None:
        return CodexHookInventory(str(source_path), (), ())
    shared = {
        "kind": "inventory",
        "source_scope": source_scope,
        "source_hooks_enabled": source_hooks_enabled,
        "source_format": source_format,
        "authenticated_bindings": authenticated_bindings,
        "legacy_bindings": legacy_bindings,
        "self_bindings": self_bindings,
    }
    # The walk reads each event on its own, so one entry per event lets a large
    # source split across requests without changing what any event answers.
    events = [{name: groups} for name, groups in hooks.items()] if isinstance(hooks, Mapping) else [hooks]
    try:
        answers = native_codex_hook_identity(
            [{**shared, "hooks": event} for event in events], required_feature=CODEX_HOOK_INVENTORY_FEATURE
        )
        records = tuple(
            _record(item, str(source_path), source_scope, source_format, source_hooks_enabled)
            for answer in answers
            for item in _list_of(answer, "records")
        )
        issues = tuple(_issue(item, str(source_path)) for answer in answers for item in _list_of(answer, "issues"))
    except CodexHookIdentityUnavailableError as error:
        return CodexHookInventory(str(source_path), (), (_unidentified_source_issue(source_path, error),))
    return CodexHookInventory(str(source_path), records, issues)


def _unidentified_source_issue(
    source_path: Path,
    error: CodexHookIdentityUnavailableError,
) -> CodexHookInventoryIssue:
    """Report a source Guard cannot identify rather than one with no hooks.

    The resident owns hook identity. With no answer there is nothing to compare
    against the manifest, so every handler in the source would read as unowned;
    an issue keeps the caller on its fail-closed path instead. The error's own
    code travels with it, so a definition the resident will not read stays
    distinguishable from a resident that could not answer at all.
    """

    return CodexHookInventoryIssue(
        error.code,
        "Guard's native runtime did not identify this source's Codex hooks. Repair whichever the code names, "
        "the Guard installation or the hook definition, before retrying install.",
        str(source_path),
    )


def _list_of(answer: Mapping[str, object], key: str) -> list[Mapping[str, object]]:
    """The answer's list of objects under ``key``; anything else is no answer."""

    items = answer.get(key)
    if not isinstance(items, list) or not all(isinstance(item, Mapping) for item in items):
        raise CodexHookIdentityUnavailableError
    return items


def _field(item: Mapping[str, object], key: str, kind: type | tuple[type, ...]) -> object:
    value = item.get(key)
    if not isinstance(value, kind) or (isinstance(value, bool) and bool not in _kinds(kind)):
        raise CodexHookIdentityUnavailableError
    return value


def _kinds(kind: type | tuple[type, ...]) -> tuple[type, ...]:
    return kind if isinstance(kind, tuple) else (kind,)


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise CodexHookIdentityUnavailableError
    return tuple(value)


def _record(
    item: Mapping[str, object],
    source_path: str,
    source_scope: str,
    source_format: HookSourceFormat,
    source_hooks_enabled: bool,
) -> CodexHookInventoryRecord:
    """One record the resident answered, checked field by field."""

    ownership = _field(item, "ownership", str)
    identity = _field(item, "canonical_identity", str)
    if ownership not in _OWNERSHIPS or not identity:
        raise CodexHookIdentityUnavailableError
    argv = item.get("command_argv")
    return CodexHookInventoryRecord(
        source_path=source_path,
        source_scope=source_scope,
        source_format=source_format,
        source_hooks_enabled=source_hooks_enabled,
        event_name=cast("str", _field(item, "event_name", str)),
        group_index=cast("int", _field(item, "group_index", int)),
        matcher=_field(item, "matcher", (str, type(None))),
        handler_index=cast("int", _field(item, "handler_index", int)),
        handler_type=cast("str | None", _field(item, "handler_type", (str, type(None)))),
        command=cast("str | None", _field(item, "command", (str, type(None)))),
        command_argv=None if argv is None else _strings(argv),
        timeout=cast("int | float | None", _field(item, "timeout", (int, float, type(None)))),
        environment_keys=_strings(item.get("environment_keys")),
        active=cast("bool", _field(item, "active", bool)),
        executable=cast("bool", _field(item, "executable", bool)),
        ownership=cast("HookOwnership", ownership),
        canonical_identity=cast("str", identity),
    )


def _issue(item: Mapping[str, object], source_path: str) -> CodexHookInventoryIssue:
    return CodexHookInventoryIssue(
        cast("str", _field(item, "reason_code", str)),
        cast("str", _field(item, "message", str)),
        source_path,
        cast("str | None", _field(item, "event_name", (str, type(None)))),
        cast("int | None", _field(item, "group_index", (int, type(None)))),
        cast("int | None", _field(item, "handler_index", (int, type(None)))),
    )


_OWNERSHIPS = frozenset(("authenticated_manifest", "exact_legacy_adoption", "self_install_binding", "unmanaged"))


__all__ = [
    "CODEX_HOOK_INVENTORY_DEFINITION_TOO_DEEP",
    "CODEX_HOOK_INVENTORY_IDENTITY_UNAVAILABLE",
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
    "enumerate_codex_hooks",
]
