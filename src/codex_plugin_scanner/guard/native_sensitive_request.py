"""Bound resident transport for the sensitive-request classifiers.

Python sends the tool call, its own observations and the caller's canonical
command and native evaluation. The resident reparses the command, re-proves
git trust, derives extension-control authority and answers; a canonical claim
binds only when the resident's parse has the same security identity. Missing
or malformed replies raise rather than read as "not sensitive".
"""

from __future__ import annotations

import os
import shutil
from dataclasses import fields, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from . import native_git_execution_safety
from .native_direct_tool_context import _facts
from .native_git_execution_safety import _environment_snapshot
from .native_request_context import NativeRequestContextFailure, _call
from .runtime.command_model import _canonical_from_wire
from .runtime.secret_file_request_services.request_models import (
    FileReadRequestMatch,
    FileWriteRequestMatch,
    ToolActionRequestMatch,
)
from .runtime.secret_sensitivity import SecretPathMatch

if TYPE_CHECKING:
    from .models import GuardArtifact
    from .runtime.actions import GuardActionEnvelope
    from .runtime.command_evaluation import CompositeCommandEvaluation
    from .runtime.command_model import CanonicalCommand

_BUDGET_MS = 9_000
_PATH_FIELDS = frozenset({"family", "path", "reason", "requested_path", "sensitivity"})
_READ_FIELDS = frozenset({"tool_name", "normalized_tool_name", "path_match"})
_WRITE_FIELDS = frozenset(item.name for item in fields(FileWriteRequestMatch))
_TOOL_ACTION_FIELDS = frozenset(item.name for item in fields(ToolActionRequestMatch))
_TUPLE_FIELDS = frozenset(
    {
        "wrapper_chain",
        "shell_execution_effective_cwds",
        "pytest_config_sources",
        "pytest_config_reason_codes",
    }
)
_REQUIRED_TEXT = frozenset({"tool_name", "normalized_tool_name", "command_text", "action_class", "reason"})
_OPTIONAL_TEXT = frozenset(
    {
        "raw_command_text",
        "shell_execution_context_hash",
        "shell_execution_context_reason_code",
        "guard_default_action",
        "reason_code",
        "restricted_profile_version",
        "pytest_config_identity_sha256",
        "script_read_identity_sha256",
    }
)
_SENSITIVITIES = frozenset({"high", "critical"})
# Names the native classifiers read that neither shared snapshot carries.
_CLASSIFIER_ENVIRONMENT_NAMES = ("GH_HOST", "GH_PAGER", "PAGER", "RIPGREP_CONFIG_PATH", "TMPDIR", "TEMP", "TMP")


class NativeSensitiveRequestError(RuntimeError):
    """The resident gave no authoritative answer; ``code`` says why."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _git_executable() -> str | None:
    found = shutil.which("git")
    return found if found is not None and os.path.isabs(found) else None


def _control_snapshot() -> dict[str, object] | None:
    from .cli.commands_hook_native_generic_facts import _control_snapshot as snapshot

    return snapshot()


def _path_text(value: Path | None) -> str | None:
    return None if value is None else str(value)


def _ask(query: str, input_value: dict[str, Any], *, cwd: Path | None, home_dir: Path | None) -> Any:
    facts = _facts(cwd or Path.cwd(), home_dir or Path.home())
    environment = dict(_environment_snapshot())
    environment.update(cast("dict[str, str]", facts["environment"]))
    environment.update(
        (name, value) for name in _CLASSIFIER_ENVIRONMENT_NAMES if (value := os.environ.get(name)) is not None
    )
    facts["environment"] = environment
    payload = _call(
        {
            "kind": "sensitive_request",
            "body": {
                "query": query,
                "input": {**input_value, "cwd": _path_text(cwd), "home_dir": _path_text(home_dir)},
                "facts": facts,
                "git_executable": _git_executable(),
                "control_snapshot": _control_snapshot(),
            },
        },
        source="hook",
        guard_home=None,
        budget_ms=_BUDGET_MS,
    )
    if isinstance(payload, NativeRequestContextFailure):
        raise NativeSensitiveRequestError(payload.code)
    if set(payload) != {"kind", "query", "result"} or payload["kind"] != "sensitive_request":
        raise NativeSensitiveRequestError("native_sensitive_request_reply_invalid")
    if payload["query"] != query:
        raise NativeSensitiveRequestError("native_sensitive_request_reply_invalid")
    return payload["result"]


def _invalid() -> NativeSensitiveRequestError:
    return NativeSensitiveRequestError("native_sensitive_request_reply_invalid")


def _text(value: object) -> str:
    if not isinstance(value, str):
        raise _invalid()
    return value


def _optional_text(value: object) -> str | None:
    return None if value is None else _text(value)


def _object(value: object, names: frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != names:
        raise _invalid()
    return cast("dict[str, Any]", value)


def _path_match(value: object) -> SecretPathMatch:
    wire = _object(value, _PATH_FIELDS)
    sensitivity = _text(wire["sensitivity"])
    if sensitivity not in _SENSITIVITIES:
        raise _invalid()
    return SecretPathMatch(
        family=_text(wire["family"]),
        path=_text(wire["path"]),
        sensitivity=cast("Any", sensitivity),
        reason=_text(wire["reason"]),
        requested_path=_text(wire["requested_path"]),
    )


def _read_match(value: object) -> FileReadRequestMatch | None:
    if value is None:
        return None
    wire = _object(value, _READ_FIELDS)
    return FileReadRequestMatch(
        tool_name=_text(wire["tool_name"]),
        normalized_tool_name=_text(wire["normalized_tool_name"]),
        path_match=_path_match(wire["path_match"]),
    )


def _bool(value: object) -> bool:
    if not isinstance(value, bool):
        raise _invalid()
    return value


def _canonical_claim(command: CanonicalCommand | None) -> dict[str, str] | None:
    if command is None:
        return None
    return {
        "raw_text": command.raw_text,
        "security_identity": command.security_identity,
        "dialect": command.dialect,
        "transport": command.transport,
        "extraction_provenance": command.extraction_provenance,
    }


def _evaluation_view(evaluation: CompositeCommandEvaluation | None) -> dict[str, object] | None:
    """The evaluation fields the classifier reads, bound to the evaluated command."""

    if evaluation is None:
        return None
    return {
        "security_identity": evaluation.command.security_identity,
        "minimum_action": evaluation.minimum_action,
        "match_default_modes": [owned.match.rule.default_mode for owned in evaluation.matches],
        "reason_codes": [reason.reason_code for reason in evaluation.decision_plane.reasons],
        "explicitly_enabled_permission_ids": list(evaluation.control_resolution.explicitly_enabled_permission_ids),
        "controlling_action_class": evaluation.controlling_action_class,
        "controlling_reason": evaluation.controlling_reason,
    }


def _string_tuple(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise _invalid()
    return tuple(value)


def _tool_action_match(value: object, canonical: CanonicalCommand | None) -> ToolActionRequestMatch:
    wire = _object(value, _TOOL_ACTION_FIELDS)
    values: dict[str, Any] = {}
    for name, item in wire.items():
        if name == "canonical_command":
            continue
        if name in _TUPLE_FIELDS:
            values[name] = _string_tuple(item)
        elif name == "interpreter_executable_identities":
            if not isinstance(item, list) or any(not isinstance(entry, dict) for entry in item):
                raise _invalid()
            values[name] = tuple(item)
        elif name in _REQUIRED_TEXT:
            values[name] = _text(item)
        elif name in _OPTIONAL_TEXT:
            values[name] = _optional_text(item)
        else:
            raise _invalid()
    command_wire = wire["canonical_command"]
    if command_wire is not None:
        if not isinstance(command_wire, dict):
            raise _invalid()
        if canonical is not None and command_wire.get("security_identity") == canonical.security_identity:
            values["canonical_command"] = canonical
        else:
            try:
                values["canonical_command"] = _canonical_from_wire(command_wire)
            except (KeyError, TypeError, ValueError) as error:
                raise _invalid() from error
    return ToolActionRequestMatch(**values)


def native_sensitive_tool_action_request(
    tool_name: object,
    arguments: object,
    *,
    cwd: Path | None,
    home_dir: Path | None,
    canonical_command: CanonicalCommand | None,
    native_evaluation: CompositeCommandEvaluation | None,
) -> ToolActionRequestMatch | None:
    result = _ask(
        "tool_action",
        {
            "tool_name": tool_name,
            "arguments": arguments,
            "canonical": _canonical_claim(canonical_command),
            "evaluation": _evaluation_view(native_evaluation),
        },
        cwd=cwd,
        home_dir=home_dir,
    )
    if isinstance(result, dict) and set(result) == {"error"}:
        raise ValueError(_text(result["error"]))
    wire = _object(result, frozenset({"match"}))
    if wire["match"] is None:
        return None
    return _tool_action_match(wire["match"], canonical_command)


def native_sensitive_file_read_request(
    tool_name: object, arguments: object, *, cwd: Path | None, home_dir: Path | None
) -> FileReadRequestMatch | None:
    result = _ask(
        "file_read",
        {"tool_name": tool_name, "arguments": arguments},
        cwd=cwd,
        home_dir=home_dir or Path.home(),
    )
    return _read_match(result)


def native_sensitive_file_read_request_from_action(
    action: GuardActionEnvelope, *, cwd: Path | None, home_dir: Path | None
) -> FileReadRequestMatch | None:
    projection = {
        "action_type": action.action_type,
        "tool_name": action.tool_name,
        "target_paths": list(action.target_paths),
    }
    result = _ask("file_read_from_action", {"action": projection}, cwd=cwd, home_dir=home_dir or Path.home())
    return _read_match(result)


def native_sensitive_file_write_request(
    tool_name: object,
    arguments: object,
    *,
    cwd: Path | None,
    home_dir: Path | None,
    protected_paths: dict[str, str] | None,
) -> FileWriteRequestMatch | None:
    result = _ask(
        "file_write",
        {"tool_name": tool_name, "arguments": arguments, "protected_paths": protected_paths},
        cwd=cwd,
        home_dir=home_dir or Path.home(),
    )
    if result is None:
        return None
    wire = _object(result, _WRITE_FIELDS)
    return FileWriteRequestMatch(**{name: _text(value) for name, value in wire.items()})


def native_command_list_candidate_texts(values: list[str], *, preserve_items: bool) -> tuple[str, ...]:
    result = _ask(
        "command_list_candidate_texts",
        {"values": values, "preserve_items": preserve_items},
        cwd=None,
        home_dir=None,
    )
    if not isinstance(result, list):
        raise _invalid()
    return tuple(_text(item) for item in result)


def native_benign_file_read(tool_name: object, arguments: object, *, cwd: Path | None, home_dir: Path | None) -> bool:
    return _bool(_ask("benign_file_read", {"tool_name": tool_name, "arguments": arguments}, cwd=cwd, home_dir=home_dir))


def native_unmodeled_shell_artifact(
    command_text: str, *, workspace: Path | None, home_dir: Path
) -> tuple[str, dict[str, object]] | None:
    """The fingerprint and metadata of the one review an incompletely modeled shell command needs."""

    result = _ask(
        "unmodeled_shell_artifact",
        {
            "command_text": command_text,
            "workspace": _path_text(workspace),
            "home": str(home_dir),
            "account_home": native_git_execution_safety._account_home_directory(),
        },
        cwd=None,
        home_dir=None,
    )
    if result is None:
        return None
    wire = _object(result, frozenset({"fingerprint", "metadata"}))
    pairs = wire["metadata"]
    if not isinstance(pairs, list) or not all(
        isinstance(pair, list) and len(pair) == 2 and isinstance(pair[0], str) for pair in pairs
    ):
        raise _invalid()
    return _text(wire["fingerprint"]), dict(pairs)


# The finding fields the resident reads when it binds findings to one command.
_COMPOUND_FINDING_FIELDS = (
    "action_class",
    "command_rule_matches",
    "risk_classes",
    "runtime_request_reason",
    "runtime_request_signals",
    "runtime_request_summary",
)


def native_compound_artifact(
    artifacts: list[GuardArtifact],
    *,
    command_text: str | None,
    decision: dict[str, object],
    workspace: Path | None,
    home_dir: Path,
) -> GuardArtifact:
    """The findings bound to the whole command, or the primary alone (resident-owned)."""

    findings = [
        {
            "artifact_id": artifact.artifact_id,
            "artifact_type": artifact.artifact_type,
            "name": artifact.name,
            "metadata": {key: artifact.metadata[key] for key in _COMPOUND_FINDING_FIELDS if key in artifact.metadata},
        }
        for artifact in artifacts
    ]
    reply = _ask(
        "compound_artifact",
        {"artifacts": findings, "command_text": command_text, "decision": decision},
        cwd=workspace,
        home_dir=home_dir,
    )
    index = reply.get("primary") if isinstance(reply, dict) else None
    if type(index) is not int or not 0 <= index < len(artifacts):
        raise _invalid()
    primary = artifacts[index]
    if set(reply) == {"primary", "metadata"} and reply["metadata"] is None:
        return primary
    pairs = reply.get("metadata")
    if set(reply) != {"primary", "artifact_id", "name", "metadata"} or not isinstance(pairs, list):
        raise _invalid()
    if not all(isinstance(pair, list) and len(pair) == 2 and isinstance(pair[0], str) for pair in pairs):
        raise _invalid()
    metadata = dict(primary.metadata)
    if len(artifacts) > 1:
        # The hint only covers the extension evaluation; other findings keep reviewing.
        metadata.pop("extension_allow_hint", None)
    metadata.update((key, value) for key, value in pairs)
    return replace(primary, artifact_id=_text(reply["artifact_id"]), name=_text(reply["name"]), metadata=metadata)


def native_read_only_lookup_target_is_safe(target: str, *, allow_dirs: bool, home_dir: Path | None) -> bool:
    return _bool(
        _ask(
            "read_only_lookup_target_is_safe",
            {"target": target, "allow_dirs": allow_dirs},
            cwd=None,
            home_dir=home_dir,
        )
    )
