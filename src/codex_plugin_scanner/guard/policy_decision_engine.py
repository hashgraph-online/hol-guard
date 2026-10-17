"""Decide one event against a policy document and explain every rule that was considered.

The decision follows the runtime non-consuming lookup (block beats allow, then scope specificity) and
is reported in the shape the Policy Studio Explain panel renders, described by
``spec/guard-policy/v1alpha1/decision.schema.json``. The ranking itself belongs to the runtime: this
module compiles the document, narrows the event and asks the resident, so ``policy check`` and
``policy test`` cannot answer differently from the store lookup that enforces the same rules. Without
the native runtime they fail closed rather than fall back to a second opinion. Tests compare the
answer with the runtime store lookup on the recorded parity events.
"""

from __future__ import annotations

import calendar
import re
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Final, cast

from .business_policy_document_import import compile_document_for_import
from .native_policy_document_decision import native_policy_document_decision
from .policy_document import GuardPolicyDocument
from .policy_document_diagnostics import COMMAND_EXPRESSION_CODE
from .policy_document_io import PolicyCompilationError
from .policy_document_types import CompiledPolicyRow
from .runtime.command_policy import CommandPolicyRule, compile_command_policy_rules
from .runtime.command_policy import evaluate_command_policy_rules as _evaluate_command_rules

POLICY_TOOL_FAMILIES: Final = (
    "file-read",
    "mcp",
    "mcp-tool",
    "package-request",
    "prompt",
    "prompt-env-read",
    "prompt-file",
    "tool-action",
)
_APPROVAL_FAMILIES: Final = frozenset(POLICY_TOOL_FAMILIES)
_EVENT_FIELDS: Final = frozenset({"harness", "artifact", "tool", "publisher", "workspace", "at"})
_TIMESTAMP: Final = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$")


class PolicyEventError(ValueError):
    """An event the evaluator cannot decide because the event itself is malformed."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class PolicyEvent:
    harness: str
    artifact: str | None = None
    tool: str | None = None
    publisher: str | None = None
    workspace: str | None = None
    at: str | None = None


def timestamp_nanos(value: str) -> int | None:
    """Nanoseconds since the epoch for a canonical UTC timestamp, or ``None`` when it is not one."""

    match = _TIMESTAMP.fullmatch(value)
    if match is None:
        return None
    year, month, day, hour, minute, second = (int(part) for part in match.groups()[:6])
    try:
        datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except ValueError:
        return None
    fraction = (match.group(7) or "").ljust(9, "0")
    seconds = calendar.timegm((year, month, day, hour, minute, second))
    return seconds * 1_000_000_000 + int(fraction or "0")


def parse_event(value: object) -> PolicyEvent:
    """Validate an event mapping the same way the ``x-hol.tests`` schema does."""

    if not isinstance(value, dict):
        raise PolicyEventError("event_not_object", "An event must be a JSON object.")
    unknown = sorted(str(key) for key in value if key not in _EVENT_FIELDS)
    if unknown:
        raise PolicyEventError(
            "event_unknown_field",
            f"Unknown event field: {unknown[0][:40]}. Allowed: {', '.join(sorted(_EVENT_FIELDS))}.",
        )
    fields: dict[str, str | None] = {}
    for key in _EVENT_FIELDS:
        item = value.get(key)
        if item is None:
            fields[key] = None
        elif isinstance(item, str) and 0 < len(item) <= 512:
            fields[key] = item
        else:
            raise PolicyEventError("event_field_invalid", f"Event field {key} must be a non-empty string.")
    if fields["harness"] is None:
        raise PolicyEventError("event_harness_required", "An event needs a harness, for example codex.")
    if fields["artifact"] is not None and fields["tool"] is not None:
        raise PolicyEventError("event_artifact_and_tool", "An event names an artifact or a tool, not both.")
    tool = fields["tool"]
    if tool is not None and tool.lower() != "shell" and tool.lower() not in _APPROVAL_FAMILIES:
        raise PolicyEventError(
            "event_tool_unknown",
            f"Unknown tool family. Use one of: {', '.join(POLICY_TOOL_FAMILIES)}, or shell.",
        )
    at = fields["at"]
    if at is not None and timestamp_nanos(at) is None:
        raise PolicyEventError("event_time_invalid", "Event time must be a UTC timestamp such as 2026-10-14T12:00:00Z.")
    return PolicyEvent(
        harness=cast(str, fields["harness"]),
        artifact=fields["artifact"],
        tool=tool,
        publisher=fields["publisher"],
        workspace=fields["workspace"],
        at=at,
    )


def _wire_row(row: CompiledPolicyRow) -> dict[str, object]:
    """One compiled row in the shape the resident's typed request reads."""

    decision = row.decision
    return {
        "rule_id": row.rule_id,
        "harness": decision.harness,
        "scope": decision.scope,
        "action": decision.action,
        "artifact_id": decision.artifact_id,
        "artifact_hash": decision.artifact_hash,
        "workspace": decision.workspace,
        "publisher": decision.publisher,
        "expires_at": decision.expires_at,
    }


def decide_rows(
    rows: tuple[CompiledPolicyRow, ...],
    event: PolicyEvent,
    *,
    now: str,
    guard_home: Path | None = None,
) -> dict[str, object]:
    """Decide ``event`` against compiled rows and return the portal Explain shape.

    The runtime ranks the rows; a malformed evaluation time is still reported here, because that is a
    fault in the request rather than a decision about it.
    """

    if timestamp_nanos(event.at or now) is None:
        raise PolicyEventError("event_time_invalid", "Evaluation time must be a UTC timestamp.")
    return native_policy_document_decision(
        [_wire_row(row) for row in rows],
        {
            "harness": event.harness,
            "artifact": event.artifact,
            "tool": event.tool,
            "publisher": event.publisher,
            "workspace": event.workspace,
            "at": event.at,
        },
        now=now,
        guard_home=guard_home,
    )


def decide_command(document: GuardPolicyDocument, command: str, *, now: str) -> dict[str, object]:
    """Decide a shell command against the typed command-expression rules of ``document``."""

    rules: tuple[CommandPolicyRule, ...] = compile_command_policy_rules(document)
    evaluation = _evaluate_command_rules(rules, command)
    matching = set(evaluation.matching_rule_ids)
    # The evaluation lists matches in document order; the deciding rule is the first one that asked for the
    # strongest action, and only matches with that same action tie with it.
    selected = next(
        (rule.rule_id for rule in rules if rule.rule_id in matching and rule.action == evaluation.action), None
    )
    candidates: list[dict[str, object]] = []
    tied: list[str] = []
    for index, rule in enumerate(rules):
        if rule.rule_id not in matching:
            candidates.append({"ruleId": rule.rule_id, "rowIndex": index, "state": "unmatched", "reason": "command"})
        elif rule.rule_id == selected:
            candidates.append({"ruleId": rule.rule_id, "rowIndex": index, "state": "selected", "reason": None})
        elif rule.action != evaluation.action:
            candidates.append({"ruleId": rule.rule_id, "rowIndex": index, "state": "outranked", "reason": "block_wins"})
        else:
            tied.append(rule.rule_id)
            candidates.append({"ruleId": rule.rule_id, "rowIndex": index, "state": "outranked", "reason": "tie"})
    effect = evaluation.action if matching and evaluation.action in ("allow", "block") else "default"
    decision: dict[str, object] = {
        "effect": effect,
        "ruleId": selected,
        "ambiguous": bool(tied),
        "matchLimitExceeded": False,
        "tiedRuleIds": sorted(tied),
        "candidates": candidates,
        "lookup": {"artifactId": None, "familyKey": None, "at": now},
    }
    if matching:
        decision["action"] = evaluation.action
    return decision


def compile_local_rows(document: GuardPolicyDocument) -> tuple[CompiledPolicyRow, ...]:
    """Compiled rows for local evaluation.

    Command-expression rules need the Guard 3.1 runtime and have no local row, so they are left out and
    the rest of the document still decides tool and artifact events.
    """

    try:
        return tuple(compile_document_for_import(document))
    except PolicyCompilationError as error:
        if error.code != COMMAND_EXPRESSION_CODE:
            raise
    portable = replace(document, rules=tuple(rule for rule in document.rules if rule.match.command_expression is None))
    return tuple(compile_document_for_import(portable))


__all__ = [
    "POLICY_TOOL_FAMILIES",
    "PolicyEvent",
    "PolicyEventError",
    "compile_local_rows",
    "decide_command",
    "decide_rows",
    "parse_event",
    "timestamp_nanos",
]
