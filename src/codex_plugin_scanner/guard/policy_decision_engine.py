"""Decide one event against a policy document and explain every rule that was considered.

The decision follows the runtime non-consuming lookup (block beats allow, then scope specificity) and
is reported in the shape the Policy Studio Explain panel renders, described by
``spec/guard-policy/v1alpha1/decision.schema.json``. The evaluation is pure: it never opens the local
store, the keyring or a native resident process, so ``policy check`` and ``policy test`` are safe to run
anywhere, including CI. Tests compare it with the runtime store lookup on the recorded parity events.
"""

from __future__ import annotations

import calendar
import hashlib
import re
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Final, cast

from .business_policy_document_import import compile_document_for_import
from .models import PolicyDecision
from .policy_document import GuardPolicyDocument
from .policy_document_diagnostics import COMMAND_EXPRESSION_CODE
from .policy_document_io import PolicyCompilationError
from .policy_document_types import CompiledPolicyRow
from .runtime.command_policy import CommandPolicyRule, compile_command_policy_rules
from .runtime.command_policy import evaluate_command_policy_rules as _evaluate_command_rules

POLICY_MATCH_LIMIT: Final = 256
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
_EXACT_ONLY_FAMILIES: Final = frozenset({"file-read", "mcp-tool", "package-request", "prompt", "tool-action"})
_APPROVAL_CONTEXT_PREFIX: Final = "guard-approval-context:v1:"
_SCOPE_RANK: Final = {"artifact": 5, "workspace": 4, "publisher": 3, "harness": 2, "global": 1}
_PROBE_ORDER: Final = {"artifact": 0, "workspace": 1, "publisher": 2, "harness": 3, "global": 4}
_SEVERITY: Final = {"allow": 0, "block": 1}
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


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def tool_family_artifact_id(tool: str) -> str | None:
    normalized = tool.lower()
    if normalized == "shell":
        return "family:tool-action"
    return f"family:{normalized}" if normalized in _APPROVAL_FAMILIES else None


def artifact_family_key(artifact_id: str | None) -> str | None:
    value = (artifact_id or "").strip()
    if not value:
        return None
    if value.startswith("family:"):
        family: str | None = value[len("family:") :].strip().lower()
    else:
        parts = value.split(":")
        family = parts[2].strip().lower() if len(parts) > 2 else None
    return f"family:{family}" if family in _APPROVAL_FAMILIES else None


def _family_name(family_key: str) -> str:
    return family_key[len("family:") :] if family_key.startswith("family:") else family_key


def _normalized_workspace_path(value: str) -> str:
    normalized = value.strip().replace("\\", "/")
    while len(normalized) > 1 and normalized.endswith("/"):
        normalized = normalized[:-1]
    if len(normalized) >= 2 and normalized[1] == ":":
        normalized = normalized.lower()
    return normalized


def workspace_policy_key(workspace: str | None) -> str | None:
    if workspace is None or not workspace.strip():
        return None
    if workspace.startswith("workspace:"):
        return workspace
    return f"workspace:{_sha256_hex(_normalized_workspace_path(workspace))}"


@dataclass(frozen=True, slots=True)
class _Keys:
    harness: str
    artifact_id: str | None
    family_key: str | None
    workspace: str | None
    workspace_key: str | None
    publisher: str | None
    at: str
    at_nanos: int


def _runtime_exact_match_key(artifact_id: str | None) -> str | None:
    value = (artifact_id or "").strip()
    if not value or value.startswith("family:"):
        return None
    family_key = artifact_family_key(value)
    if family_key is None or _family_name(family_key) not in _EXACT_ONLY_FAMILIES:
        return None
    return f"runtime-exact:{_sha256_hex(value)}"


def _legacy_hash(artifact_hash: str | None) -> bool:
    return artifact_hash is None or not artifact_hash.startswith(_APPROVAL_CONTEXT_PREFIX)


def _artifact_selector_matches(decision: PolicyDecision, keys: _Keys, *, legacy_only: bool) -> bool:
    if decision.artifact_id is None:
        return True
    if decision.artifact_id not in (keys.artifact_id, keys.family_key):
        return False
    return decision.artifact_hash is None if legacy_only else _legacy_hash(decision.artifact_hash)


def _mismatch(decision: PolicyDecision, keys: _Keys) -> str | None:
    if decision.harness not in (keys.harness, "*"):
        return "harness"
    scope = decision.scope
    if scope == "artifact":
        ok = (
            keys.artifact_id is not None and decision.artifact_id == keys.artifact_id and decision.artifact_hash is None
        )
        return None if ok else "artifact"
    if scope == "workspace":
        stored = workspace_policy_key(decision.workspace)
        if stored is None or stored not in (keys.workspace_key, keys.workspace):
            return "workspace"
        return None if _artifact_selector_matches(decision, keys, legacy_only=True) else "artifact"
    if scope == "publisher":
        if keys.publisher is None or decision.publisher != keys.publisher:
            return "publisher"
        return None if _legacy_hash(decision.artifact_hash) else "artifact"
    return None if _artifact_selector_matches(decision, keys, legacy_only=False) else "artifact"


def _requires_exact_match(decision: PolicyDecision, keys: _Keys) -> bool:
    if decision.scope not in ("harness", "global"):
        return False
    family_key = artifact_family_key(decision.artifact_id)
    if family_key is None or _family_name(family_key) not in _EXACT_ONLY_FAMILIES:
        return False
    expected = _runtime_exact_match_key(keys.artifact_id)
    return expected is None or expected != (decision.artifact_hash or "")


def _specificity(decision: PolicyDecision, harness: str) -> tuple[int, ...]:
    return (
        _SCOPE_RANK[decision.scope],
        1 if decision.harness == harness else 0,
        0 if decision.artifact_hash is None else 1,
        0 if decision.artifact_id is None else 1,
        0 if decision.workspace is None else 1,
        0 if decision.publisher is None else 1,
    )


def _lookup_keys(event: PolicyEvent, now: str) -> _Keys:
    at = event.at or now
    nanos = timestamp_nanos(at)
    if nanos is None:
        raise PolicyEventError("event_time_invalid", "Evaluation time must be a UTC timestamp.")
    artifact_id = event.artifact or (tool_family_artifact_id(event.tool) if event.tool else None)
    return _Keys(
        harness=event.harness,
        artifact_id=artifact_id,
        family_key=artifact_family_key(artifact_id),
        workspace=event.workspace,
        workspace_key=workspace_policy_key(event.workspace),
        publisher=event.publisher,
        at=at,
        at_nanos=nanos,
    )


def _is_expired(decision: PolicyDecision, at_nanos: int) -> bool:
    if decision.expires_at is None:
        return False
    expires = timestamp_nanos(decision.expires_at)
    return expires is None or expires <= at_nanos


def _classify(rows: tuple[CompiledPolicyRow, ...], keys: _Keys) -> list[tuple[str, str | None]]:
    states: list[tuple[str, str | None]] = []
    for row in rows:
        failed = _mismatch(row.decision, keys)
        if failed is not None:
            states.append(("unmatched", failed))
        elif _is_expired(row.decision, keys.at_nanos):
            states.append(("expired", "expired"))
        elif _requires_exact_match(row.decision, keys):
            states.append(("not_enforced", "exact_only_family"))
        else:
            states.append(("matched", None))
    return states


def _pick_winner(rows: tuple[CompiledPolicyRow, ...], matched: list[int], harness: str) -> int | None:
    ordered = sorted(
        matched,
        key=lambda index: (
            _PROBE_ORDER[rows[index].decision.scope],
            0 if rows[index].decision.harness == harness else 1,
            index,
        ),
    )
    winner: int | None = None
    for index in ordered:
        if winner is None:
            winner = index
            continue
        candidate, current = rows[index].decision, rows[winner].decision
        severity = _SEVERITY.get(candidate.action, 1) - _SEVERITY.get(current.action, 1)
        if severity > 0 or (severity == 0 and _specificity(candidate, harness) > _specificity(current, harness)):
            winner = index
    return winner


def decide_rows(rows: tuple[CompiledPolicyRow, ...], event: PolicyEvent, *, now: str) -> dict[str, object]:
    """Decide ``event`` against compiled rows and return the portal Explain shape."""

    keys = _lookup_keys(event, now)
    states = _classify(rows, keys)
    matched = [index for index, (state, _reason) in enumerate(states) if state == "matched"]
    winner = _pick_winner(rows, matched, keys.harness)
    winning = rows[winner].decision if winner is not None else None
    winning_specificity = _specificity(winning, keys.harness) if winning is not None else None
    tied: set[str] = set()
    candidates: list[dict[str, object]] = []
    for index, row in enumerate(rows):
        state, reason = states[index]
        if state == "matched":
            if index == winner:
                state, reason = "selected", None
            else:
                state, reason = "outranked", "more_specific_rule"
                if winning is not None and winning_specificity is not None:
                    if winning.action != row.decision.action:
                        reason = "block_wins"
                    elif (
                        _specificity(row.decision, keys.harness) == winning_specificity
                        and row.rule_id != rows[cast(int, winner)].rule_id
                    ):
                        reason = "tie"
                        tied.add(row.rule_id)
        candidates.append({"ruleId": row.rule_id, "rowIndex": index, "state": state, "reason": reason})
    lookup = {"artifactId": keys.artifact_id, "familyKey": keys.family_key, "at": keys.at}
    fetched = sum(1 for state, _reason in states if state in ("matched", "not_enforced"))
    if fetched > POLICY_MATCH_LIMIT:
        return {
            "effect": "block",
            "ruleId": None,
            "ambiguous": False,
            "matchLimitExceeded": True,
            "tiedRuleIds": [],
            "candidates": candidates,
            "lookup": lookup,
        }
    return {
        "effect": winning.action if winning is not None else "default",
        "ruleId": rows[winner].rule_id if winner is not None else None,
        "ambiguous": bool(tied),
        "matchLimitExceeded": False,
        "tiedRuleIds": sorted(tied),
        "candidates": candidates,
        "lookup": lookup,
    }


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
    "POLICY_MATCH_LIMIT",
    "POLICY_TOOL_FAMILIES",
    "PolicyEvent",
    "PolicyEventError",
    "compile_local_rows",
    "decide_command",
    "decide_rows",
    "parse_event",
    "timestamp_nanos",
    "tool_family_artifact_id",
    "workspace_policy_key",
]
