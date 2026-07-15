"""Reusable command rule and matcher contracts for Guard extensions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol, final

from .command_model import CanonicalCommand, CommandSegment

CommandRuleSeverity = Literal["critical", "high", "medium", "low"]
CommandRuleMode = Literal["required", "enforce", "review", "monitor", "disabled"]

_VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low"})
_VALID_MODES = frozenset({"required", "enforce", "review", "monitor", "disabled"})


@dataclass(frozen=True, slots=True)
class MatcherEvidence:
    """Redaction-safe location emitted by one structured matcher."""

    segment_index: int
    executable: str | None
    detail: str

    def to_dict(self) -> dict[str, object]:
        return {
            "segment_index": self.segment_index,
            "executable": self.executable,
            "detail": self.detail,
        }


class CommandMatcher(Protocol):
    """Side-effect-free structured command matcher."""

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]: ...


@final
@dataclass(frozen=True, slots=True)
class ExecutableMatcher:
    """Match executable names with optional subcommand and flag constraints."""

    executables: frozenset[str]
    subcommands: tuple[str, ...] = ()
    required_flags: frozenset[str] = frozenset()
    forbidden_flags: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        normalized = frozenset(value.strip().lower() for value in self.executables if value.strip())
        if not normalized:
            raise ValueError("ExecutableMatcher requires at least one executable")
        object.__setattr__(self, "executables", normalized)
        normalized_subcommands = tuple(value.strip().lower() for value in self.subcommands if value.strip())
        normalized_required_flags = frozenset(value.strip().lower() for value in self.required_flags if value.strip())
        normalized_forbidden_flags = frozenset(value.strip().lower() for value in self.forbidden_flags if value.strip())
        object.__setattr__(self, "subcommands", normalized_subcommands)
        object.__setattr__(self, "required_flags", normalized_required_flags)
        object.__setattr__(self, "forbidden_flags", normalized_forbidden_flags)
        if normalized_required_flags & normalized_forbidden_flags:
            raise ValueError("A matcher flag cannot be both required and forbidden")

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if not _segment_matches_executable(segment, self.executables):
                continue
            lowered_arguments = tuple(argument.lower() for argument in segment.arguments)
            if self.subcommands and lowered_arguments[: len(self.subcommands)] != self.subcommands:
                continue
            argument_set = frozenset(lowered_arguments)
            if not self.required_flags <= argument_set or self.forbidden_flags & argument_set:
                continue
            evidence.append(
                MatcherEvidence(
                    segment_index=index,
                    executable=segment.executable,
                    detail="Matched executable and structured argument constraints.",
                )
            )
        return tuple(evidence)


@final
@dataclass(frozen=True, slots=True)
class AnyMatcher:
    """Match when any child matcher emits evidence."""

    matchers: tuple[CommandMatcher, ...]

    def __post_init__(self) -> None:
        if not self.matchers:
            raise ValueError("AnyMatcher requires at least one child matcher")

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for matcher in self.matchers:
            evidence.extend(matcher.match(command))
        return tuple(evidence)


@final
@dataclass(frozen=True, slots=True)
class AllMatcher:
    """Match only when every child matcher emits evidence."""

    matchers: tuple[CommandMatcher, ...]

    def __post_init__(self) -> None:
        if not self.matchers:
            raise ValueError("AllMatcher requires at least one child matcher")

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for matcher in self.matchers:
            child_evidence = matcher.match(command)
            if not child_evidence:
                return ()
            evidence.extend(child_evidence)
        return tuple(evidence)


@dataclass(frozen=True, slots=True)
class CommandSafetyRule:
    """Stable rule metadata owned by one command safety extension."""

    rule_id: str
    title: str
    description: str
    severity: CommandRuleSeverity
    risk_classes: tuple[str, ...]
    action_classes: tuple[str, ...]
    safer_alternatives: tuple[str, ...]
    default_mode: CommandRuleMode = "review"
    matcher: CommandMatcher | None = None

    def __post_init__(self) -> None:
        if not self.rule_id.startswith("command.") or self.rule_id != self.rule_id.lower():
            raise ValueError("Command safety rule IDs must be lowercase and start with 'command.'")
        if not self.title.strip() or not self.description.strip():
            raise ValueError(f"Command safety rule {self.rule_id} requires a title and description")
        if self.severity not in _VALID_SEVERITIES:
            raise ValueError(f"Command safety rule {self.rule_id} has invalid severity")
        if self.default_mode not in _VALID_MODES:
            raise ValueError(f"Command safety rule {self.rule_id} has invalid default mode")
        for field_name, values in (
            ("risk classes", self.risk_classes),
            ("action classes", self.action_classes),
            ("safer alternatives", self.safer_alternatives),
        ):
            if not values or len(set(values)) != len(values):
                raise ValueError(f"Command safety rule {self.rule_id} requires unique {field_name}")

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "risk_classes": list(self.risk_classes),
            "action_classes": list(self.action_classes),
            "safer_alternatives": list(self.safer_alternatives),
            "default_mode": self.default_mode,
            "matcher_kind": type(self.matcher).__name__ if self.matcher is not None else "compatibility",
        }


@dataclass(frozen=True, slots=True)
class CommandRuleMatch:
    """Rule-level evidence emitted without making a policy decision."""

    rule: CommandSafetyRule
    action_class: str
    reason: str
    command: CanonicalCommand
    matcher_evidence: tuple[MatcherEvidence, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule.rule_id,
            "severity": self.rule.severity,
            "risk_classes": list(self.rule.risk_classes),
            "action_class": self.action_class,
            "reason": self.reason,
            "safer_alternatives": list(self.rule.safer_alternatives),
            "matcher_evidence": [item.to_dict() for item in self.matcher_evidence],
            "parse_confidence": self.command.confidence,
        }


def _segment_matches_executable(segment: CommandSegment, executables: frozenset[str]) -> bool:
    if segment.executable is None:
        return False
    executable = segment.executable.rsplit("/", 1)[-1].lower()
    return executable in executables
