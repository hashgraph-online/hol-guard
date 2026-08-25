"""Path-set matcher for one executable with many destructive subcommand paths."""

from __future__ import annotations

from dataclasses import dataclass
from typing import final

from .command_matcher_contracts import MatcherEvidence
from .command_model import CanonicalCommand
from .command_option_parsing import (
    argument_semantics,
    flags_present_in_all_option_parses,
    matches_subcommands_conservatively,
)
from .command_rules import _after_leading_options, _segment_matches_executable, _without_options


@final
@dataclass(frozen=True, slots=True)
class ExecutablePathSetMatcher:
    """Match one executable against a set of subcommand paths without matcher explosion."""

    executables: frozenset[str]
    paths: frozenset[tuple[str, ...]]
    required_flags: frozenset[str] = frozenset()
    forbidden_flags: frozenset[str] = frozenset()
    allow_leading_options: bool = False
    leading_options_with_values: frozenset[str] = frozenset()
    interspersed_options_with_values: frozenset[str] = frozenset()
    interspersed_flags: frozenset[str] = frozenset()
    options_with_values: frozenset[str] = frozenset()
    inverse_flag_pairs: frozenset[tuple[str, str]] = frozenset()
    required_option_values: tuple[tuple[str, frozenset[str]], ...] = ()
    required_flags_in_all_arguments: bool = False
    fail_secure_unknown_options: bool = False

    def __post_init__(self) -> None:
        normalized = frozenset(value.strip().lower() for value in self.executables if value.strip())
        paths = frozenset(tuple(token.strip().lower() for token in path if token.strip()) for path in self.paths)
        if not normalized or not paths or any(not path for path in paths):
            raise ValueError("ExecutablePathSetMatcher requires executables and non-empty paths")
        object.__setattr__(self, "executables", normalized)
        object.__setattr__(self, "paths", paths)

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if not _segment_matches_executable(segment, self.executables):
                continue
            if self._segment_matches(tuple(argument.lower() for argument in segment.arguments)) is None:
                continue
            evidence.append(
                MatcherEvidence(
                    segment_index=index,
                    executable=segment.executable,
                    detail="Matched executable and structured argument constraints.",
                )
            )
        return tuple(evidence)

    def _segment_matches(self, lowered_arguments: tuple[str, ...]) -> tuple[str, ...] | None:
        remaining = _without_options(
            lowered_arguments,
            self.interspersed_options_with_values,
            self.interspersed_flags,
        )
        if self.allow_leading_options:
            remaining = _after_leading_options(
                remaining,
                self.leading_options_with_values,
                self.interspersed_flags,
            )
        matched = self._exact_path(remaining)
        if matched is None and self.fail_secure_unknown_options:
            matched = self._conservative_path(lowered_arguments)
        if matched is None:
            return None
        flag_arguments = lowered_arguments if self.required_flags_in_all_arguments else remaining[len(matched) :]
        options_with_values = (
            self.options_with_values | self.leading_options_with_values | self.interspersed_options_with_values
        )
        semantics = argument_semantics(
            flag_arguments,
            options_with_values=options_with_values,
            inverse_flag_pairs=self.inverse_flag_pairs,
        )
        required_present = self.required_flags <= semantics.present_flags and not any(
            semantics.option_value(option) not in allowed_values
            for option, allowed_values in self.required_option_values
        )
        if self.fail_secure_unknown_options and self.required_flags_in_all_arguments:
            required_present = required_present and self._required_flags_survive_unknown_options(lowered_arguments)
        if not required_present or self.forbidden_flags & semantics.present_flags:
            return None
        return matched

    def _exact_path(self, remaining: tuple[str, ...]) -> tuple[str, ...] | None:
        prefix: list[str] = []
        for token in remaining:
            prefix.append(token)
            candidate = tuple(prefix)
            if candidate in self.paths:
                return candidate
        return None

    def _conservative_path(self, lowered_arguments: tuple[str, ...]) -> tuple[str, ...] | None:
        options_with_values = (
            self.options_with_values | self.leading_options_with_values | self.interspersed_options_with_values
        )
        for path in sorted(self.paths, key=lambda item: (len(item), item)):
            if matches_subcommands_conservatively(
                lowered_arguments,
                path,
                options_with_values=options_with_values,
                known_flags=self.interspersed_flags,
            ):
                return path
        return None

    def _required_flags_survive_unknown_options(self, lowered_arguments: tuple[str, ...]) -> bool:
        conservative_requirements = set(self.required_flags)
        semantics = argument_semantics(
            lowered_arguments,
            options_with_values=(
                self.options_with_values | self.leading_options_with_values | self.interspersed_options_with_values
            ),
            inverse_flag_pairs=self.inverse_flag_pairs,
        )
        for positive, negative in self.inverse_flag_pairs:
            if not conservative_requirements.intersection({positive, negative}):
                continue
            conservative_requirements.difference_update({positive, negative})
            effective_token = semantics.option_token(positive)
            if effective_token is not None:
                conservative_requirements.add(effective_token)
        return flags_present_in_all_option_parses(
            lowered_arguments,
            frozenset(conservative_requirements) | {option for option, _values in self.required_option_values},
            options_with_values=(
                self.options_with_values | self.leading_options_with_values | self.interspersed_options_with_values
            ),
            known_flags=(
                self.interspersed_flags
                | self.required_flags
                | self.forbidden_flags
                | {name for pair in self.inverse_flag_pairs for name in pair}
            ),
        )
