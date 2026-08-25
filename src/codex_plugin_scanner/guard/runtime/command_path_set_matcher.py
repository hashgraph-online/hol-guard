"""Path-set matcher for one executable with many destructive subcommand paths."""

from __future__ import annotations

from dataclasses import dataclass, field
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
    _path_lengths_desc: tuple[int, ...] = field(init=False, repr=False, compare=False)
    _paths_desc: tuple[tuple[str, ...], ...] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        normalized_executables = frozenset(
            value.strip().lower() for value in self.executables if value.strip()
        )
        if not normalized_executables:
            raise ValueError("ExecutablePathSetMatcher requires at least one executable")
        if not self.paths:
            raise ValueError("ExecutablePathSetMatcher requires at least one path")
        if any(not path or any(not token.strip() for token in path) for path in self.paths):
            raise ValueError("ExecutablePathSetMatcher paths require non-empty path tokens")

        normalized_paths = frozenset(
            tuple(token.strip().lower() for token in path) for path in self.paths
        )
        normalized_required_flags = frozenset(
            value.strip().lower() for value in self.required_flags if value.strip()
        )
        normalized_forbidden_flags = frozenset(
            value.strip().lower() for value in self.forbidden_flags if value.strip()
        )
        normalized_leading_options = frozenset(
            value.strip().lower() for value in self.leading_options_with_values if value.strip()
        )
        normalized_interspersed_options = frozenset(
            value.strip().lower()
            for value in self.interspersed_options_with_values
            if value.strip()
        )
        normalized_interspersed_flags = frozenset(
            value.strip().lower() for value in self.interspersed_flags if value.strip()
        )
        normalized_options = frozenset(
            value.strip().lower() for value in self.options_with_values if value.strip()
        )
        normalized_inverse_pairs = frozenset(
            (positive.strip().lower(), negative.strip().lower())
            for positive, negative in self.inverse_flag_pairs
            if positive.strip() and negative.strip()
        )
        normalized_required_option_values = tuple(
            sorted(
                (
                    (
                        option.strip().lower(),
                        frozenset(value.strip().lower() for value in values if value.strip()),
                    )
                    for option, values in self.required_option_values
                    if option.strip()
                ),
                key=lambda item: item[0],
            )
        )

        object.__setattr__(self, "executables", normalized_executables)
        object.__setattr__(self, "paths", normalized_paths)
        object.__setattr__(self, "required_flags", normalized_required_flags)
        object.__setattr__(self, "forbidden_flags", normalized_forbidden_flags)
        object.__setattr__(self, "leading_options_with_values", normalized_leading_options)
        object.__setattr__(self, "interspersed_options_with_values", normalized_interspersed_options)
        object.__setattr__(self, "interspersed_flags", normalized_interspersed_flags)
        object.__setattr__(self, "options_with_values", normalized_options)
        object.__setattr__(self, "inverse_flag_pairs", normalized_inverse_pairs)
        object.__setattr__(self, "required_option_values", normalized_required_option_values)
        object.__setattr__(
            self,
            "_path_lengths_desc",
            tuple(sorted({len(path) for path in normalized_paths}, reverse=True)),
        )
        object.__setattr__(
            self,
            "_paths_desc",
            tuple(sorted(normalized_paths, key=lambda item: (-len(item), item))),
        )

        if normalized_required_flags & normalized_forbidden_flags:
            raise ValueError("A matcher flag cannot be both required and forbidden")
        inverse_names = [name for pair in normalized_inverse_pairs for name in pair]
        if len(inverse_names) != len(set(inverse_names)):
            raise ValueError("Inverse flag pairs cannot reuse an option name")
        required_option_names = [option for option, _values in normalized_required_option_values]
        if len(required_option_names) != len(set(required_option_names)):
            raise ValueError("Required option values cannot declare an option more than once")
        if any(not values for _option, values in normalized_required_option_values):
            raise ValueError("Required option values cannot be empty")

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
        for length in self._path_lengths_desc:
            if len(remaining) < length:
                continue
            candidate = remaining[:length]
            if candidate in self.paths:
                return candidate
        return None

    def _conservative_path(self, lowered_arguments: tuple[str, ...]) -> tuple[str, ...] | None:
        options_with_values = (
            self.options_with_values | self.leading_options_with_values | self.interspersed_options_with_values
        )
        for path in self._paths_desc:
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
