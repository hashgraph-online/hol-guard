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

RequiredOptionValues = tuple[tuple[str, frozenset[str]], ...]


def _normalized_strings(values: frozenset[str]) -> frozenset[str]:
    return frozenset(value.strip().lower() for value in values if value.strip())


def _normalized_paths(paths: frozenset[tuple[str, ...]]) -> frozenset[tuple[str, ...]]:
    if not paths:
        raise ValueError("ExecutablePathSetMatcher requires at least one path")
    normalized: set[tuple[str, ...]] = set()
    for path in paths:
        if not path:
            raise ValueError("ExecutablePathSetMatcher paths require non-empty path tokens")
        normalized_path = tuple(token.strip().lower() for token in path)
        if any(not token for token in normalized_path):
            raise ValueError("ExecutablePathSetMatcher paths require non-empty path tokens")
        normalized.add(normalized_path)
    return frozenset(normalized)


def _normalized_inverse_pairs(
    pairs: frozenset[tuple[str, str]],
) -> frozenset[tuple[str, str]]:
    return frozenset(
        (positive.strip().lower(), negative.strip().lower())
        for positive, negative in pairs
        if positive.strip() and negative.strip()
    )


def _normalized_required_option_values(values: RequiredOptionValues) -> RequiredOptionValues:
    normalized: list[tuple[str, frozenset[str]]] = []
    for option, allowed in values:
        normalized_option = option.strip().lower()
        if not normalized_option:
            raise ValueError("Required option names cannot be empty")
        normalized.append(
            (
                normalized_option,
                frozenset(value.strip().lower() for value in allowed if value.strip()),
            )
        )
    return tuple(sorted(normalized, key=lambda item: item[0]))


def _validate_flag_constraints(
    required_flags: frozenset[str],
    forbidden_flags: frozenset[str],
    inverse_flag_pairs: frozenset[tuple[str, str]],
) -> None:
    if required_flags & forbidden_flags:
        raise ValueError("A matcher flag cannot be both required and forbidden")
    inverse_names = [name for pair in inverse_flag_pairs for name in pair]
    if len(inverse_names) != len(set(inverse_names)):
        raise ValueError("Inverse flag pairs cannot reuse an option name")


def _validate_required_option_values(values: RequiredOptionValues) -> None:
    option_names = [option for option, _allowed in values]
    if len(option_names) != len(set(option_names)):
        raise ValueError("Required option values cannot declare an option more than once")
    if any(not allowed for _option, allowed in values):
        raise ValueError("Required option values cannot be empty")


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
    required_option_values: RequiredOptionValues = ()
    required_flags_in_all_arguments: bool = False
    fail_secure_unknown_options: bool = False
    _path_lengths_desc: tuple[int, ...] = field(init=False, repr=False, compare=False)
    _paths_desc: tuple[tuple[str, ...], ...] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        executables = _normalized_strings(self.executables)
        if not executables:
            raise ValueError("ExecutablePathSetMatcher requires at least one executable")
        paths = _normalized_paths(self.paths)
        required_flags = _normalized_strings(self.required_flags)
        forbidden_flags = _normalized_strings(self.forbidden_flags)
        inverse_flag_pairs = _normalized_inverse_pairs(self.inverse_flag_pairs)
        required_option_values = _normalized_required_option_values(self.required_option_values)
        _validate_flag_constraints(required_flags, forbidden_flags, inverse_flag_pairs)
        _validate_required_option_values(required_option_values)

        object.__setattr__(self, "executables", executables)
        object.__setattr__(self, "paths", paths)
        object.__setattr__(self, "required_flags", required_flags)
        object.__setattr__(self, "forbidden_flags", forbidden_flags)
        object.__setattr__(
            self,
            "leading_options_with_values",
            _normalized_strings(self.leading_options_with_values),
        )
        object.__setattr__(
            self,
            "interspersed_options_with_values",
            _normalized_strings(self.interspersed_options_with_values),
        )
        object.__setattr__(self, "interspersed_flags", _normalized_strings(self.interspersed_flags))
        object.__setattr__(self, "options_with_values", _normalized_strings(self.options_with_values))
        object.__setattr__(self, "inverse_flag_pairs", inverse_flag_pairs)
        object.__setattr__(self, "required_option_values", required_option_values)
        object.__setattr__(
            self,
            "_path_lengths_desc",
            tuple(sorted({len(path) for path in paths}, reverse=True)),
        )
        object.__setattr__(
            self,
            "_paths_desc",
            tuple(sorted(paths, key=lambda item: (-len(item), item))),
        )

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
