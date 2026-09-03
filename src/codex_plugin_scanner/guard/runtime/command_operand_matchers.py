"""Operand-direction matchers for copy-style command-line tools."""

from __future__ import annotations

from dataclasses import dataclass
from typing import final

from .command_matcher_contracts import CommandMatcher, MatcherEvidence
from .command_model import CanonicalCommand
from .command_structured_matchers import (
    _normalize_option_token,
    _operands_without_options,
    _segment_matches_executable,
    present_flags,
)


@final
@dataclass(frozen=True, slots=True)
class TrailingOperandPrefixMatcher:
    """Match commands whose final operand carries one of the given prefixes.

    Direction is part of the grammar for copy-style tools: the last operand is
    the destination, so a prefixed *final* operand means data leaving the host,
    while the same prefix in an earlier position is a read. Matching any operand
    would treat a restore exactly like an upload.
    """

    executables: frozenset[str]
    operand_prefixes: frozenset[str]
    options_with_values: frozenset[str] = frozenset()
    required_flags: frozenset[str] = frozenset()
    forbidden_flags: frozenset[str] = frozenset()
    minimum_operands: int = 2
    excluded_first_arguments: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        normalized_executables = frozenset(value.strip().lower() for value in self.executables if value.strip())
        normalized_prefixes = frozenset(value for value in self.operand_prefixes if value)
        normalized_options = frozenset(
            _normalize_option_token(value) for value in self.options_with_values if value.strip()
        )
        normalized_required = frozenset(
            _normalize_option_token(value) for value in self.required_flags if value.strip()
        )
        normalized_forbidden = frozenset(
            _normalize_option_token(value) for value in self.forbidden_flags if value.strip()
        )
        if not normalized_executables or not normalized_prefixes:
            raise ValueError("TrailingOperandPrefixMatcher requires executables and operand prefixes")
        if self.minimum_operands < 1:
            raise ValueError("TrailingOperandPrefixMatcher requires at least one operand")
        object.__setattr__(self, "executables", normalized_executables)
        object.__setattr__(self, "operand_prefixes", normalized_prefixes)
        object.__setattr__(self, "options_with_values", normalized_options)
        object.__setattr__(self, "required_flags", normalized_required)
        object.__setattr__(self, "forbidden_flags", normalized_forbidden)

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if not _segment_matches_executable(segment, self.executables):
                continue
            if _first_argument_is_excluded(segment.arguments, self.excluded_first_arguments):
                continue
            flags = present_flags(
                segment.arguments,
                options_with_values=self.options_with_values,
            )
            if self.required_flags - flags:
                continue
            if self.forbidden_flags & flags:
                continue
            operands = _operands_without_options(
                segment.arguments,
                options_with_values=self.options_with_values,
            )
            if len(operands) < self.minimum_operands:
                continue
            destination = operands[-1]
            if not any(
                len(destination) > len(prefix) and destination.startswith(prefix) for prefix in self.operand_prefixes
            ):
                continue
            evidence.append(
                MatcherEvidence(
                    segment_index=index,
                    executable=segment.executable,
                    detail="Matched a prefixed final operand.",
                )
            )
        return tuple(evidence)


def _is_remote_host_target(operand: str) -> bool:
    """Report whether an operand uses scp-style ``[user@]host:path`` syntax.

    Parsed by hand rather than by regular expression: the grammar is small, and
    a matcher on the review path should not carry backtracking behaviour that
    depends on attacker-influenced operand length.
    """
    if "://" in operand:
        return False  # a scheme, which the prefix matcher already owns
    rest = operand.split("@", 1)[1] if "@" in operand else operand
    if rest.startswith("["):  # bracketed IPv6 literal, e.g. [::1]:/srv
        closing = rest.find("]:")
        return closing > 1 and len(rest) > closing + 2
    separator = rest.find(":")
    if separator <= 0 or separator == len(rest) - 1:
        return False
    host = rest[:separator]
    if any(character.isspace() for character in host):
        return False
    # A single-letter host is a Windows drive (``C:\\backup``), not a remote.
    return not (len(host) == 1 and host.isalpha())


@final
@dataclass(frozen=True, slots=True)
class TrailingOperandHostTargetMatcher:
    """Match commands whose final operand is an scp-style remote host target.

    The companion to :class:`TrailingOperandPrefixMatcher` for tools that accept
    both ``scheme://`` endpoints and ``[user@]host:path``. Direction is read the
    same way: only the last operand is a destination, so an upload matches while
    a download from the same host does not.
    """

    executables: frozenset[str]
    options_with_values: frozenset[str] = frozenset()
    required_flags: frozenset[str] = frozenset()
    forbidden_flags: frozenset[str] = frozenset()
    minimum_operands: int = 2
    excluded_first_arguments: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        normalized_executables = frozenset(value.strip().lower() for value in self.executables if value.strip())
        normalized_options = frozenset(
            _normalize_option_token(value) for value in self.options_with_values if value.strip()
        )
        normalized_required = frozenset(
            _normalize_option_token(value) for value in self.required_flags if value.strip()
        )
        normalized_forbidden = frozenset(
            _normalize_option_token(value) for value in self.forbidden_flags if value.strip()
        )
        if not normalized_executables:
            raise ValueError("TrailingOperandHostTargetMatcher requires executables")
        if self.minimum_operands < 1:
            raise ValueError("TrailingOperandHostTargetMatcher requires at least one operand")
        object.__setattr__(self, "executables", normalized_executables)
        object.__setattr__(self, "options_with_values", normalized_options)
        object.__setattr__(self, "required_flags", normalized_required)
        object.__setattr__(self, "forbidden_flags", normalized_forbidden)

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if not _segment_matches_executable(segment, self.executables):
                continue
            if _first_argument_is_excluded(segment.arguments, self.excluded_first_arguments):
                continue
            flags = present_flags(segment.arguments, options_with_values=self.options_with_values)
            if self.required_flags - flags:
                continue
            if self.forbidden_flags & flags:
                continue
            operands = _operands_without_options(
                segment.arguments,
                options_with_values=self.options_with_values,
            )
            if len(operands) < self.minimum_operands:
                continue
            if not _is_remote_host_target(operands[-1]):
                continue
            evidence.append(
                MatcherEvidence(
                    segment_index=index,
                    executable=segment.executable,
                    detail="Matched a remote host target as the final operand.",
                )
            )
        return tuple(evidence)


def _first_argument_is_excluded(arguments: tuple[str, ...], excluded: frozenset[str]) -> bool:
    """Report whether the raw first argument names an excluded subcommand.

    Deliberately the *raw* first argument and deliberately case-sensitive: tools
    that dispatch on ``argv[1]`` (blitcp checks ``sys.argv[1] == "creds"``) only
    enter the subcommand when it is literally the first argument with that exact
    spelling. ``tool --flag creds ...`` and ``tool Creds ...`` both fall through
    to the tool's ordinary copy grammar, so the matcher must keep looking at
    them.
    """
    return bool(excluded) and bool(arguments) and arguments[0] in excluded


def _is_remote_alias_target(operand: str, *, allow_bare_names: bool, bare_names_only: bool = False) -> bool:
    """Report whether an operand can name a saved connection (``NAME[:subpath]``).

    Mirrors the acceptor in blitcp's ``resolve_named_endpoint`` exclusion by
    exclusion, so the matcher and the tool read the same operand the same way:

    - an operand with ``://`` is a scheme endpoint, owned by the prefix matcher;
    - a head containing ``@`` is an scp-style target, owned by the host matcher;
    - a single-character head is a Windows drive (``C:\backup``);
    - a head containing a path separator is a local path with a colon in it.

    A bare name (no colon) is only accepted when ``allow_bare_names`` is set:
    without the colon nothing distinguishes a connection name from an ordinary
    relative destination, so callers gate that form on stronger evidence. With
    ``bare_names_only`` the colon form is left to a sibling matcher, so the two
    never both fire on one operand.
    """
    if "://" in operand:
        return False
    head, separator, _tail = operand.partition(":")
    if separator and bare_names_only:
        return False
    if separator:
        if "@" in head or len(head) <= 1:
            return False
        if "/" in head or "\\" in head:
            return False
        return not any(character.isspace() for character in head)
    if not allow_bare_names:
        return False
    name = operand.rstrip("/").rstrip("\\")
    if len(name) <= 1 or name.startswith("-") or name in {".", ".."}:
        return False
    if "@" in name or "/" in name or "\\" in name:
        return False
    return not any(character.isspace() for character in name)


@final
@dataclass(frozen=True, slots=True)
class TrailingOperandRemoteAliasMatcher:
    """Match commands whose final operand names a saved remote connection.

    The third destination syntax for copy-style tools, next to
    :class:`TrailingOperandPrefixMatcher` (``scheme://``) and
    :class:`TrailingOperandHostTargetMatcher` (``[user@]host:path``): a saved
    connection referenced as ``NAME:subpath`` or, with ``allow_bare_names``, as
    a bare ``NAME``. Direction is read the same way — only the final operand is
    a destination, so a restore from the same alias does not match.
    """

    executables: frozenset[str]
    options_with_values: frozenset[str] = frozenset()
    required_flags: frozenset[str] = frozenset()
    forbidden_flags: frozenset[str] = frozenset()
    minimum_operands: int = 2
    allow_bare_names: bool = False
    bare_names_only: bool = False
    excluded_first_arguments: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        normalized_executables = frozenset(value.strip().lower() for value in self.executables if value.strip())
        normalized_options = frozenset(
            _normalize_option_token(value) for value in self.options_with_values if value.strip()
        )
        normalized_required = frozenset(
            _normalize_option_token(value) for value in self.required_flags if value.strip()
        )
        normalized_forbidden = frozenset(
            _normalize_option_token(value) for value in self.forbidden_flags if value.strip()
        )
        if not normalized_executables:
            raise ValueError("TrailingOperandRemoteAliasMatcher requires executables")
        if self.minimum_operands < 1:
            raise ValueError("TrailingOperandRemoteAliasMatcher requires at least one operand")
        object.__setattr__(self, "executables", normalized_executables)
        object.__setattr__(self, "options_with_values", normalized_options)
        object.__setattr__(self, "required_flags", normalized_required)
        object.__setattr__(self, "forbidden_flags", normalized_forbidden)

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if not _segment_matches_executable(segment, self.executables):
                continue
            if _first_argument_is_excluded(segment.arguments, self.excluded_first_arguments):
                continue
            flags = present_flags(segment.arguments, options_with_values=self.options_with_values)
            if self.required_flags - flags:
                continue
            if self.forbidden_flags & flags:
                continue
            operands = _operands_without_options(
                segment.arguments,
                options_with_values=self.options_with_values,
            )
            if len(operands) < self.minimum_operands:
                continue
            if not _is_remote_alias_target(
                operands[-1],
                allow_bare_names=self.allow_bare_names,
                bare_names_only=self.bare_names_only,
            ):
                continue
            evidence.append(
                MatcherEvidence(
                    segment_index=index,
                    executable=segment.executable,
                    detail="Matched a saved-connection alias as the final operand.",
                )
            )
        return tuple(evidence)


@final
@dataclass(frozen=True, slots=True)
class OperandGatedFlagMatcher:
    """Match required flags only on commands with enough operands to act.

    A flag like ``--no-verify`` or ``--use-sudo`` describes how a copy runs, so
    on an invocation that copies nothing — ``tool --use-sudo``, a bare help run
    — it describes no risk. Gating the flag on the operand count keeps those
    from prompting, which is what preserves the prompt's signal for the copy
    that matters.
    """

    executables: frozenset[str]
    required_flags: frozenset[str]
    options_with_values: frozenset[str] = frozenset()
    forbidden_flags: frozenset[str] = frozenset()
    minimum_operands: int = 2
    excluded_first_arguments: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        normalized_executables = frozenset(value.strip().lower() for value in self.executables if value.strip())
        normalized_required = frozenset(
            _normalize_option_token(value) for value in self.required_flags if value.strip()
        )
        normalized_options = frozenset(
            _normalize_option_token(value) for value in self.options_with_values if value.strip()
        )
        normalized_forbidden = frozenset(
            _normalize_option_token(value) for value in self.forbidden_flags if value.strip()
        )
        if not normalized_executables or not normalized_required:
            raise ValueError("OperandGatedFlagMatcher requires executables and required flags")
        if self.minimum_operands < 1:
            raise ValueError("OperandGatedFlagMatcher requires at least one operand")
        object.__setattr__(self, "executables", normalized_executables)
        object.__setattr__(self, "required_flags", normalized_required)
        object.__setattr__(self, "options_with_values", normalized_options)
        object.__setattr__(self, "forbidden_flags", normalized_forbidden)

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if not _segment_matches_executable(segment, self.executables):
                continue
            if _first_argument_is_excluded(segment.arguments, self.excluded_first_arguments):
                continue
            flags = present_flags(segment.arguments, options_with_values=self.options_with_values)
            if self.required_flags - flags:
                continue
            if self.forbidden_flags & flags:
                continue
            operands = _operands_without_options(
                segment.arguments,
                options_with_values=self.options_with_values,
            )
            if len(operands) < self.minimum_operands:
                continue
            evidence.append(
                MatcherEvidence(
                    segment_index=index,
                    executable=segment.executable,
                    detail=f"Matched required flags on a command with at least {self.minimum_operands} operands.",
                )
            )
        return tuple(evidence)


def operand_matcher_index_hints(matcher: CommandMatcher) -> tuple[frozenset[str], frozenset[str]] | None:
    """Return conservative registry hints for matchers in this module."""

    if isinstance(matcher, (TrailingOperandPrefixMatcher, TrailingOperandHostTargetMatcher)):
        return matcher.executables, frozenset()
    if isinstance(matcher, TrailingOperandRemoteAliasMatcher):
        return matcher.executables, frozenset()
    if isinstance(matcher, OperandGatedFlagMatcher):
        return matcher.executables, frozenset()
    return None
