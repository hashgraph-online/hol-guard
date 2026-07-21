"""Exact, side-effect-free parsing for the supported Unix ``env`` contract."""

from __future__ import annotations

import os
import shlex
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

ENV_SPLIT_MAX_BYTES = 8192
ENV_SPLIT_MAX_EXPANSIONS = 4
ENV_TOKEN_MAX_COUNT = 256


@dataclass(frozen=True, slots=True)
class EnvEnvironmentDelta:
    clear: bool
    unset_names: tuple[str, ...]
    assignments: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class EnvOptionEffects:
    ignore_environment: bool
    unset_names: tuple[str, ...]
    chdir: str | None
    search_path: str | None
    verbose: bool
    null_output: bool


@dataclass(frozen=True, slots=True)
class EnvSplitExpansion:
    payload: str
    source_index: int
    tokens: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class EnvWrapperParseResult:
    complete: bool
    error: str | None
    original_tokens: tuple[str, ...]
    expanded_tokens: tuple[str, ...]
    option_effects: EnvOptionEffects
    environment_delta: EnvEnvironmentDelta
    effective_environment: tuple[tuple[str, str], ...] | None
    effective_cwd: Path | None
    command_index: int | None
    executable_argv: tuple[str, ...]
    split_expansions: tuple[EnvSplitExpansion, ...]

    def environment_dict(self) -> dict[str, str] | None:
        if self.effective_environment is None:
            return None
        return dict(self.effective_environment)


@dataclass(frozen=True, slots=True)
class _SourcedToken:
    value: str
    source_index: int


def parse_env_wrapper(
    tokens: Sequence[str],
    *,
    inherited_environment: Mapping[str, str] | None = None,
    cwd: Path | None = None,
) -> EnvWrapperParseResult:
    """Parse argv following ``env`` with exact option-operand consumption.

    Unknown implementation-specific options and malformed operands are returned
    as incomplete so callers cannot silently model a different environment.
    ``command_index`` refers to ``expanded_tokens`` after bounded ``-S``
    expansion.
    """

    original_tokens = tuple(tokens)
    working = [_SourcedToken(value, index) for index, value in enumerate(original_tokens)]
    environment = dict(inherited_environment) if inherited_environment is not None else None
    ignore_environment = False
    unset_names: list[str] = []
    assignments: list[tuple[str, str]] = []
    chdir_operand: str | None = None
    search_path: str | None = None
    verbose = False
    null_output = False
    split_expansions: list[EnvSplitExpansion] = []
    options = True
    index = 0

    def result(*, complete: bool, error: str | None, command_index: int | None) -> EnvWrapperParseResult:
        effective_cwd = _effective_cwd(cwd, chdir_operand)
        executable_argv = tuple(token.value for token in working[command_index:]) if command_index is not None else ()
        effects = EnvOptionEffects(
            ignore_environment=ignore_environment,
            unset_names=tuple(unset_names),
            chdir=chdir_operand,
            search_path=search_path,
            verbose=verbose,
            null_output=null_output,
        )
        delta = EnvEnvironmentDelta(
            clear=ignore_environment,
            unset_names=tuple(unset_names),
            assignments=tuple(assignments),
        )
        return EnvWrapperParseResult(
            complete=complete,
            error=error,
            original_tokens=original_tokens,
            expanded_tokens=tuple(token.value for token in working),
            option_effects=effects,
            environment_delta=delta,
            effective_environment=(tuple(sorted(environment.items())) if environment is not None else None),
            effective_cwd=effective_cwd,
            command_index=command_index,
            executable_argv=executable_argv,
            split_expansions=tuple(split_expansions),
        )

    def fail(error: str) -> EnvWrapperParseResult:
        return result(complete=False, error=error, command_index=None)

    def apply_unset(name: str) -> EnvWrapperParseResult | None:
        if not name or "=" in name or "\x00" in name:
            return fail("invalid_unset_operand")
        unset_names.append(name)
        if environment is not None:
            _ = environment.pop(name, None)
        return None

    def apply_clear() -> None:
        nonlocal ignore_environment
        ignore_environment = True
        if environment is not None:
            environment.clear()

    while index < len(working):
        if len(working) > ENV_TOKEN_MAX_COUNT:
            return fail("token_limit_exceeded")
        sourced = working[index]
        token = sourced.value
        if "\x00" in token:
            return fail("nul_token")
        assignment = _env_assignment(token)
        if not options:
            if token == "--":
                index += 1
                return result(
                    complete=True,
                    error=None,
                    command_index=index if index < len(working) else None,
                )
            if assignment is not None:
                assignments.append(assignment)
                if environment is not None:
                    environment[assignment[0]] = assignment[1]
                index += 1
                continue
            return result(complete=True, error=None, command_index=index)
        if token == "--":
            options = False
            index += 1
            continue
        if token == "-":
            apply_clear()
            index += 1
            continue
        if not token.startswith("-"):
            if assignment is not None:
                options = False
                assignments.append(assignment)
                if environment is not None:
                    environment[assignment[0]] = assignment[1]
                index += 1
                continue
            return result(complete=True, error=None, command_index=index)

        if token.startswith("--"):
            option_name, separator, attached = token.partition("=")
            if option_name == "--ignore-environment" and not separator:
                apply_clear()
                index += 1
                continue
            if option_name == "--debug" and not separator:
                verbose = True
                index += 1
                continue
            if option_name == "--null" and not separator:
                null_output = True
                index += 1
                continue
            if option_name not in {"--unset", "--chdir", "--split-string"}:
                return fail("unsupported_option")
            if separator:
                operand = attached
                consumed = 1
                operand_source = sourced.source_index
            else:
                if index + 1 >= len(working):
                    return fail(_missing_operand_error(option_name))
                operand = working[index + 1].value
                consumed = 2
                operand_source = working[index + 1].source_index
            if option_name == "--unset":
                invalid = apply_unset(operand)
                if invalid is not None:
                    return invalid
                index += consumed
                continue
            if option_name == "--chdir":
                if not operand or "\x00" in operand:
                    return fail("invalid_chdir_operand")
                chdir_operand = operand
                index += consumed
                continue
            expansion = _split_expansion(operand, operand_source)
            if isinstance(expansion, str):
                return fail(expansion)
            if len(split_expansions) >= ENV_SPLIT_MAX_EXPANSIONS:
                return fail("split_string_limit_exceeded")
            split_expansions.append(expansion)
            working[index : index + consumed] = [_SourcedToken(value, operand_source) for value in expansion.tokens]
            continue

        short_index = 1
        tokens_consumed = 1
        replace_with_split: tuple[int, EnvSplitExpansion] | None = None
        while short_index < len(token):
            flag = token[short_index]
            if flag == "0":
                null_output = True
                short_index += 1
                continue
            if flag == "i":
                apply_clear()
                short_index += 1
                continue
            if flag == "v":
                verbose = True
                short_index += 1
                continue
            if flag not in {"u", "C", "S", "P"}:
                return fail("unsupported_option")
            attached_operand = token[short_index + 1 :]
            if attached_operand:
                operand = attached_operand
                tokens_consumed = 1
                operand_source = sourced.source_index
            else:
                if index + 1 >= len(working):
                    return fail(_missing_operand_error(f"-{flag}"))
                operand = working[index + 1].value
                tokens_consumed = 2
                operand_source = working[index + 1].source_index
            if flag == "u":
                invalid = apply_unset(operand)
                if invalid is not None:
                    return invalid
            elif flag == "C":
                if not operand or "\x00" in operand:
                    return fail("invalid_chdir_operand")
                chdir_operand = operand
            elif flag == "P":
                if "\x00" in operand:
                    return fail("invalid_search_path_operand")
                search_path = operand
            else:
                expansion = _split_expansion(operand, operand_source)
                if isinstance(expansion, str):
                    return fail(expansion)
                if len(split_expansions) >= ENV_SPLIT_MAX_EXPANSIONS:
                    return fail("split_string_limit_exceeded")
                split_expansions.append(expansion)
                replace_with_split = (tokens_consumed, expansion)
            short_index = len(token)
        if replace_with_split is not None:
            consumed, expansion = replace_with_split
            working[index : index + consumed] = [
                _SourcedToken(value, expansion.source_index) for value in expansion.tokens
            ]
            continue
        index += tokens_consumed

    return result(complete=True, error=None, command_index=None)


def _env_assignment(token: str) -> tuple[str, str] | None:
    name, separator, value = token.partition("=")
    if separator != "=" or not name or "\x00" in name:
        return None
    return name, value


def _missing_operand_error(option: str) -> str:
    if option in {"-u", "--unset"}:
        return "missing_unset_operand"
    if option in {"-C", "--chdir"}:
        return "missing_chdir_operand"
    if option == "-P":
        return "missing_search_path_operand"
    return "missing_split_string_operand"


def _split_expansion(payload: str, source_index: int) -> EnvSplitExpansion | str:
    if len(payload.encode("utf-8")) > ENV_SPLIT_MAX_BYTES:
        return "split_string_byte_limit_exceeded"
    if "\x00" in payload:
        return "split_string_nul"
    try:
        tokens = tuple(shlex.split(payload, posix=True, comments=False))
    except ValueError:
        return "split_string_syntax_error"
    if len(tokens) > ENV_TOKEN_MAX_COUNT:
        return "token_limit_exceeded"
    return EnvSplitExpansion(payload=payload, source_index=source_index, tokens=tokens)


def _effective_cwd(cwd: Path | None, operand: str | None) -> Path | None:
    if operand is None:
        return cwd
    candidate = Path(operand)
    if candidate.is_absolute() or cwd is None:
        return Path(os.path.normpath(str(candidate)))
    return Path(os.path.normpath(str(cwd / candidate)))


__all__ = [
    "ENV_SPLIT_MAX_BYTES",
    "ENV_SPLIT_MAX_EXPANSIONS",
    "ENV_TOKEN_MAX_COUNT",
    "EnvEnvironmentDelta",
    "EnvOptionEffects",
    "EnvSplitExpansion",
    "EnvWrapperParseResult",
    "parse_env_wrapper",
]
