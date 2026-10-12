"""Exact, side-effect-free parsing for the supported Unix ``env`` contract."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from ..native_rich_command_model import NativeCommandModelError, request, string_tuple

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


def parse_env_wrapper(
    tokens: Sequence[str],
    *,
    inherited_environment: Mapping[str, str] | None = None,
    cwd: Path | None = None,
) -> EnvWrapperParseResult:
    """Present the native env parser result; never infer an executable locally."""
    try:
        value = request(
            "env",
            {
                "tokens": list(tokens),
                "inherited_environment": dict(inherited_environment) if inherited_environment is not None else None,
                "cwd": str(cwd) if cwd is not None else None,
            },
        )
    except NativeCommandModelError:
        return EnvWrapperParseResult(
            False,
            "native_unavailable",
            tuple(tokens),
            (),
            EnvOptionEffects(False, (), None, None, False, False),
            EnvEnvironmentDelta(False, (), ()),
            None,
            None,
            None,
            (),
            (),
        )
    effects, delta = value["option_effects"], value["environment_delta"]
    effects["unset_names"] = string_tuple(effects["unset_names"])
    delta["unset_names"] = string_tuple(delta["unset_names"])
    delta["assignments"] = tuple(map(tuple, delta["assignments"]))
    value["option_effects"] = EnvOptionEffects(**effects)
    value["environment_delta"] = EnvEnvironmentDelta(**delta)
    for name in ("original_tokens", "expanded_tokens", "executable_argv"):
        value[name] = string_tuple(value[name])
    environment = value["effective_environment"]
    value["effective_environment"] = None if environment is None else tuple(map(tuple, environment))
    cwd_value = value["effective_cwd"]
    value["effective_cwd"] = None if cwd_value is None else Path(cwd_value)
    value["split_expansions"] = tuple(
        EnvSplitExpansion(item["payload"], item["source_index"], string_tuple(item["tokens"]))
        for item in value["split_expansions"]
    )
    return EnvWrapperParseResult(**value)
