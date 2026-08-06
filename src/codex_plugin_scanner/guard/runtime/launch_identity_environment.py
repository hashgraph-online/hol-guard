"""Side-effect-free effective environment plans for launch observations."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from .command_model import CommandSegment
from .command_structure import EmbeddedCommand
from .command_tokens import executable_name, leading_environment, shell_tokens

_ENVIRONMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_SCRIPT_SCOPE_WRAPPERS = frozenset({"ash", "bash", "bash.exe", "dash", "fish", "ksh", "sh", "sh.exe", "zsh"})


@dataclass(frozen=True, slots=True)
class WrapperLaunchEnvironment:
    name: str
    environment: dict[str, str]


@dataclass(frozen=True, slots=True)
class LaunchEnvironmentPlan:
    executable_environment: dict[str, str]
    wrapper_environments: tuple[WrapperLaunchEnvironment, ...]
    complete: bool


def inherited_launch_environment(launch_env: Mapping[str, str] | None) -> LaunchEnvironmentPlan:
    environment = os.environ if launch_env is None else launch_env
    raw_environment = cast(Mapping[object, object], environment)
    items = [
        (name, value) for name, value in raw_environment.items() if isinstance(name, str) and isinstance(value, str)
    ]
    return LaunchEnvironmentPlan(dict(items), (), len(items) == len(environment))


def plan_launch_environment(
    tokens: tuple[str, ...],
    inherited: Mapping[str, str],
    *,
    inherited_complete: bool = True,
) -> LaunchEnvironmentPlan:
    """Apply leading assignments and static ``env`` controls in shell order."""

    environment = dict(inherited)
    _names, executable_index, wrappers = leading_environment(tokens)
    wrapper_environments: list[WrapperLaunchEnvironment] = []
    wrapper_index = 0
    env_options = False
    complete = inherited_complete
    index = 0
    while index < executable_index:
        token = tokens[index]
        name, separator, value = token.partition("=")
        if separator and _ENVIRONMENT_NAME.fullmatch(name) is not None:
            environment[name] = value
            index += 1
            continue
        command_name = executable_name(token)
        if wrapper_index < len(wrappers) and command_name == wrappers[wrapper_index]:
            wrapper_environments.append(WrapperLaunchEnvironment(wrappers[wrapper_index], dict(environment)))
            wrapper_index += 1
            env_options = command_name == "env"
            index += 1
            continue
        if not env_options:
            index += 1
            continue
        if token in {"-i", "--ignore-environment"}:
            environment.clear()
            index += 1
            continue
        if token in {"-u", "--unset"}:
            if index + 1 >= executable_index:
                complete = False
                break
            _ = environment.pop(tokens[index + 1], None)
            index += 2
            continue
        if token.startswith("--unset="):
            _ = environment.pop(token.split("=", 1)[1], None)
            index += 1
            continue
        if token in {"-C", "--chdir"}:
            if index + 1 >= executable_index:
                complete = False
                break
            index += 2
            continue
        if token.startswith("--chdir="):
            index += 1
            continue
        if token == "--":
            env_options = False
            index += 1
            continue
        if token.startswith("-"):
            complete = False
        index += 1
    if env_options and executable_index < len(tokens) and tokens[executable_index].startswith("-"):
        complete = False
    if wrapper_index != len(wrappers):
        complete = False
        for wrapper in wrappers[wrapper_index:]:
            wrapper_environments.append(WrapperLaunchEnvironment(wrapper, dict(environment)))
    return LaunchEnvironmentPlan(environment, tuple(wrapper_environments), complete)


def plan_command_segment_environment(
    segment: CommandSegment,
    embedded_commands: tuple[EmbeddedCommand, ...],
    inherited: Mapping[str, str],
) -> LaunchEnvironmentPlan:
    embedded = next(
        (item for item in embedded_commands if segment.execution_context.startswith(f"{item.execution_context}:")),
        None,
    )
    if embedded is None:
        return plan_launch_environment(segment.tokens, inherited)
    embedded_tokens, _exact = shell_tokens(embedded.text)
    outer = plan_launch_environment(embedded_tokens, inherited)
    normalized = plan_launch_environment(segment.tokens, outer.executable_environment)
    return LaunchEnvironmentPlan(
        normalized.executable_environment,
        (*outer.wrapper_environments, *normalized.wrapper_environments),
        outer.complete and normalized.complete,
    )


def launch_search_path(environment: Mapping[str, str]) -> str:
    search_path = environment.get("PATH")
    return search_path if isinstance(search_path, str) else os.defpath


_SHELL_LIST_OPERATORS = frozenset({"&&", "||", ";", "|", "&"})
_SHELL_LIST_OPERATOR_CHARS = frozenset({";", "|", "&"})


def _script_payload_has_list_operators(script: str) -> bool:
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(script):
        character = script[index]
        if quote == "'":
            if character == "'":
                quote = None
            index += 1
            continue
        if escaped:
            escaped = False
            index += 1
            continue
        if character == "\\":
            escaped = True
            index += 1
            continue
        if quote == '"':
            if character == '"':
                quote = None
            elif character == "`" or (character == "$" and index + 1 < len(script) and script[index + 1] == "("):
                return True
            index += 1
            continue
        if character in {"'", '"'}:
            quote = character
        elif (
            character == "`"
            or character in {"\n", "\r"}
            or character in _SHELL_LIST_OPERATOR_CHARS
            or (character == "$" and index + 1 < len(script) and script[index + 1] == "(")
        ):
            return True
        index += 1
    return quote is not None or escaped


def _is_script_command_flag(token: str) -> bool:
    return token.startswith("-") and not token.startswith("--") and "=" not in token and "c" in token[1:]


def _script_command_payloads(tokens: tuple[str, ...]) -> tuple[str, ...]:
    """Extract ``-c`` payloads belonging to script-scope shells in raw tokens.

    Scans the raw command text for ``<script-shell> ... -c <payload>`` shapes
    regardless of how the parser attributed the wrapper, so path spellings
    that drop the shell from the normalized wrapper chain still surface the
    payload. Flag-values and option-terminators are respected well enough
    for wrapper chains (``env``/``command``) that precede the shell.
    """

    payloads: list[str] = []
    for index, token in enumerate(tokens[:-1]):
        if not _is_script_command_flag(token):
            continue
        # Walk backwards to the nearest script-scope shell before this -c,
        # stopping at list operators that would end the wrapper chain.
        for back in range(index - 1, -1, -1):
            candidate = tokens[back]
            if candidate in _SHELL_LIST_OPERATORS:
                break
            name = candidate.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()
            if name in _SCRIPT_SCOPE_WRAPPERS:
                payload = tokens[index + 1]
                if payload:
                    payloads.append(payload)
                break
    return tuple(payloads)


def launch_environment_scope_is_ambiguous(
    wrappers: tuple[str, ...],
    segment_count: int,
    *,
    script_payloads: tuple[str, ...] = (),
) -> bool:
    """Whether wrapper scope defies a reusable launch observation.

    Multi-segment commands behind a script-scope wrapper (sh/bash/dash/...)
    are always ambiguous. A single extracted segment is still ambiguous when
    the wrapper's ``-c`` payload itself contains shell list operators — the
    embedded ``&&``/``;``/``|`` chain executes additional executables whose
    environments the observation cannot bind. The parser may or may not
    split that payload into top-level segments depending on interpreter path
    spellings, so payload inspection must not rely on segment count.
    """

    if segment_count > 1 and any(wrapper in _SCRIPT_SCOPE_WRAPPERS for wrapper in wrappers):
        return True
    # Payload evidence alone is sufficient: a script shell carrying -c with
    # list operators executes extra executables even when the normalized
    # wrapper chain lost the shell (e.g. /usr/bin/sh path spellings).
    return any(_script_payload_has_list_operators(payload) for payload in script_payloads)


def unresolved_launch_observation(segment_index: str) -> dict[str, object]:
    return {
        "segment_index": segment_index,
        "identity_digest": secrets.token_hex(32),
        "reusable_observation": False,
    }


def environment_observation_material(
    plans: tuple[LaunchEnvironmentPlan, ...],
) -> list[dict[str, object]]:
    material: list[dict[str, object]] = []
    for index, plan in enumerate(plans):
        payload = json.dumps(
            sorted(plan.executable_environment.items()),
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        material.append(
            {
                "index": index,
                "complete": plan.complete,
                "entry_count": len(plan.executable_environment),
                "environment_digest": hashlib.sha256(b"hol-guard.launch-environment\x00" + payload).hexdigest(),
                **({"reuse_nonce": secrets.token_hex(16)} if not plan.complete else {}),
            }
        )
    return material


__all__ = [
    "LaunchEnvironmentPlan",
    "WrapperLaunchEnvironment",
    "environment_observation_material",
    "inherited_launch_environment",
    "launch_environment_scope_is_ambiguous",
    "launch_search_path",
    "plan_command_segment_environment",
    "plan_launch_environment",
    "unresolved_launch_observation",
]
