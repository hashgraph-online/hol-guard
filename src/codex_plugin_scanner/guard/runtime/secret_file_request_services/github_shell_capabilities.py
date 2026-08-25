"""GitHub CLI shell capability parsing."""

from __future__ import annotations

import re
from pathlib import Path

from ..env_wrapper import parse_env_wrapper
from ..github_capability_contract import GitHubCommandAssessment, github_assessment
from ..github_command_capabilities import _github_repository_selector_is_safe
from ..github_rest_capabilities import _PR_HEAD_OID_ENDPOINT
from ..github_shell_capabilities import GitHubShellAnalysis
from ..github_shell_capabilities import classify_github_shell_capabilities as _classify_github_shell_capabilities
from ..interpreter_options import shell_interpreter_command_payload as _shell_interpreter_command_payload
from .constants_core import _READ_ONLY_LOOKUP_FILTERS, _SHELL_COMMAND_STRING_INTERPRETERS
from .constants_patterns import _SHELL_ASSIGNMENT_PATTERN, _SHELL_COMMAND_SEPARATORS, _SHELL_COMMAND_WRAPPERS
from .read_only_filters import _github_output_filter_segment_is_safe
from .request_artifacts import _normalized_shell_command_name
from .shell_quote_tokens import (
    ShellTokenWithQuoteContext as _ShellTokenWithQuoteContext,
)
from .shell_quote_tokens import (
    shell_token_segments,
    shell_tokens_preserving_quote_context,
)
from .shell_static_safety import (
    _github_jq_filter_args_are_safe,
    _is_python_interpreter_command,
    _script_interpreter_texts,
    _script_is_read_only_observer,
)
from .shell_tokenization import (
    _iter_shell_command_segments,
    _shell_command_token_without_attached_redirection,
    _shell_segment_primary_command,
    _split_shell_parts,
    _wrapper_option_tokens_consumed,
)

_SHELL_FUNCTION_DEFINITION = re.compile(
    r"(?:\A|[;&\n])\s*(?:function\s+[A-Za-z_][A-Za-z0-9_]*(?:\s*\(\s*\))?"
    r"|[A-Za-z_][A-Za-z0-9_]*\s*\(\s*\))\s*\{"
)
_SHELL_ALIAS_DEFINITION = re.compile(r"(?:\A|[;&\n])\s*alias\s+[A-Za-z_][A-Za-z0-9_]*\s*=")
_DEFERRED_GITHUB_EFFECT = re.compile(
    r"(?:\A|[;{&|\n])\s*gh(?:\s|\Z)|\b(?:GH|GITHUB)_(?:CONFIG_DIR|ENTERPRISE_TOKEN|HOST|REPO|TOKEN)\b"
)


def classify_github_shell_capabilities(
    command_text: str,
    *,
    home_dir: Path | None,
) -> GitHubCommandAssessment | None:
    """Adapt the shared shell parser to focused GitHub capability composition."""

    if (
        _SHELL_FUNCTION_DEFINITION.search(command_text) or _SHELL_ALIAS_DEFINITION.search(command_text)
    ) and _DEFERRED_GITHUB_EFFECT.search(command_text):
        return github_assessment(
            "unknown",
            "github.command.shell-function",
            "Shell functions in a GitHub command compound require explicit review.",
        )
    parts = _split_shell_parts(command_text)
    if _persistent_github_environment_requires_review(parts):
        return github_assessment(
            "unknown",
            "github.command.untrusted-environment",
            "Exported GitHub host or credential configuration requires explicit review.",
        )
    if _github_shell_has_dynamic_arguments(command_text):
        return github_assessment(
            "unknown",
            "github.command.dynamic-argument",
            "Dynamic GitHub arguments require explicit review.",
        )
    for segment in _iter_shell_command_segments(parts):
        if _shell_segment_is_command_builtin_lookup(segment):
            continue
        if segment[:1] == ["env"]:
            parsed_raw_env = parse_env_wrapper(segment[1:])
            if parsed_raw_env.complete:
                raw_assignments = parsed_raw_env.environment_delta.assignments
                executable = parsed_raw_env.executable_argv
                if executable[:1] == ("gh",) and (_github_environment_requires_review(raw_assignments)):
                    return github_assessment(
                        "unknown",
                        "github.command.untrusted-environment",
                        "Expanded GitHub environment or arguments require explicit review.",
                    )
                if executable[:1] in {("bash",), ("sh",), ("zsh",)}:
                    scripts = _shell_command_scripts(list(executable))
                    if scripts and _github_environment_requires_review(raw_assignments):
                        return github_assessment(
                            "unknown",
                            "github.command.untrusted-environment",
                            "Nested GitHub environment configuration requires explicit review.",
                        )
                    if any(_github_script_requires_review(script) for script in scripts):
                        return github_assessment(
                            "unknown",
                            "github.command.dynamic-nested-shell",
                            "Nested dynamic GitHub arguments require explicit review.",
                        )
        command_name, command_index = _shell_segment_primary_command(segment)
        assignments = tuple(
            (token.partition("=")[0], token.partition("=")[2])
            for token in segment[: command_index or 0]
            if "=" in token
        )
        targets_github = command_name == "gh"
        if command_name == "env" and command_index is not None:
            parsed_env = parse_env_wrapper(segment[command_index + 1 :])
            if parsed_env.complete and parsed_env.executable_argv[:1] == ("gh",):
                assignments = (*assignments, *parsed_env.environment_delta.assignments)
                targets_github = True
        if targets_github and _github_environment_requires_review(assignments):
            return github_assessment(
                "unknown",
                "github.command.untrusted-environment",
                "Inline GitHub host or credential configuration requires explicit review.",
            )
    return _classify_github_shell_capabilities(
        command_text,
        analysis=GitHubShellAnalysis(
            command_substitution_payloads=_shell_command_substitution_payloads,
            split_parts=_split_shell_parts,
            nested_commands=lambda parts: (*_env_split_string_payloads(parts), *_shell_command_scripts(parts)),
            pipelines=_iter_shell_pipelines,
            command_builtin_is_lookup=_shell_segment_is_command_builtin_lookup,
            primary_command=_shell_segment_primary_command,
            pipeline_companion_is_read_only=lambda segment: _github_pipeline_companion_is_read_only(
                segment, home_dir=home_dir, command_text=command_text
            ),
        ),
    )


def _github_environment_requires_review(assignments: tuple[tuple[str, str], ...]) -> bool:
    normalized = dict(assignments)
    protected = {
        "GH_CONFIG_DIR",
        "GH_ENTERPRISE_TOKEN",
        "GH_TOKEN",
        "GITHUB_ENTERPRISE_TOKEN",
        "GITHUB_TOKEN",
    }
    if protected.intersection(normalized):
        return True
    github_host = normalized.get("GH_HOST")
    if github_host is not None and github_host.casefold() != "github.com":
        return True
    github_repo = normalized.get("GH_REPO")
    return github_repo is not None and not _github_repository_selector_is_safe(github_repo)


def _persistent_github_environment_requires_review(parts: list[str]) -> bool:
    shell_values: dict[str, str] = {}
    exported: dict[str, str] = {}
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name is None:
            for token in segment:
                name, separator, value = token.partition("=")
                if separator:
                    shell_values[name] = value
                    if name in exported:
                        exported[name] = value
            continue
        args = segment[command_index + 1 :] if command_index is not None else []
        if command_name == "unset":
            for name in args:
                shell_values.pop(name, None)
                exported.pop(name, None)
            continue
        if command_name in {"export", "readonly", "declare", "typeset"}:
            export_enabled = command_name == "export" or "-x" in args
            relevant_assignment = any(
                _github_environment_name(token.partition("=")[0])
                or any(marker in token.partition("=")[0] for marker in ("$", "`"))
                for token in args
                if not token.startswith("-")
            )
            if not relevant_assignment:
                continue
            if not export_enabled:
                if any(
                    _github_environment_name(token.partition("=")[0]) for token in args if not token.startswith("-")
                ):
                    return True
                continue
            for token in args:
                if token.startswith("-"):
                    if token != "-x":
                        return True
                    continue
                name, separator, value = token.partition("=")
                if any(marker in name for marker in ("$", "`")):
                    return True
                if separator:
                    shell_values[name] = value
                if name in shell_values:
                    exported[name] = shell_values[name]
                elif _github_environment_name(name):
                    return True
            continue
        if command_name in {"bash", "sh", "zsh"} and command_index is not None:
            inherited = {
                **exported,
                **{
                    token.partition("=")[0]: token.partition("=")[2]
                    for token in segment[:command_index]
                    if "=" in token
                },
            }
            scripts = _shell_command_scripts(segment)
            if scripts and _github_environment_requires_review(tuple(inherited.items())):
                return True
            if any(_github_script_requires_review(script) for script in scripts):
                return True
        if command_name != "gh" or command_index is None:
            continue
        local_assignments = {
            token.partition("=")[0]: token.partition("=")[2] for token in segment[:command_index] if "=" in token
        }
        effective = {**exported, **local_assignments}
        if _github_environment_requires_review(tuple(effective.items())):
            return True
    return False


def _github_shell_has_dynamic_arguments(command_text: str) -> bool:
    for contextual_segment in shell_token_segments(shell_tokens_preserving_quote_context(command_text)):
        plain_segment = [token.plain for token in contextual_segment]
        if _shell_segment_is_command_builtin_lookup(plain_segment):
            continue
        command_name, command_index = _shell_segment_primary_command(plain_segment)
        if command_name != "gh" or command_index is None:
            continue
        if any(
            github_argument_token_has_untrusted_expansion(token.raw)
            for token in contextual_segment[command_index + 1 :]
        ):
            return True
    return False


def github_argument_token_has_untrusted_expansion(token: str) -> bool:
    unquoted = token[1:-1] if len(token) >= 2 and token[0] == token[-1] and token[0] in {"'", '"'} else token
    if _PR_HEAD_OID_ENDPOINT.fullmatch(unquoted):
        return False
    return _shell_token_has_expansion(token)


def _shell_token_has_expansion(token: str) -> bool:
    single_quoted = False
    double_quoted = False
    escaped = False
    index = 0
    while index < len(token):
        character = token[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if character == "\\" and not single_quoted:
            escaped = True
            index += 1
            continue
        if not single_quoted and not double_quoted and token.startswith("$'", index):
            index += 2
            while index < len(token):
                if token[index] == "\\" and index + 1 < len(token):
                    index += 2
                    continue
                if token[index] == "'":
                    index += 1
                    break
                index += 1
            continue
        if character == "'" and not double_quoted:
            single_quoted = not single_quoted
            index += 1
            continue
        if character == '"' and not single_quoted:
            double_quoted = not double_quoted
            index += 1
            continue
        if not single_quoted and character in {"$", "`"}:
            return True
        index += 1
    return False


def _github_script_requires_review(script: str) -> bool:
    parts = _split_shell_parts(script)
    if _persistent_github_environment_requires_review(parts):
        return True
    return _github_shell_has_dynamic_arguments(script)


def _github_environment_name(name: str) -> bool:
    return name in {
        "GH_CONFIG_DIR",
        "GH_ENTERPRISE_TOKEN",
        "GH_HOST",
        "GH_REPO",
        "GH_TOKEN",
        "GITHUB_ENTERPRISE_TOKEN",
        "GITHUB_TOKEN",
    }


def _shell_segment_is_command_builtin_lookup(segment: list[str]) -> bool:
    contextual_segment = [_ShellTokenWithQuoteContext(raw=token, plain=token) for token in segment]
    for index, token in enumerate(segment):
        command_name = _normalized_shell_command_name(_shell_command_token_without_attached_redirection(token))
        if command_name == "command":
            return _command_builtin_options_are_lookup_only(contextual_segment, index + 1)
    return False


def _github_pipeline_companion_is_read_only(
    segment: list[str],
    *,
    home_dir: Path | None,
    command_text: str,
) -> bool:
    command_name, command_index = _shell_segment_primary_command(segment)
    if command_name is None or command_index is None:
        return False
    if _is_python_interpreter_command(command_name):
        scripts = list(_script_interpreter_texts(segment))
        return bool(scripts) and all(_script_is_read_only_observer(script_text) for script_text in scripts)
    if any(">" in token or "<" in token for token in segment[command_index + 1 :] if token not in {"2>&1", "1>&2"}):
        return False
    args = [token for token in segment[command_index + 1 :] if token not in {"2>&1", "1>&2"}]
    if command_name == "jq":
        return _github_jq_filter_args_are_safe(args)
    if command_name == "sort":
        return all(re.fullmatch(r"-[nru]+", arg) for arg in args)
    if command_name == "uniq":
        return args in ([], ["-c"])
    if command_name in _READ_ONLY_LOOKUP_FILTERS:
        return _github_output_filter_segment_is_safe(command_name, args, home_dir=home_dir, command_text=command_text)
    return False


def _command_builtin_options_are_lookup_only(segment: list[_ShellTokenWithQuoteContext], index: int) -> bool:
    while index < len(segment):
        plain = segment[index].plain
        if plain == "--":
            return False
        if not plain.startswith("-"):
            return False
        if "v" in plain[1:] or "V" in plain[1:]:
            return True
        index += 1
    return False


def _shell_command_substitution_payloads(command_text: str) -> tuple[str, ...]:
    payloads: list[str] = []
    index = 0
    single_quoted = False
    double_quoted = False
    while index < len(command_text):
        if single_quoted:
            if command_text[index] == "'":
                single_quoted = False
            index += 1
            continue
        if double_quoted:
            if command_text[index] == "\\" and index + 1 < len(command_text):
                index += 2
                continue
            if command_text[index] == '"':
                double_quoted = False
                index += 1
                continue
            if command_text[index] == "$" and index + 1 < len(command_text) and command_text[index + 1] == "(":
                payload, next_index = _read_command_substitution(command_text, index + 2)
                if payload.strip():
                    payloads.append(payload)
                index = next_index
                continue
            if command_text[index] == "`":
                payload, next_index = _read_backtick_command_substitution(command_text, index + 1)
                if payload.strip():
                    payloads.append(payload)
                index = next_index
                continue
            index += 1
            continue
        if command_text[index] == "\\" and index + 1 < len(command_text):
            index += 2
            continue
        if command_text[index] == "'":
            single_quoted = True
            index += 1
            continue
        if command_text[index] == '"':
            double_quoted = True
            index += 1
            continue
        if command_text[index] == "$" and index + 1 < len(command_text) and command_text[index + 1] == "(":
            payload, next_index = _read_command_substitution(command_text, index + 2)
            if payload.strip():
                payloads.append(payload)
            index = next_index
            continue
        if command_text[index] in "<>" and index + 1 < len(command_text) and command_text[index + 1] == "(":
            payload, next_index = _read_command_substitution(command_text, index + 2)
            if payload.strip():
                payloads.append(payload)
            index = next_index
            continue
        if command_text[index] == "`":
            payload, next_index = _read_backtick_command_substitution(command_text, index + 1)
            if payload.strip():
                payloads.append(payload)
            index = next_index
            continue
        index += 1
    return tuple(payloads)


def _read_command_substitution(command_text: str, start_index: int) -> tuple[str, int]:
    index = start_index
    depth = 1
    payload_characters: list[str] = []
    single_quoted = False
    double_quoted = False
    while index < len(command_text):
        character = command_text[index]
        if single_quoted:
            payload_characters.append(character)
            if character == "'":
                single_quoted = False
            index += 1
            continue
        if double_quoted:
            payload_characters.append(character)
            if character == "\\" and index + 1 < len(command_text):
                payload_characters.append(command_text[index + 1])
                index += 2
                continue
            if character == '"':
                double_quoted = False
            index += 1
            continue
        if character == "'":
            single_quoted = True
            payload_characters.append(character)
            index += 1
            continue
        if character == '"':
            double_quoted = True
            payload_characters.append(character)
            index += 1
            continue
        if character == "$" and index + 1 < len(command_text) and command_text[index + 1] == "(":
            nested_payload, next_index = _read_command_substitution(command_text, index + 2)
            payload_characters.append(f"$({nested_payload})")
            index = next_index
            continue
        if character == "(":
            depth += 1
            payload_characters.append(character)
            index += 1
            continue
        if character == ")":
            depth -= 1
            if depth == 0:
                return "".join(payload_characters), index + 1
            payload_characters.append(character)
            index += 1
            continue
        payload_characters.append(character)
        index += 1
    return "".join(payload_characters), index


def _read_backtick_command_substitution(command_text: str, start_index: int) -> tuple[str, int]:
    index = start_index
    payload_characters: list[str] = []
    while index < len(command_text):
        character = command_text[index]
        if character == "\\" and index + 1 < len(command_text):
            payload_characters.append(character)
            payload_characters.append(command_text[index + 1])
            index += 2
            continue
        if character == "$" and index + 1 < len(command_text) and command_text[index + 1] == "(":
            nested_payload, next_index = _read_command_substitution(command_text, index + 2)
            payload_characters.append(f"$({nested_payload})")
            index = next_index
            continue
        if character == "`":
            return "".join(payload_characters), index + 1
        payload_characters.append(character)
        index += 1
    return "".join(payload_characters), index


def _iter_shell_pipelines(parts: list[str]) -> list[list[list[str]]]:
    pipelines: list[list[list[str]]] = []
    current_pipeline: list[list[str]] = []
    current_segment: list[str] = []
    for part in parts:
        token = part.strip()
        if not token:
            continue
        if token in {"|", "|&"}:
            if current_segment:
                current_pipeline.append(current_segment)
                current_segment = []
            continue
        if token in _SHELL_COMMAND_SEPARATORS:
            if current_segment:
                current_pipeline.append(current_segment)
                current_segment = []
            if current_pipeline:
                pipelines.append(current_pipeline)
                current_pipeline = []
            continue
        current_segment.append(token)
    if current_segment:
        current_pipeline.append(current_segment)
    if current_pipeline:
        pipelines.append(current_pipeline)
    return pipelines


def _env_split_string_payloads(parts: list[str]) -> tuple[str, ...]:
    payloads: list[str] = []
    for segment in _iter_shell_command_segments(parts):
        env_index = _shell_segment_env_index(segment)
        if env_index is None:
            continue
        parsed = parse_env_wrapper(segment[env_index + 1 :])
        payloads.extend(expansion.payload for expansion in parsed.split_expansions if expansion.payload.strip())
    return tuple(payloads)


def _shell_segment_env_index(segment: list[str]) -> int | None:
    index = 0
    while index < len(segment):
        normalized_token = segment[index].lstrip("(").rstrip(")")
        if _SHELL_ASSIGNMENT_PATTERN.match(normalized_token):
            index += 1
            continue
        command_name = _normalized_shell_command_name(normalized_token)
        if command_name == "env":
            return index
        if command_name in _SHELL_COMMAND_WRAPPERS:
            index += 1
            while index < len(segment):
                token = segment[index]
                if not token.startswith("-"):
                    break
                index += _wrapper_option_tokens_consumed(command_name, token)
            continue
        return None
    return None


def _shell_command_scripts(parts: list[str]) -> tuple[str, ...]:
    scripts: list[str] = []
    for segment in _iter_shell_command_segments(parts):
        command_name, command_index = _shell_segment_primary_command(segment)
        if command_name not in _SHELL_COMMAND_STRING_INTERPRETERS or command_index is None:
            continue
        flag_payload = _shell_interpreter_command_payload(segment, command_index)
        if flag_payload is not None:
            scripts.append(flag_payload.script_text)
    return tuple(scripts)


__all__ = [
    "_ShellTokenWithQuoteContext",
    "_command_builtin_options_are_lookup_only",
    "_env_split_string_payloads",
    "_github_pipeline_companion_is_read_only",
    "_iter_shell_pipelines",
    "_read_backtick_command_substitution",
    "_read_command_substitution",
    "_shell_command_scripts",
    "_shell_command_substitution_payloads",
    "_shell_segment_env_index",
    "_shell_segment_is_command_builtin_lookup",
    "classify_github_shell_capabilities",
]
