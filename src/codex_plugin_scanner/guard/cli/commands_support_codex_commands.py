"""Guard CLI helper definitions."""

# pyright: reportImportCycles=false

# fmt: off
# ruff: noqa: F403, F405

from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

from ..native_codex_tool_output import codex_tool_output_native
from ..runtime.secret_file_requests import (
    COMMAND_CANDIDATE_LIST_KEYS,
    COMMAND_SEQUENCE_KEYS,
    command_list_candidate_texts,
)
from ._commands_shared import *
from .codex_output_safety import output_uses_placeholder_private_key_fixture
from .commands_parser_helpers import *
from .commands_support_native_search import native_post_tool_search_is_read_only

if TYPE_CHECKING:
    from .commands_support_codex_reads import _codex_command_is_read_only_source_inspection
    from .commands_support_runtime_artifacts import _codex_command_references_sensitive_local_source


def _codex_command_reads_environment_pipeline(command_text: str) -> bool:
    answer = codex_tool_output_native("reads_environment_pipeline", command=command_text)
    return answer.error_code is not None or answer.allowed


def _codex_local_secret_source_label(
    matches: list[SecretPathMatch],
    *,
    command_text: str,
) -> str | None:
    families: list[str] = []
    for match in matches:
        if match.family not in families:
            families.append(match.family)
    if families:
        if len(families) == 1:
            return families[0]
        return f"{families[0]} and other local secret files"
    if _codex_command_reads_environment_pipeline(command_text):
        return "environment variables"
    return None


def _codex_post_tool_command_is_read_only_source_inspection(
    *,
    payload: dict[str, object],
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    command_texts = _codex_post_tool_command_texts(payload)
    if not command_texts:
        return False
    return codex_tool_output_native(
        "post_tool_read_only", commands=command_texts, cwd=cwd, home_dir=home_dir
    ).allowed


def _codex_command_is_read_only_git_metadata(
    command_text: str,
    *,
    cwd: Path | None = None,
) -> bool:
    return codex_tool_output_native("git_metadata", command=command_text, cwd=cwd).allowed




def _codex_post_tool_command_texts(payload: dict[str, object]) -> tuple[str, ...]:
    tool_input = payload.get("tool_input")
    if isinstance(tool_input, dict):
        candidates: list[str] = []
        command = tool_input.get("command")
        if isinstance(command, str):
            stripped = command.strip()
            if stripped:
                candidates.append(stripped)
        for key in COMMAND_CANDIDATE_LIST_KEYS:
            candidate = tool_input.get(key)
            if isinstance(candidate, list):
                candidates.extend(
                    command_list_candidate_texts(candidate, preserve_items=key in COMMAND_SEQUENCE_KEYS)
                )
        if not candidates and str(payload.get("tool_name", "")).strip().lower() in {
            "cat_file",
            "open_file",
            "read",
            "read_file",
            "view",
            "view_file",
        }:
            for key in ("path", "file_path", "filePath", "filepath", "file", "filename"):
                value = tool_input.get(key)
                if isinstance(value, str) and value.strip():
                    candidates.append(f"cat -- {shlex.quote(value.strip())}")
        if not candidates:
            native_command = command_text_from_tool_payload(payload.get("tool_name"), tool_input)
            if native_command is not None:
                candidates.append(native_command)
        return tuple(dict.fromkeys(text for text in candidates if text))
    return ()


_CODEX_BENIGN_SOURCE_DOTFILES = SOURCE_INSPECTION_BENIGN_DOTFILES | frozenset({".worktrees"})


_CODEX_BENIGN_SECRET_FIXTURE_ASSIGNMENT_PATTERN = re.compile(
    r"""(?ix)
    \s*
    fake[_-]?(?:credential|secret|token)
    \s*[:=]\s*
    (?:
        "[^\r\n"]*"             # double-quoted value
        |'[^\r\n']*'            # single-quoted value
        |[^\s"',}]+             # unquoted token (excludes delimiters ,})
    )
    \s*"""
)


_CODEX_PRIVATE_KEY_FIXTURE_PATTERN = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?P<body>.*?)-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)


_CODEX_PRIVATE_KEY_FIXTURE_BODY_PATTERN = re.compile(
    r"(?i)\b(?:secret-key-material|fixture|fake|example|sample|dummy|test-key|placeholder)\b"
)


def _codex_source_inspection_can_skip_secret_output(
    *,
    command_text: str,
    response_text: str,
    content_matches: tuple[SecretContentMatch, ...],
    cwd: Path | None,
    home_dir: Path | None = None,
    payload: dict[str, object] | None = None,
) -> bool:
    command_is_read_only = _codex_command_is_read_only_source_inspection(
        command_text,
        cwd=cwd,
        home_dir=home_dir,
    )
    native_search_is_read_only = payload is not None and native_post_tool_search_is_read_only(
        payload=payload,
        cwd=cwd,
        home_dir=home_dir,
    )
    if not command_is_read_only and not native_search_is_read_only:
        return False
    if _codex_command_references_sensitive_local_source(command_text, cwd=cwd):
        return False
    if _codex_command_targets_secret_like_source_name(command_text, cwd=cwd, home_dir=home_dir):
        return False
    non_medium_matches = [match for match in content_matches if match.sensitivity != "medium"]
    if non_medium_matches:
        return all(
            match.classifier == "pem-private-key" for match in non_medium_matches
        ) and _codex_output_uses_placeholder_private_key_fixture(response_text)
    if _codex_command_references_benign_source_dotfile(command_text):
        return _codex_output_is_only_benign_secret_fixture(response_text)
    return True


def _codex_output_is_only_benign_secret_fixture(response_text: str) -> bool:
    lines = [line for line in response_text.splitlines() if line.strip()]
    return bool(lines) and all(_CODEX_BENIGN_SECRET_FIXTURE_ASSIGNMENT_PATTERN.fullmatch(line) for line in lines)


_codex_output_uses_placeholder_private_key_fixture = partial(
    output_uses_placeholder_private_key_fixture,
    fixture_pattern=_CODEX_PRIVATE_KEY_FIXTURE_PATTERN,
    fixture_body_pattern=_CODEX_PRIVATE_KEY_FIXTURE_BODY_PATTERN,
)


def _codex_command_references_benign_source_dotfile(command_text: str) -> bool:
    try:
        parts = shlex.split(command_text)
    except ValueError:
        return False
    return any(Path(part).name.lower() in _CODEX_BENIGN_SOURCE_DOTFILES for part in parts)


def _codex_command_targets_secret_like_source_name(
    command_text: str,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> bool:
    answer = codex_tool_output_native(
        "secret_like_source_name", command=command_text, cwd=cwd, home_dir=home_dir, exec_context=False
    )
    return answer.error_code is not None or answer.allowed


__all__ = [
    "_CODEX_BENIGN_SECRET_FIXTURE_ASSIGNMENT_PATTERN",
    "_CODEX_BENIGN_SOURCE_DOTFILES",
    "_CODEX_PRIVATE_KEY_FIXTURE_BODY_PATTERN",
    "_CODEX_PRIVATE_KEY_FIXTURE_PATTERN",
    "_codex_command_reads_environment_pipeline",
    "_codex_command_references_benign_source_dotfile",
    "_codex_command_targets_secret_like_source_name",
    "_codex_output_is_only_benign_secret_fixture",
    "_codex_output_uses_placeholder_private_key_fixture",
    "_codex_post_tool_command_is_read_only_source_inspection",
    "_codex_source_inspection_can_skip_secret_output",
]
