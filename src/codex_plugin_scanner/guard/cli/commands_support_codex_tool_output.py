"""Guard CLI helper definitions."""

# fmt: off
# ruff: noqa: F403, F405

from __future__ import annotations

from functools import partial

from ..native_codex_tool_output import codex_tool_output_native
from ..runtime.shell_execution_context import model_shell_execution_context, validate_shell_execution_segment
from ._commands_shared import *
from .codex_output_safety import output_uses_placeholder_private_key_fixture
from .commands_parser_helpers import *
from .commands_support_codex_paths import _PROMPT_PATH_TOKEN_PATTERN

_CODEX_PRIVATE_KEY_FIXTURE_PATTERN = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?P<body>.*?)-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)


_CODEX_PRIVATE_KEY_FIXTURE_BODY_PATTERN = re.compile(
    r"(?i)\b(?:secret-key-material|fixture|fake|example|sample|dummy|test-key|placeholder)\b"
)


_CODEX_PYTEST_PROGRESS_LINE_PATTERN = re.compile(r"^[.FEsxXrR]+$")


_CODEX_PYTEST_SUMMARY_LINE_PATTERN = re.compile(
    r"(?ix)^"
    r"(?:=+\s.*\s=+"
    r"|collected\s+\d+\s+items(?:\s*/\s*\d+\s+deselected)?"
    r"|(?:\d+\s+\w+(?:,\s*\d+\s+\w+)*)\s+in\s+\d+(?:\.\d+)?s"
    r"|.+::.+\s+(?:PASSED|FAILED|ERROR|SKIPPED|XFAIL|XPASS))$"
)


_codex_output_uses_placeholder_private_key_fixture = partial(
    output_uses_placeholder_private_key_fixture,
    fixture_pattern=_CODEX_PRIVATE_KEY_FIXTURE_PATTERN,
    fixture_body_pattern=_CODEX_PRIVATE_KEY_FIXTURE_BODY_PATTERN,
)


def _codex_command_targets_secret_like_source_name(
    command_text: str,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> bool:
    answer = codex_tool_output_native(
        "secret_like_source_name", command=command_text, cwd=cwd, home_dir=home_dir, exec_context=True
    )
    return answer.error_code is not None or answer.allowed


def _codex_command_references_sensitive_local_source(command_text: str, *, cwd: Path | None) -> bool:
    return bool(_codex_sensitive_local_source_matches(command_text, cwd=cwd))


def _codex_sensitive_local_source_matches(
    command_text: str,
    *,
    cwd: Path | None,
    _execution_context_applied: bool = False,
) -> list[SecretPathMatch]:
    if not _execution_context_applied:
        execution_context = model_shell_execution_context(command_text, cwd=cwd, workspace_root=cwd)
        if execution_context.directory_change_present:
            if not execution_context.complete:
                return []
            contextual_matches: list[SecretPathMatch] = []
            for segment in execution_context.segments:
                if segment.directory_operation is not None:
                    continue
                segment_cwd, reason = validate_shell_execution_segment(execution_context, segment)
                if segment_cwd is None or reason is not None:
                    return []
                contextual_matches.extend(
                    _codex_sensitive_local_source_matches(
                        segment.command_text,
                        cwd=segment_cwd,
                        _execution_context_applied=True,
                    )
                )
            return _dedupe_codex_secret_path_matches(contextual_matches)
    matches = _codex_sensitive_path_matches_in_text(command_text, cwd=cwd)
    try:
        parts = shlex.split(command_text)
    except ValueError:
        return matches
    for part in parts:
        stripped = part.strip()
        if not stripped or stripped.startswith("-"):
            continue
        if _codex_token_is_url(stripped):
            local_match = _codex_existing_local_path_match(stripped, cwd=cwd)
            if local_match is not None:
                matches.append(local_match)
            continue
        path_match = classify_secret_path(stripped, cwd=cwd)
        if path_match is not None:
            matches.append(path_match)
    return _dedupe_codex_secret_path_matches(matches)


def _dedupe_codex_secret_path_matches(matches: list[SecretPathMatch]) -> list[SecretPathMatch]:
    deduped: list[SecretPathMatch] = []
    seen: set[tuple[str, str]] = set()
    for match in matches:
        key = (match.family, match.requested_path or match.path)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(match)
    return deduped


def _codex_command_captures_combined_shell_output(command_text: str) -> bool:
    return "2>&1" in command_text or "|&" in command_text


def _codex_focused_pytest_can_skip_secret_output(
    *,
    command_text: str,
    response_text: str,
    content_matches: tuple[SecretContentMatch, ...],
    cwd: Path | None,
    home_dir: Path | None = None,
) -> bool:
    if not _codex_command_is_focused_pytest_verification(command_text):
        return False
    if _codex_command_references_sensitive_local_source(command_text, cwd=cwd):
        return False
    if _codex_command_targets_secret_like_source_name(command_text, cwd=cwd, home_dir=home_dir):
        return False
    non_medium_matches = [match for match in content_matches if match.sensitivity != "medium"]
    if non_medium_matches:
        return all(match.classifier == "pem-private-key" for match in non_medium_matches) and (
            _codex_output_uses_placeholder_private_key_fixture(response_text)
        )
    return _codex_focused_pytest_output_is_only_benign_fixture(response_text)


def _codex_focused_pytest_output_is_only_benign_fixture(response_text: str) -> bool:
    from .commands_support_codex_commands import _codex_output_is_only_benign_secret_fixture

    saw_fixture = False
    for raw_line in response_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if _codex_output_is_only_benign_secret_fixture(line):
            saw_fixture = True
            continue
        if _codex_focused_pytest_status_line_is_benign(line):
            continue
        return False
    return saw_fixture


def _codex_focused_pytest_status_line_is_benign(line: str) -> bool:
    return bool(
        _CODEX_PYTEST_PROGRESS_LINE_PATTERN.fullmatch(line)
        or _CODEX_PYTEST_SUMMARY_LINE_PATTERN.fullmatch(line)
    )


def _codex_command_is_focused_pytest_verification(command_text: str) -> bool:
    return codex_tool_output_native("focused_pytest", command=command_text).allowed


def _codex_token_is_url(token: str) -> bool:
    parsed = urllib.parse.urlparse(token)
    return bool(parsed.scheme and parsed.netloc)


def _codex_sensitive_path_matches_in_text(text: str, *, cwd: Path | None) -> list[SecretPathMatch]:
    matches: list[SecretPathMatch] = []
    for match in _PROMPT_PATH_TOKEN_PATTERN.finditer(text):
        token = match.group(0)
        if _codex_path_token_is_url_path(text, match.start()):
            local_match = _codex_existing_local_path_match(token, cwd=cwd)
            if local_match is not None:
                matches.append(local_match)
            continue
        path_match = classify_secret_path(token, cwd=cwd)
        if path_match is not None:
            matches.append(path_match)
    for token in _codex_url_like_local_path_tokens(text):
        local_match = _codex_existing_local_path_match(token, cwd=cwd)
        if local_match is not None:
            matches.append(local_match)
    return matches


def _codex_url_like_local_path_tokens(text: str) -> tuple[str, ...]:
    separators = frozenset(" \t\r\n'\"`<>|;(){}[]")
    tokens: list[str] = []
    start = 0
    for index, char in enumerate(f"{text} "):
        if char not in separators:
            continue
        token = text[start:index]
        start = index + 1
        if 0 < len(token) <= 255 and _codex_token_is_url(token):
            tokens.append(token)
    return tuple(tokens)


def _codex_existing_local_path_match(token: str, *, cwd: Path | None) -> SecretPathMatch | None:
    if cwd is None:
        return None
    base_dir = cwd.resolve()
    parsed = urllib.parse.urlparse(token)
    if not parsed.scheme or not parsed.netloc:
        return None
    relative_parts = [f"{parsed.scheme}:", parsed.netloc]
    for part in PurePosixPath(parsed.path).parts:
        if part in {"", "/", ".", ".."}:
            continue
        relative_parts.append(part)
    if len(relative_parts) <= 2 and not parsed.path.strip("/"):
        return None
    candidate = base_dir.joinpath(*relative_parts)
    if not candidate.exists():
        return None
    relative_candidate = candidate.relative_to(base_dir)
    return classify_secret_path(str(relative_candidate), cwd=cwd)


def _codex_path_token_is_url_path(text: str, start: int) -> bool:
    prefix = text[:start].lower()
    last_separator = max(prefix.rfind(separator) for separator in " \t\r\n'\"`<>|;(){}[]")
    token_prefix = prefix[last_separator + 1 :]
    if "://" in token_prefix:
        return True
    scheme = ""
    if token_prefix.endswith(":/"):
        scheme = token_prefix[:-2]
    elif token_prefix.endswith(":"):
        scheme = token_prefix[:-1]
    return _codex_token_prefix_is_url_scheme(scheme)


def _codex_token_prefix_is_url_scheme(scheme: str) -> bool:
    return bool(scheme) and scheme[0].isalpha() and all(char.isalnum() or char in "+.-" for char in scheme)
