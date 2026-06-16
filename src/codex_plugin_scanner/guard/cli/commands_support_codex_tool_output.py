"""Guard CLI helper definitions."""

# fmt: off
# ruff: noqa: F403, F405

from __future__ import annotations

from ._commands_shared import *
from .commands_parser_helpers import *
from .commands_support_codex_paths import _PROMPT_PATH_TOKEN_PATTERN, _codex_search_target_is_source_like
from .commands_support_codex_reads import (
    _codex_source_inspection_target_tokens,
    _split_codex_safe_read_only_chain,
    _split_codex_safe_read_only_pipeline,
)

_CODEX_PRIVATE_KEY_FIXTURE_PATTERN = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----(?P<body>.*?)-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)

_CODEX_PRIVATE_KEY_FIXTURE_BODY_PATTERN = re.compile(
    r"(?i)\b(?:secret-key-material|fixture|fake|example|sample|dummy|test-key|placeholder)\b"
)

_CODEX_SECRET_LIKE_SOURCE_NAME_STEMS = frozenset(
    {
        "auth",
        "credential",
        "credentials",
        "passwd",
        "password",
        "private-key",
        "private_key",
        "secret",
        "secrets",
        "token",
    }
)

_CODEX_PYTEST_SAFE_FLAGS = frozenset({"-q", "-s", "-x", "-v", "-vv", "-vvv", "-ra", "--lf", "--ff"})
_CODEX_PYTEST_SAFE_FLAGS_WITH_VALUES = frozenset({"-k", "-m", "--maxfail", "--tb", "--color", "--durations"})
_CODEX_PYTEST_SAFE_FLAG_PREFIXES = (
    "--maxfail=",
    "--tb=",
    "--color=",
    "--durations=",
)
_CODEX_SAFE_SHELL_REDIRECTION_TOKENS = frozenset({"1>&2", "2>&1", ">/dev/null", "1>/dev/null", "2>/dev/null"})


def _codex_tool_output_request_summary(
    *,
    tool_name: str,
    command_text: str,
    local_secret_source: str | None,
    merged_output_capture: bool = False,
) -> str:
    focused_pytest = _codex_command_is_focused_pytest_verification(command_text)
    if local_secret_source is not None:
        return f"Codex tool `{tool_name}` read local secrets from {local_secret_source} while running `{command_text}`."
    if focused_pytest and merged_output_capture:
        return (
            f"Codex tool `{tool_name}` ran focused pytest, merged stderr into stdout while running "
            f"`{command_text}`, and the captured output looked credential-like."
        )
    if focused_pytest:
        return (
            f"Codex tool `{tool_name}` ran focused pytest and produced credential-looking output while "
            f"running `{command_text}`."
        )
    if merged_output_capture:
        return (
            f"Codex tool `{tool_name}` merged stderr into stdout while running `{command_text}`, "
            "and the captured output looked credential-like."
        )
    return f"Codex tool `{tool_name}` produced credential-looking output while running `{command_text}`."


def _codex_tool_output_runtime_summary(
    local_secret_source: str | None,
    *,
    command_text: str = "",
    merged_output_capture: bool = False,
) -> str:
    focused_pytest = bool(command_text) and _codex_command_is_focused_pytest_verification(command_text)
    if local_secret_source is not None:
        return f"Local secrets from {local_secret_source} reached Codex tool output."
    if focused_pytest and merged_output_capture:
        return (
            "Focused pytest merged stderr into stdout and emitted credential-looking output before it reached "
            "Codex. Pytest can execute repository-controlled code, so this could be a real local secret."
        )
    if focused_pytest:
        return (
            "Focused pytest emitted credential-looking output before it reached Codex. "
            "Pytest can execute repository-controlled code, so this could be a real local secret."
        )
    if merged_output_capture:
        return "Combined stdout/stderr looked credential-like before it reached Codex."
    return "Requests a sensitive native tool action: credential-looking output reached Codex."


def _codex_tool_output_runtime_reason(
    local_secret_source: str | None,
    *,
    command_text: str = "",
    merged_output_capture: bool = False,
) -> str:
    focused_pytest = bool(command_text) and _codex_command_is_focused_pytest_verification(command_text)
    if local_secret_source is not None:
        return (
            "Guard inspects supported Codex tool output before Codex uses it, so accidental secret reads can be "
            "stopped even when the filename was not obviously sensitive."
        )
    if focused_pytest and merged_output_capture:
        return (
            "Guard stopped this pytest output because pytest executes repository-controlled code, and merging stderr "
            "into stdout can forward real local secrets to Codex. If you only need the exit status, rerun without "
            "`2>&1` or keep stderr out of model-visible output."
        )
    if focused_pytest:
        return (
            "Guard stopped this pytest output because pytest executes repository-controlled code. "
            "Credential-looking output could be a real local secret printed by the test, not just fixture text."
        )
    if merged_output_capture:
        return (
            "Guard stopped this command shape because merging stderr into stdout can send credential-looking failure "
            "output to Codex. If you only need the exit status, rerun without `2>&1` or keep stderr out of the "
            "model-visible output."
        )
    return (
        "Guard inspects supported Codex tool output before Codex uses it, so accidental secret reads can be stopped "
        "even when the filename was not obviously sensitive."
    )


def _codex_command_start_indexes(parts: list[str]) -> list[int]:
    starts = [0] if parts else []
    for index, part in enumerate(parts[:-1]):
        if part in {"&&", "||", ";", "&", "|", "|&"}:
            starts.append(index + 1)
    return starts


def _codex_command_segment_parts(parts: list[str], start: int) -> list[str]:
    end = start
    while end < len(parts) and parts[end] not in {"&&", "||", ";", "&", "|", "|&"}:
        end += 1
    return parts[start:end]


def _codex_unwrapped_command_parts(parts: list[str]) -> list[str]:
    remaining = parts
    while remaining:
        executable = Path(remaining[0]).name.lower()
        if executable == "command":
            remaining = _codex_strip_command_wrapper(remaining[1:])
            continue
        if executable == "env":
            remaining = _codex_strip_env_wrapper(remaining[1:])
            continue
        return remaining
    return []


def _codex_strip_command_wrapper(parts: list[str]) -> list[str]:
    index = 0
    while index < len(parts) and parts[index] in {"-p", "-v", "-V"}:
        index += 1
    if index < len(parts) and parts[index] == "--":
        index += 1
    return parts[index:]


def _codex_strip_env_wrapper(parts: list[str]) -> list[str]:
    index = 0
    while index < len(parts):
        part = parts[index]
        if part == "--":
            return parts[index + 1 :]
        if part in {"-i", "-0", "--ignore-environment", "--null"}:
            index += 1
            continue
        if part in {"-u", "--unset", "-C", "--chdir", "-S", "--split-string"}:
            index += 2
            continue
        if part.startswith(("--unset=", "--chdir=", "--split-string=")):
            index += 1
            continue
        if part.startswith("-"):
            index += 1
            continue
        if "=" in part and not part.startswith("="):
            index += 1
            continue
        return parts[index:]
    return []


def _codex_env_args_clear_environment(parts: list[str]) -> bool:
    saw_clear_environment = False
    for part in parts:
        if part == "--":
            return False
        if part in {"-i", "--ignore-environment"}:
            saw_clear_environment = True
            continue
        if part.startswith("-"):
            continue
        if "=" in part and not part.startswith("="):
            if _codex_env_assignment_uses_shell_expansion(part):
                return False
            continue
        return False
    return saw_clear_environment


def _codex_env_assignment_uses_shell_expansion(part: str) -> bool:
    _, _, value = part.partition("=")
    return "$" in value or "`" in value


def _codex_shell_split(command_text: str) -> list[str]:
    lexer = shlex.shlex(command_text, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    return list(lexer)


def _codex_output_uses_placeholder_private_key_fixture(response_text: str) -> bool:
    matches = list(_CODEX_PRIVATE_KEY_FIXTURE_PATTERN.finditer(response_text))
    if not matches:
        return False
    return all(
        _CODEX_PRIVATE_KEY_FIXTURE_BODY_PATTERN.search(
            " ".join(line.strip() for line in match.group("body").splitlines() if line.strip())
            .replace("\\n", " ")
            .replace("\\r", " ")
        )
        is not None
        for match in matches
    )


def _codex_source_name_stem_has_compound_secret_segment(stem: str, *, split_compound: bool) -> bool:
    lowered = stem.lower()
    if not split_compound:
        return False
    return any(
        segment in _CODEX_SECRET_LIKE_SOURCE_NAME_STEMS
        for segment in re.split(r"[-_]+", lowered)
        if segment and segment != lowered
    )


def _codex_command_targets_secret_like_source_name(
    command_text: str,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> bool:
    chained_segments = _split_codex_safe_read_only_chain(command_text)
    if chained_segments is not None:
        return any(
            _codex_command_targets_secret_like_source_name(segment, cwd=cwd, home_dir=home_dir)
            for segment in chained_segments
        )
    pipeline_segments = _split_codex_safe_read_only_pipeline(command_text)
    if pipeline_segments:
        return _codex_command_targets_secret_like_source_name(
            pipeline_segments[0],
            cwd=cwd,
            home_dir=home_dir,
        )
    try:
        parts = shlex.split(command_text)
    except ValueError:
        return False
    for part in _codex_source_inspection_target_tokens(parts):
        stripped = part.strip().strip("'\"")
        if not stripped:
            continue
        name = Path(stripped).name.lower().lstrip(".")
        stem = Path(name).stem or name
        exact_secret_like = stem.lower() in _CODEX_SECRET_LIKE_SOURCE_NAME_STEMS
        compound_secret_like = _codex_source_name_stem_has_compound_secret_segment(
            stem,
            split_compound=cwd is not None,
        )
        if not exact_secret_like and not compound_secret_like and not name.startswith("id_"):
            continue
        if compound_secret_like and cwd is not None and _codex_search_target_is_source_like(
            stripped,
            cwd=cwd,
            home_dir=home_dir,
        ):
            continue
        return True
    return False


def _codex_command_references_sensitive_local_source(command_text: str, *, cwd: Path | None) -> bool:
    return bool(_codex_sensitive_local_source_matches(command_text, cwd=cwd))


def _codex_sensitive_local_source_matches(command_text: str, *, cwd: Path | None) -> list[SecretPathMatch]:
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
    from .commands_support_codex_commands import _codex_output_is_only_benign_secret_fixture

    return _codex_output_is_only_benign_secret_fixture(response_text)


def _codex_command_is_focused_pytest_verification(command_text: str) -> bool:
    try:
        parts = _codex_shell_split(command_text)
    except ValueError:
        return False
    if not parts:
        return False
    saw_pytest = False
    for start in _codex_command_start_indexes(parts):
        segment_parts = _codex_command_segment_parts(parts, start)
        if not segment_parts:
            return False
        separator = parts[start - 1] if start > 0 else None
        if separator in {"|", "|&", "||", "&"}:
            return False
        if _codex_command_segment_is_safe_directory_change(segment_parts):
            continue
        if _codex_command_segment_is_exit_code_echo(segment_parts):
            continue
        if _codex_command_segment_is_focused_pytest(segment_parts):
            saw_pytest = True
            continue
        return False
    return saw_pytest


def _codex_command_segment_is_safe_directory_change(parts: list[str]) -> bool:
    command_parts = _codex_unwrapped_command_parts(parts)
    return len(command_parts) == 2 and Path(command_parts[0]).name.lower() == "cd"


def _codex_command_segment_is_exit_code_echo(parts: list[str]) -> bool:
    command_parts = _codex_unwrapped_command_parts(parts)
    if len(command_parts) != 2:
        return False
    return Path(command_parts[0]).name.lower() == "echo" and command_parts[1].startswith("__EXIT_CODE__:$?")


def _codex_command_segment_is_focused_pytest(parts: list[str]) -> bool:
    command_parts = [part for part in parts if part not in _CODEX_SAFE_SHELL_REDIRECTION_TOKENS]
    command_parts = _codex_unwrapped_command_parts(command_parts)
    if not command_parts:
        return False
    executable = Path(command_parts[0]).name.lower()
    args: list[str]
    if executable == "pytest":
        args = command_parts[1:]
    elif (
        executable.startswith("python")
        and len(command_parts) >= 3
        and command_parts[1] == "-m"
        and command_parts[2] == "pytest"
    ):
        args = command_parts[3:]
    else:
        return False
    saw_target = False
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in _CODEX_PYTEST_SAFE_FLAGS:
            index += 1
            continue
        if any(arg.startswith(prefix) for prefix in _CODEX_PYTEST_SAFE_FLAG_PREFIXES):
            index += 1
            continue
        if arg in _CODEX_PYTEST_SAFE_FLAGS_WITH_VALUES:
            if index + 1 >= len(args):
                return False
            index += 2
            continue
        if arg.startswith("-"):
            return False
        if _codex_pytest_target_arg(arg):
            saw_target = True
            index += 1
            continue
        return False
    return saw_target


def _codex_pytest_target_arg(value: str) -> bool:
    stripped = value.strip()
    if not stripped:
        return False
    return (
        "::" in stripped
        or stripped.endswith(".py")
        or stripped == "tests"
        or stripped.startswith("tests/")
        or "/tests/" in stripped
        or stripped.startswith("test_")
    )


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
