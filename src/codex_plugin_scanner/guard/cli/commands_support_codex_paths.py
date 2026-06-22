"""Guard CLI helper definitions."""

# ruff: noqa: F403, F405

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .commands_support_codex_commands import (
        _CODEX_BENIGN_SOURCE_DOTFILES,
        _CODEX_SEARCH_OPTION_VALUE_FLAGS,
        _CODEX_SEARCH_OPTION_VALUE_FLAGS_BY_EXECUTABLE,
        _CODEX_SEARCH_PATTERN_VALUE_FLAGS,
        _CODEX_SEARCH_UNSAFE_FLAGS,
        _CODEX_SEARCH_UNSAFE_SHORT_FLAGS_BY_EXECUTABLE,
        _CODEX_SENSITIVE_SEARCH_BASENAMES,
        _CODEX_SOURCE_SEARCH_EXTENSIONS,
        _CODEX_SOURCE_SEARCH_PREFIXES,
    )
    from .commands_support_codex_reads import _codex_sed_args_are_bounded_filter
    from .commands_support_runtime_artifacts import (
        _CODEX_PROMPT_FILE_FINGERPRINT_LENGTH,
        _CODEX_TOOL_RESPONSE_MAX_DEPTH,
        _CODEX_TOOL_RESPONSE_TEXT_LIMIT,
    )
    from .commands_support_runtime_resolution import (
        _redact_codex_prompt_secret_assignments,
        _resolve_prompt_scan_path,
        _truncate_codex_display_text,
    )


from ._commands_shared import *
from .commands_parser_helpers import *


def _git_config_value_without_inline_comment(raw_value: str) -> str:
    value = raw_value.strip()
    if not value:
        return value
    quote = value[0] if value[0] in {"'", '"'} else None
    if quote is not None:
        escaped = False
        parsed: list[str] = []
        for char in value[1:]:
            if escaped:
                parsed.append(char)
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if char == quote:
                return "".join(parsed)
            parsed.append(char)
        return "".join(parsed)
    for index, char in enumerate(value):
        if char in {"#", ";"} and (index == 0 or value[index - 1].isspace()):
            return value[:index].strip()
    return value


def _git_config_enables_diff_helper(config_text: str) -> bool:
    return any(
        re.match(r"(?i)^\s*(?:command|external|textconv)\s*=", line) for line in _git_config_logical_lines(config_text)
    )


def _git_config_logical_lines(config_text: str) -> tuple[str, ...]:
    lines: list[str] = []
    pending = ""
    for raw_line in config_text.splitlines():
        line = raw_line.rstrip()
        if _git_config_line_continues(line):
            pending = f"{pending}{line[:-1]}"
            continue
        if pending:
            lines.append(f"{pending}{line.lstrip()}")
            pending = ""
            continue
        lines.append(line)
    if pending:
        lines.append(pending)
    return tuple(lines)


def _git_config_line_continues(line: str) -> bool:
    backslashes = 0
    for char in reversed(line):
        if char != "\\":
            break
        backslashes += 1
    return backslashes % 2 == 1


def _git_grep_uses_external_execution(args: list[str]) -> bool:
    return any(
        arg == "-O"
        or (arg.startswith("-O") and len(arg) > 2)
        or arg == "--open-files-in-pager"
        or arg.startswith("--open-files-in-pager=")
        or arg in {"--textconv", "--ext-grep"}
        for arg in args
    )


def _shell_wrapper_script_index(parts: list[str]) -> int | None:
    for index, arg in enumerate(parts[1:], start=1):
        if arg == "-c":
            return index + 1
        if arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:]:
            return index + 1
    return None


def _codex_command_has_unquoted_shell_control(command: str) -> bool:
    quote: str | None = None
    escaped = False
    for char in command:
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if quote is not None:
            if char == quote:
                quote = None
            if quote == '"' and char == "`":
                return True
            if quote == '"' and char == "$":
                return True
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char in {"\n", "\r"}:
            return True
        if char in {"|", "&", ";", ">", "<", "`"}:
            return True
        if char == "$":
            return True
    return False


def _codex_search_targets_are_source_like(
    args: list[str],
    *,
    cwd: Path | None,
    home_dir: Path | None,
    executable: str,
) -> bool:
    targets = _codex_search_targets(args, executable=executable)
    if not targets:
        return False
    return bool(targets) and all(
        _codex_search_target_is_source_like(target, cwd=cwd, home_dir=home_dir) for target in targets
    )


def _codex_fd_targets_are_source_like(args: list[str], *, cwd: Path | None, home_dir: Path | None) -> bool:
    if fd_args_follow_symlinks(args):
        return False
    targets = _codex_fd_targets(args)
    if not targets:
        return False
    return all(_codex_search_target_is_source_like(target, cwd=cwd, home_dir=home_dir) for target in targets)


def _codex_fd_targets(args: list[str]) -> tuple[str, ...]:
    return fd_search_targets(args) or ("__guard_unsafe_fd_args__",)


def _codex_fd_exec_is_bounded_read_only(args: list[str]) -> bool:
    if fd_args_follow_symlinks(args):
        return False
    parsed = split_fd_args_and_exec(args)
    if parsed is None:
        return not any(fd_arg_requests_exec(arg) for arg in args)
    _fd_args, exec_parts = parsed
    if not exec_parts or not fd_exec_token_is_plain_sed(exec_parts[0]):
        return False
    if exec_parts.count("{}") != 1:
        return False
    sed_args = [arg for arg in exec_parts[1:] if arg != "{}"]
    return _codex_sed_args_are_bounded_filter(sed_args)


def _codex_search_targets(args: list[str], *, executable: str) -> tuple[str, ...]:
    positional: list[str] = []
    skip_next = False
    pattern_from_option = False
    after_option_terminator = False
    option_value_flags = _CODEX_SEARCH_OPTION_VALUE_FLAGS | _CODEX_SEARCH_OPTION_VALUE_FLAGS_BY_EXECUTABLE.get(
        executable, frozenset()
    )
    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if after_option_terminator:
            positional.append(arg)
            continue
        if arg == "--":
            after_option_terminator = True
            continue
        if _codex_search_arg_is_unsafe(arg, executable=executable, option_value_flags=option_value_flags):
            return ()
        if arg in _CODEX_SEARCH_PATTERN_VALUE_FLAGS:
            pattern_from_option = True
            skip_next = True
            continue
        if any(arg.startswith(flag) and len(arg) > len(flag) for flag in ("-e", "-f")):
            pattern_from_option = True
            continue
        if arg in option_value_flags:
            skip_next = True
            continue
        if any(arg.startswith(f"{flag}=") for flag in _CODEX_SEARCH_PATTERN_VALUE_FLAGS):
            pattern_from_option = True
            continue
        if any(arg.startswith(f"{flag}=") for flag in option_value_flags):
            continue
        if arg.startswith("-"):
            continue
        positional.append(arg)
    if pattern_from_option:
        return tuple(positional)
    if len(positional) >= 2:
        return tuple(positional[1:])
    return ()


def _codex_search_arg_is_unsafe(arg: str, *, executable: str, option_value_flags: frozenset[str]) -> bool:
    if arg in _CODEX_SEARCH_UNSAFE_FLAGS:
        return True
    if any(arg.startswith(f"{flag}=") for flag in _CODEX_SEARCH_UNSAFE_FLAGS):
        return True
    if not arg.startswith("-") or arg.startswith("--"):
        return False
    unsafe_short_flags = _CODEX_SEARCH_UNSAFE_SHORT_FLAGS_BY_EXECUTABLE.get(executable, frozenset())
    for flag in arg[1:]:
        if flag in unsafe_short_flags:
            return True
        if f"-{flag}" in option_value_flags:
            return False
    return False


def _codex_search_target_is_source_like(target: str, *, cwd: Path | None, home_dir: Path | None) -> bool:
    stripped = target.strip().strip("'\"")
    if not stripped:
        return False
    if target_is_known_skill_doc_path(stripped, home_dir=home_dir):
        return True
    if any(char in stripped for char in ("*", "?", "{", "}")):
        return False
    base_dir = (cwd or Path.cwd()).resolve()
    target_path = _codex_resolve_source_like_path(stripped, cwd=base_dir, home_dir=home_dir)
    if target_path is None:
        return False
    if target_path.is_absolute():
        try:
            candidate = target_path.resolve(strict=False)
            relative_candidate = candidate.relative_to(base_dir)
        except (RuntimeError, ValueError):
            return False
        if _path_contains_symlink(candidate, base_dir=base_dir):
            return False
        parts = [part for part in relative_candidate.parts if part not in {"", "."}]
    else:
        unresolved_candidate = base_dir / target_path
        if _path_contains_symlink(unresolved_candidate, base_dir=base_dir):
            return False
        try:
            candidate = unresolved_candidate.resolve(strict=False)
        except RuntimeError:
            return False
        if candidate.exists():
            try:
                relative_candidate = candidate.relative_to(base_dir)
            except ValueError:
                return False
            parts = [part for part in relative_candidate.parts if part not in {"", "."}]
        else:
            parts = [part for part in target_path.parts if part not in {"", "."}]
    if not parts:
        return False
    lowered_parts = [part.lower() for part in parts]
    if any(part in _CODEX_SENSITIVE_SEARCH_BASENAMES for part in lowered_parts):
        return False
    hidden_parts = [part for part in lowered_parts if part.startswith(".")]
    if hidden_parts and not all(part in _CODEX_BENIGN_SOURCE_DOTFILES for part in hidden_parts):
        return False
    normalized = "/".join(parts)
    if normalized in {prefix.rstrip("/") for prefix in _CODEX_SOURCE_SEARCH_PREFIXES}:
        return True
    if any(normalized.startswith(prefix) for prefix in _CODEX_SOURCE_SEARCH_PREFIXES):
        return True
    if any(part in SOURCE_INSPECTION_PARTS for part in lowered_parts):
        return True
    if Path(stripped).name.lower() in _CODEX_BENIGN_SOURCE_DOTFILES:
        return True
    return Path(stripped).suffix.lower() in _CODEX_SOURCE_SEARCH_EXTENSIONS


def _codex_resolve_source_like_path(target: str, *, cwd: Path | None, home_dir: Path | None) -> Path | None:
    stripped = target.strip().strip("'\"")
    if not stripped:
        return None
    if stripped.startswith("~"):
        if home_dir is None:
            return None
        if stripped == "~":
            return home_dir.resolve()
        if not stripped.startswith("~/"):
            return None
        return (home_dir / stripped[2:]).resolve(strict=False)
    target_path = Path(stripped)
    if target_path.is_absolute():
        return target_path
    return (cwd or Path.cwd()).resolve() / target_path


def _codex_absolute_search_target_is_source_like(target_path: Path) -> bool:
    parts = [part for part in target_path.parts if part not in {"", "/", "."}]
    if not parts:
        return False
    lowered_parts = [part.lower() for part in parts]
    if any(part in _CODEX_SENSITIVE_SEARCH_BASENAMES for part in lowered_parts):
        return False
    hidden_parts = [part for part in lowered_parts if part.startswith(".")]
    if hidden_parts and not all(part in _CODEX_BENIGN_SOURCE_DOTFILES for part in hidden_parts):
        return False
    normalized = "/".join(parts)
    if any(f"/{prefix}" in f"/{normalized}" for prefix in _CODEX_SOURCE_SEARCH_PREFIXES):
        return True
    return target_path.suffix.lower() in _CODEX_SOURCE_SEARCH_EXTENSIONS


def _path_contains_symlink(path: Path, *, base_dir: Path) -> bool:
    candidate = base_dir
    try:
        relative_parts = path.relative_to(base_dir).parts
    except ValueError:
        return True
    for part in relative_parts:
        if part in {"", "."}:
            continue
        candidate /= part
        try:
            if candidate.is_symlink():
                return True
        except OSError:
            return True
    return False


def _collect_codex_tool_response_text(value: object, *, depth: int = 0) -> str:
    if depth > _CODEX_TOOL_RESPONSE_MAX_DEPTH:
        return ""
    if isinstance(value, str):
        return value[:_CODEX_TOOL_RESPONSE_TEXT_LIMIT]
    if isinstance(value, dict):
        parts: list[str] = []
        for key, child in value.items():
            key_text = str(key).lower()
            if key_text in {"stdout", "stderr", "output", "text", "content", "result", "message"} or depth > 0:
                text = _collect_codex_tool_response_text(child, depth=depth + 1)
                if text:
                    parts.append(text)
        return "\n".join(parts)[:_CODEX_TOOL_RESPONSE_TEXT_LIMIT]
    if isinstance(value, list):
        return "\n".join(_collect_codex_tool_response_text(item, depth=depth + 1) for item in value)[
            :_CODEX_TOOL_RESPONSE_TEXT_LIMIT
        ]
    return ""


_PROMPT_PATH_TOKEN_PATTERN = re.compile(
    r"(?<![\w/.-])\.[A-Za-z0-9][A-Za-z0-9_.-]{0,255}|"
    r"(?:~|\.{1,2}|/)[^\s'\"`<>|;(){}\[\]]{0,255}"
)

_PROMPT_FILE_READ_VERB_PATTERN = re.compile(r"\b(?:read|open|print|show|dump|cat|head|tail|less|view|display)\b", re.I)

_PROMPT_CONTENT_SCAN_MAX_BYTES = 64 * 1024

_PROMPT_CONTENT_SCAN_SKIP_BASENAMES = frozenset(
    {
        ".env",
        ".npmrc",
        ".pypirc",
        ".netrc",
        ".git-credentials",
    }
)

_PROMPT_CONTENT_SCAN_SECRET_BASENAME_MARKERS = frozenset(
    {
        "auth",
        "credential",
        "env",
        "key",
        "pass",
        "secret",
        "token",
    }
)
_CODEX_PROMPT_RETRY_BOILERPLATE_PATTERNS = (
    re.compile(
        r"Warning:\s*HOL Guard flagged this prompt because it asks for direct local secret access and is protecting "
        r"your local secrets\. If that is intentional, continue and Guard will ask again on the actual tool call\. "
        r"Open HOL Guard to approve or keep this blocked:\s*\S+\. "
        r"After you choose, retry the same the harness action\.?",
        re.IGNORECASE,
    ),
    re.compile(
        r"HOL Guard stopped this Codex prompt before Codex could open (?:a credential-looking local file|a sensitive "
        r"local file)\. Codex does not expose native approval prompts for Read-tool file reads, so Guard blocks this "
        r"request at prompt time\. Open HOL Guard to approve or keep this blocked:\s*\S+\. After you choose, retry "
        r"the same Codex action\.?",
        re.IGNORECASE,
    ),
)


def _codex_prompt_credential_file_artifact(
    *,
    prompt_text: str,
    cwd: Path | None,
    config_path: str,
) -> GuardArtifact | None:
    if _PROMPT_FILE_READ_VERB_PATTERN.search(prompt_text) is None:
        return None
    for match in _PROMPT_PATH_TOKEN_PATTERN.finditer(prompt_text):
        requested_path = match.group(0)
        path = _resolve_prompt_scan_path(requested_path, cwd=cwd)
        if path is None or path.name in _PROMPT_CONTENT_SCAN_SKIP_BASENAMES:
            continue
        if not path.name.startswith("."):
            continue
        if not _prompt_path_looks_secret_bearing(path):
            continue
        if not path.is_file():
            continue
        try:
            with path.open("rb") as handle:
                content = handle.read(_PROMPT_CONTENT_SCAN_MAX_BYTES).decode("utf-8", errors="ignore")
        except OSError:
            continue
        if not classify_secret_content(content):
            continue
        normalized_path = str(path)
        fingerprint = hashlib.sha256(
            json.dumps(
                {
                    "harness": "codex",
                    "prompt_path": normalized_path,
                    "content_class": "credential-looking local file",
                },
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()[:_CODEX_PROMPT_FILE_FINGERPRINT_LENGTH]
        prompt_display = _codex_prompt_display_text(prompt_text, requested_path=requested_path)
        prompt_intent_hash = hashlib.sha256(_codex_prompt_intent_text(prompt_text).encode("utf-8")).hexdigest()
        return GuardArtifact(
            artifact_id=f"codex:project:prompt-file:{fingerprint}",
            name=f"credential-looking local file {path.name}",
            harness="codex",
            artifact_type="prompt_request",
            source_scope="project",
            config_path=config_path,
            metadata={
                "prompt_signals": ["requested file content contains credential-looking material"],
                "prompt_summary": "Prompt asks Codex to read a credential-looking local file.",
                "prompt_matched_text": requested_path,
                "prompt_intent_hash": prompt_intent_hash,
                "prompt_display_text": prompt_display,
                "prompt_request_class": "secret_read",
                "prompt_request_classes": ["secret_read"],
                "request_summary": prompt_display,
                "runtime_request_summary": prompt_display,
                "runtime_request_reason": (
                    "Guard scanned a small local dotfile before Codex read it and found credential-looking text."
                ),
                "normalized_path": normalized_path,
            },
        )
    return None


def _prompt_path_looks_secret_bearing(path: Path) -> bool:
    lowered_name = path.name.lower()
    return any(marker in lowered_name for marker in _PROMPT_CONTENT_SCAN_SECRET_BASENAME_MARKERS)


def _with_codex_prompt_display_metadata(artifact: GuardArtifact, *, prompt_text: str) -> GuardArtifact:
    matched_text = artifact.metadata.get("prompt_matched_text")
    display = _codex_prompt_display_text(
        prompt_text,
        requested_path=matched_text if isinstance(matched_text, str) else None,
    )
    metadata = {
        **artifact.metadata,
        "prompt_display_text": display,
        "request_summary": display,
        "runtime_request_summary": display,
    }
    return replace(artifact, metadata=metadata)


def _codex_prompt_display_text(prompt_text: str, *, requested_path: str | None = None) -> str:
    sanitized_prompt = _sanitize_codex_display_text(prompt_text)
    path_suffix = ""
    if requested_path is not None and requested_path.strip():
        path_suffix = f" for `{_sanitize_codex_display_text(requested_path.strip())}`"
    return f"Codex prompt{path_suffix}: {_truncate_codex_display_text(sanitized_prompt, limit=320)}"


def _codex_prompt_intent_text(prompt_text: str) -> str:
    normalized = _sanitize_codex_display_text(prompt_text)
    for pattern in _CODEX_PROMPT_RETRY_BOILERPLATE_PATTERNS:
        normalized = pattern.sub(" ", normalized)
    return " ".join(normalized.split())


def _sanitize_codex_display_text(value: str) -> str:
    collapsed = " ".join(value.strip().split())
    redacted = _redact_codex_prompt_secret_assignments(collapsed)
    sanitized = re.sub(r"/(?:Users|home)/[^/\s]+", "~", redacted)
    return re.sub(r"[A-Za-z]:\\Users\\[^\\\s]+", "~", sanitized)


__all__ = [
    "_PROMPT_CONTENT_SCAN_MAX_BYTES",
    "_PROMPT_CONTENT_SCAN_SECRET_BASENAME_MARKERS",
    "_PROMPT_CONTENT_SCAN_SKIP_BASENAMES",
    "_PROMPT_FILE_READ_VERB_PATTERN",
    "_PROMPT_PATH_TOKEN_PATTERN",
    "_codex_absolute_search_target_is_source_like",
    "_codex_command_has_unquoted_shell_control",
    "_codex_fd_exec_is_bounded_read_only",
    "_codex_fd_targets",
    "_codex_fd_targets_are_source_like",
    "_codex_prompt_credential_file_artifact",
    "_codex_prompt_display_text",
    "_codex_resolve_source_like_path",
    "_codex_search_arg_is_unsafe",
    "_codex_search_target_is_source_like",
    "_codex_search_targets",
    "_codex_search_targets_are_source_like",
    "_collect_codex_tool_response_text",
    "_git_config_enables_diff_helper",
    "_git_config_line_continues",
    "_git_config_logical_lines",
    "_git_config_value_without_inline_comment",
    "_git_grep_uses_external_execution",
    "_path_contains_symlink",
    "_prompt_path_looks_secret_bearing",
    "_sanitize_codex_display_text",
    "_shell_wrapper_script_index",
    "_with_codex_prompt_display_metadata",
]
