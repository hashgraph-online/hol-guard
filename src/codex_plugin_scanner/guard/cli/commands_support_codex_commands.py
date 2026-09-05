"""Guard CLI helper definitions."""

# pyright: reportImportCycles=false

# fmt: off
# ruff: noqa: F403, F405, SIM905

from __future__ import annotations

from functools import partial
from typing import TYPE_CHECKING

from .codex_output_safety import output_uses_placeholder_private_key_fixture
from .commands_support_codex_reads import (
    _codex_source_name_stem_has_compound_secret_segment as _codex_source_name_stem_has_compound_secret_segment,
)
from .commands_support_codex_reads import (
    codex_scan_targets_secret_like_source_name,
)

if TYPE_CHECKING:
    from .commands_support_codex_git import _git_grep_search_args
    from .commands_support_codex_reads import (
        _codex_command_is_read_only_source_inspection,
        _codex_command_is_read_only_source_search,
        _codex_command_is_read_only_source_view,
    )
    from .commands_support_runtime_artifacts import _codex_command_references_sensitive_local_source


from ..runtime.git_execution_safety import (
    git_config_routing_environment_is_clean,
    git_status_args_are_read_only,
    git_status_has_execution_free_config,
    trusted_git_binary_for_cwd,
)
from ..runtime.secret_file_requests import (
    COMMAND_CANDIDATE_LIST_KEYS,
    COMMAND_SEQUENCE_KEYS,
    command_list_candidate_texts,
)
from ._commands_shared import *
from .commands_parser_helpers import *
from .commands_support_codex_tool_output import (
    _codex_command_segment_parts,
    _codex_command_start_indexes,
    _codex_env_args_clear_environment,
    _codex_shell_split,
    _codex_strip_env_wrapper,
    _codex_unwrapped_command_parts,
)
from .commands_support_native_search import native_post_tool_search_is_read_only


def _codex_pipeline_segment_may_read_local_content(segment: str, *, index: int, cwd: Path | None) -> bool:
    try:
        parts = _codex_shell_split(segment)
    except ValueError:
        return True
    if not parts:
        return False
    if index == 0:
        return _codex_command_parts_are_environment_dump(parts) or _codex_command_parts_may_read_local_content(
            parts,
            cwd=cwd,
        )
    return _codex_command_is_read_only_source_search(
        segment, cwd=cwd, home_dir=None
    ) or _codex_command_is_read_only_source_view(segment, cwd=cwd, home_dir=None)

def _codex_command_parts_may_read_local_content(parts: list[str], *, cwd: Path | None) -> bool:
    for start in _codex_command_start_indexes(parts):
        previous_token = parts[start - 1] if start > 0 else None
        segment_parts = _codex_command_segment_parts(parts, start)
        if previous_token == "|":
            if _codex_command_sequence_is_read_only_source_inspection(segment_parts, cwd=cwd):
                return True
            continue
        if _codex_command_sequence_starts_with_local_reader(segment_parts, cwd=cwd):
            return True
    return False

def _codex_command_reads_environment_pipeline(command_text: str) -> bool:
    try:
        parts = _codex_shell_split(command_text)
    except ValueError:
        return False
    if not parts:
        return False
    segment_starts = _codex_command_start_indexes(parts)
    if not segment_starts:
        return False
    first_segment = _codex_command_segment_parts(parts, segment_starts[0])
    if not _codex_command_parts_are_environment_dump(first_segment):
        return False
    saw_pipeline = False
    for start in segment_starts[1:]:
        separator = parts[start - 1]
        if separator != "|":
            return False
        saw_pipeline = True
    return saw_pipeline


def _codex_command_parts_are_environment_dump(parts: list[str]) -> bool:
    if not parts:
        return False
    executable = Path(parts[0]).name.lower()
    if executable == "printenv":
        return True
    if executable != "env":
        return False
    if _codex_env_args_clear_environment(parts[1:]):
        return False
    return not _codex_strip_env_wrapper(parts[1:])


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

def _codex_command_sequence_is_read_only_source_inspection(parts: list[str], *, cwd: Path | None) -> bool:
    command_parts = _codex_unwrapped_command_parts(parts)
    if not command_parts:
        return False
    segment = shlex.join(command_parts)
    return _codex_command_is_read_only_source_search(
        segment, cwd=cwd, home_dir=None
    ) or _codex_command_is_read_only_source_view(segment, cwd=cwd, home_dir=None)

def _codex_command_sequence_starts_with_local_reader(parts: list[str], *, cwd: Path | None) -> bool:
    command_parts = _codex_unwrapped_command_parts(parts)
    if not command_parts:
        return False
    if _codex_command_parts_are_git_grep(command_parts):
        return True
    return _codex_command_part_is_local_reader(command_parts, 0, cwd=cwd)

def _codex_command_parts_are_git_grep(parts: list[str]) -> bool:
    return bool(parts) and Path(parts[0]).name.lower() == "git" and _git_grep_search_args(parts[1:]) is not None

def _codex_command_part_is_local_reader(parts: list[str], index: int, *, cwd: Path | None) -> bool:
    local_read_commands = {"cat", "grep", "head", "nl", "rg", "sed", "tail", "wc", "yq"}
    executable = Path(parts[index]).name.lower()
    if executable not in local_read_commands:
        return False
    if index == 0:
        return True
    if parts[index - 1] == "|":
        segment = shlex.join(parts[index:])
        return _codex_command_is_read_only_source_search(
            segment, cwd=cwd, home_dir=None
        ) or _codex_command_is_read_only_source_view(segment, cwd=cwd, home_dir=None)
    return parts[index - 1] in {"&&", "||", ";", "&", "|&"}

def _codex_post_tool_command_is_read_only_source_inspection(
    *,
    payload: dict[str, object],
    cwd: Path | None,
    home_dir: Path | None,
) -> bool:
    command_texts = _codex_post_tool_command_texts(payload)
    return bool(command_texts) and all(
        _codex_command_is_read_only_source_inspection(command_text, cwd=cwd, home_dir=home_dir)
        or _codex_command_is_read_only_git_metadata(command_text, cwd=cwd)
        for command_text in command_texts
    )


def _codex_command_is_read_only_git_metadata(
    command_text: str,
    *,
    cwd: Path | None = None,
) -> bool:
    if any(marker in command_text for marker in ("\n", "\r", ";", "&", "|", "<", ">", "`", "$(")):
        return False
    try:
        parts = shlex.split(command_text)
    except ValueError:
        return False
    if not parts or parts[0] != "git":
        return False
    try:
        execution_cwd = (cwd or Path.cwd()).resolve()
    except (OSError, RuntimeError):
        return False
    if trusted_git_binary_for_cwd(execution_cwd) is None or not git_config_routing_environment_is_clean():
        return False
    args = parts[1:]
    if args[:1] == ["-C"]:
        if len(args) < 3:
            return False
        target = Path(args[1]).expanduser()
        try:
            target = (target if target.is_absolute() else execution_cwd / target).resolve(strict=True)
            target.relative_to(execution_cwd)
        except (OSError, RuntimeError, ValueError):
            return False
        if not target.is_dir():
            return False
        execution_cwd = target
        args = args[2:]
    if not args or args[0].startswith("-"):
        return False
    if args[0] == "status":
        return git_status_args_are_read_only(args) and git_status_has_execution_free_config(execution_cwd)
    if args[0:2] == ["worktree", "list"]:
        return all(
            arg in {"--porcelain", "-v", "--verbose", "-z"} or arg.startswith("--expire=")
            for arg in args[2:]
        )
    return args[0:2] == ["branch", "--list"] and all(not arg.startswith("-") for arg in args[2:])


def _codex_post_tool_command_text(payload: dict[str, object]) -> str:
    command_texts = _codex_post_tool_command_texts(payload)
    return command_texts[0] if command_texts else ""


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

_CODEX_READ_ONLY_SEARCH_COMMANDS = frozenset({"fd", "rg", "grep", "egrep", "fgrep"})

_CODEX_READ_ONLY_VIEW_COMMANDS = frozenset({"cat", "head", "nl", "tail", "sed", "wc", "yq"})

_CODEX_READ_ONLY_PIPE_FILTERS = frozenset({"cat", "head", "nl", "tail", "sed", "wc"})

_CODEX_READ_ONLY_SEARCH_WRAPPERS = frozenset({"bash", "sh", "zsh"})

_CODEX_SEARCH_PATTERN_VALUE_FLAGS = frozenset({"-e", "--regexp", "-f", "--file"})

_CODEX_SEARCH_OPTION_VALUE_FLAGS = frozenset(
    {
        *_CODEX_SEARCH_PATTERN_VALUE_FLAGS,
        "-g",
        "--glob",
        "--iglob",
        "--max-depth",
        "--type",
        "-t",
        "--type-not",
    }
)

_CODEX_SEARCH_OPTION_VALUE_FLAGS_BY_EXECUTABLE = {
    "grep": frozenset({"-d", "--directories"}),
    "rg": frozenset({"-T"}),
}

_CODEX_SEARCH_UNSAFE_FLAGS = frozenset({"--dereference-recursive", "--follow", "--pre"})

_CODEX_SEARCH_UNSAFE_SHORT_FLAGS_BY_EXECUTABLE = {
    "egrep": frozenset({"R"}),
    "fgrep": frozenset({"R"}),
    "grep": frozenset({"R"}),
    "rg": frozenset({"L"}),
}

_CODEX_GIT_GLOBAL_VALUE_FLAGS = frozenset(
    {"-c", "--config-env", "--exec-path", "--git-dir", "--work-tree", "--namespace"}
)

_CODEX_SOURCE_SEARCH_PREFIXES = tuple(f"{part}/" for part in sorted(SOURCE_INSPECTION_PARTS))

_CODEX_SOURCE_SEARCH_EXTENSIONS = SOURCE_INSPECTION_EXTENSIONS

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

_CODEX_SENSITIVE_SEARCH_BASENAMES = SOURCE_INSPECTION_SENSITIVE_PARTS | frozenset({"id_rsa"})

_CODEX_GIT_DIFF_VALUE_OPTIONS = frozenset(
    {
        "--diff-filter",
        "--inter-hunk-context",
        "--line-prefix",
        "--output-indicator-context",
        "--output-indicator-new",
        "--output-indicator-old",
        "--src-prefix",
        "--dst-prefix",
        "--stat-width",
        "--stat-name-width",
        "--stat-graph-width",
        "--unified",
        "-G",
        "-S",
        "-U",
        "--word-diff-regex",
    }
)

_CODEX_GIT_DIFF_OPTIONAL_VALUE_OPTIONS = frozenset(
    {
        "--color",
        "--color-moved",
        "--find-copies",
        "--find-renames",
        "--ignore-submodules",
        "--submodule",
        "--word-diff",
    }
)

_CODEX_GIT_DIFF_BOOLEAN_OPTIONS = frozenset(
    {
        "--binary",
        "--cached",
        "--check",
        "--compact-summary",
        "--exit-code",
        "--find-copies-harder",
        "--full-index",
        "--ignore-all-space",
        "--ignore-blank-lines",
        "--ignore-cr-at-eol",
        "--ignore-space-at-eol",
        "--ignore-space-change",
        "--minimal",
        "--name-only",
        "--name-status",
        "--no-ext-diff",
        "--no-textconv",
        "--numstat",
        "--patch",
        "--patch-with-raw",
        "--pickaxe-all",
        "--pickaxe-regex",
        "--raw",
        "--relative",
        "--shortstat",
        "--stat",
        "--summary",
        "--staged",
    }
)

_CODEX_GIT_DIFF_DISALLOWED_OPTIONS = frozenset({"--ext-diff", "--no-index", "--output", "--textconv"})

_CODEX_SAFE_GIT_GLOBAL_BOOLEAN_FLAGS = frozenset(
    {
        "--bare",
        "--glob-pathspecs",
        "--literal-pathspecs",
        "--no-literal-pathspecs",
        "--no-pager",
        "--noglob-pathspecs",
    }
)

@dataclass(frozen=True, slots=True)
class _CodexSedReadOnlyArgs:
    scripts: tuple[str, ...]
    targets: tuple[str, ...]
    saw_print_suppression: bool

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
    return codex_scan_targets_secret_like_source_name(
        command_text,
        cwd=cwd,
        home_dir=home_dir,
        recurse=lambda segment: _codex_command_targets_secret_like_source_name(segment, cwd=cwd, home_dir=home_dir),
    )

__all__ = """
_CODEX_BENIGN_SECRET_FIXTURE_ASSIGNMENT_PATTERN _CODEX_BENIGN_SOURCE_DOTFILES _CODEX_GIT_DIFF_BOOLEAN_OPTIONS
_CODEX_GIT_DIFF_DISALLOWED_OPTIONS _CODEX_GIT_DIFF_OPTIONAL_VALUE_OPTIONS _CODEX_GIT_DIFF_VALUE_OPTIONS
_CODEX_GIT_GLOBAL_VALUE_FLAGS _CODEX_PRIVATE_KEY_FIXTURE_BODY_PATTERN _CODEX_PRIVATE_KEY_FIXTURE_PATTERN
_CODEX_READ_ONLY_PIPE_FILTERS _CODEX_READ_ONLY_SEARCH_COMMANDS _CODEX_READ_ONLY_SEARCH_WRAPPERS
_CODEX_READ_ONLY_VIEW_COMMANDS _CODEX_SAFE_GIT_GLOBAL_BOOLEAN_FLAGS _CODEX_SEARCH_OPTION_VALUE_FLAGS
_CODEX_SEARCH_OPTION_VALUE_FLAGS_BY_EXECUTABLE _CODEX_SEARCH_PATTERN_VALUE_FLAGS _CODEX_SEARCH_UNSAFE_FLAGS
_CODEX_SEARCH_UNSAFE_SHORT_FLAGS_BY_EXECUTABLE _CODEX_SENSITIVE_SEARCH_BASENAMES _CODEX_SOURCE_SEARCH_EXTENSIONS
_CODEX_SOURCE_SEARCH_PREFIXES _CodexSedReadOnlyArgs _codex_command_part_is_local_reader
_codex_command_parts_are_environment_dump _codex_command_parts_are_git_grep
_codex_command_parts_may_read_local_content _codex_command_reads_environment_pipeline
_codex_command_references_benign_source_dotfile _codex_command_segment_parts
_codex_command_sequence_is_read_only_source_inspection _codex_command_sequence_starts_with_local_reader
_codex_command_start_indexes _codex_command_targets_secret_like_source_name
_codex_output_is_only_benign_secret_fixture _codex_output_uses_placeholder_private_key_fixture
_codex_pipeline_segment_may_read_local_content _codex_post_tool_command_is_read_only_source_inspection
_codex_post_tool_command_text _codex_shell_split _codex_source_inspection_can_skip_secret_output
_codex_source_name_stem_has_compound_secret_segment
_codex_unwrapped_command_parts
""".split()
