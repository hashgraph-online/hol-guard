"""Guard CLI helper definitions."""

# pyright: reportImportCycles=false

# fmt: off
# ruff: noqa: F403, F405, SIM905

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .commands_support_codex_git import _git_grep_search_args
    from .commands_support_codex_paths import _codex_search_target_is_source_like
    from .commands_support_codex_reads import (
        _codex_command_is_read_only_source_inspection,
        _codex_command_is_read_only_source_search,
        _codex_command_is_read_only_source_view,
        _codex_source_inspection_target_tokens,
        _split_codex_safe_read_only_chain,
        _split_codex_safe_read_only_pipeline,
    )
    from .commands_support_runtime_artifacts import _codex_command_references_sensitive_local_source


from ..runtime.secret_file_requests import COMMAND_LIST_KEYS
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
    local_read_commands = {"cat", "grep", "head", "rg", "sed", "tail"}
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
    command_text = _codex_post_tool_command_text(payload)
    return bool(command_text) and _codex_command_is_read_only_source_inspection(
        command_text,
        cwd=cwd,
        home_dir=home_dir,
    )

def _codex_post_tool_command_text(payload: dict[str, object]) -> str:
    tool_input = payload.get("tool_input")
    if isinstance(tool_input, dict):
        command = tool_input.get("command")
        if isinstance(command, str):
            return command.strip()
        for key in COMMAND_LIST_KEYS:
            candidate = tool_input.get(key)
            if isinstance(candidate, list):
                string_values = [item.strip() for item in candidate if isinstance(item, str) and item.strip()]
                if string_values:
                    return shlex.join(string_values)
    return ""

_CODEX_READ_ONLY_SEARCH_COMMANDS = frozenset({"fd", "rg", "grep", "egrep", "fgrep"})

_CODEX_READ_ONLY_VIEW_COMMANDS = frozenset({"cat", "head", "tail", "sed"})

_CODEX_READ_ONLY_PIPE_FILTERS = frozenset({"head", "tail", "sed"})

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
) -> bool:
    if not _codex_command_is_read_only_source_inspection(command_text, cwd=cwd, home_dir=home_dir):
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

def _codex_command_references_benign_source_dotfile(command_text: str) -> bool:
    try:
        parts = shlex.split(command_text)
    except ValueError:
        return False
    return any(Path(part).name.lower() in _CODEX_BENIGN_SOURCE_DOTFILES for part in parts)

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
