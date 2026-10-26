"""Shared command and tool classification constants."""

from __future__ import annotations

_FILE_READ_TOOL_NAMES = frozenset(
    {
        "read",
        "read_file",
        "open_file",
        "view",
        "view_file",
        "cat_file",
    }
)

# Deletes change files too; strreplace and delete are Cursor's native edit and delete tools.
_FILE_WRITE_TOOL_NAMES = frozenset(
    {
        "edit",
        "edit_file",
        "multiedit",
        "strreplace",
        "delete",
        "delete_file",
        "write",
        "write_file",
        "apply_patch",
    }
)

_PATH_KEYS = (
    "path",
    "file_path",
    "filePath",
    "filepath",
    "file",
    "filename",
    "target_path",
    "targetPath",
)

_PATH_LIST_KEYS = ("paths", "file_paths", "filePaths")

_COMMAND_KEYS = (
    "command",
    "cmd",
    "shell_command",
    "shellCommand",
    "pattern",
    "query",
    "search",
    "regex",
)


COMMAND_LIST_KEYS = ("argv", "command_args", "commandArgs")

COMMAND_SEQUENCE_KEYS = ("commands",)

COMMAND_CANDIDATE_LIST_KEYS = (*COMMAND_LIST_KEYS, *COMMAND_SEQUENCE_KEYS)


_DOCKER_BUILD_OUTPUT_FLAGS = frozenset(
    {"--cache-to", "--iidfile", "--load", "--metadata-file", "--output", "--push", "-o"}
)


_DOCKER_BUILDX_OPTIONS_WITH_VALUES = frozenset({"--builder"})

_DOCKER_BUILDX_FLAG_OPTIONS = frozenset({"--debug"})

_DOCKER_BUILD_ARG_SECRET_MARKERS = frozenset(
    {"API", "AUTH", "AWS", "CREDENTIAL", "KEY", "NPM", "PASSWORD", "SECRET", "TOKEN"}
)

_DOCKER_BUILD_ARG_TOKEN_PREFIXES = (
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "sk-",
)


_PYTEST_SAFE_FLAGS_WITH_VALUES = frozenset({"-k", "-m", "--maxfail", "--tb"})

_PYTEST_SAFE_FLAGS = frozenset({"-q", "-s", "-v", "-x", "--disable-warnings", "--quiet", "--verbose"})

_PYTHON_MODULE_MUTATING_FLAGS = {
    "mypy": frozenset({"--install-types"}),
    "pytest": frozenset({"--basetemp", "--debug", "--junitxml"}),
    "ruff": frozenset({"--add-noqa"}),
}


_SHELL_TOOL_NAMES = frozenset(
    {
        "ash",
        "bash",
        "cmd",
        "dash",
        "powershell",
        "pwsh",
        "run_command",
        "run_terminal_command",
        "shell",
        "sh",
        "terminal",
        "zsh",
    }
)


__all__ = [
    "COMMAND_CANDIDATE_LIST_KEYS",
    "COMMAND_LIST_KEYS",
    "COMMAND_SEQUENCE_KEYS",
    "_COMMAND_KEYS",
    "_DOCKER_BUILDX_FLAG_OPTIONS",
    "_DOCKER_BUILDX_OPTIONS_WITH_VALUES",
    "_DOCKER_BUILD_ARG_SECRET_MARKERS",
    "_DOCKER_BUILD_ARG_TOKEN_PREFIXES",
    "_DOCKER_BUILD_OUTPUT_FLAGS",
    "_FILE_READ_TOOL_NAMES",
    "_FILE_WRITE_TOOL_NAMES",
    "_PATH_KEYS",
    "_PATH_LIST_KEYS",
    "_PYTEST_SAFE_FLAGS",
    "_PYTEST_SAFE_FLAGS_WITH_VALUES",
    "_PYTHON_MODULE_MUTATING_FLAGS",
    "_SHELL_TOOL_NAMES",
]
