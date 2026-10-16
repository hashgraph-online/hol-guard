"""Shared command and tool classification constants."""

from __future__ import annotations

from pathlib import Path

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

_SUDO_OPTION_VALUE_FLAGS = frozenset({"-u", "-g", "-h", "-p", "-C", "-D", "-R", "-r", "-T", "-t"})

_SUDO_OPTION_VALUE_LONG_FLAGS = frozenset(
    {
        "--chdir",
        "--chroot",
        "--close-from",
        "--command-timeout",
        "--group",
        "--host",
        "--login-class",
        "--prompt",
        "--role",
        "--type",
        "--user",
    }
)

_GH_PR_OPTION_VALUE_FLAGS = frozenset({"-R", "--repo"})

_SHELL_CONTROL_PREFIX_TOKENS = frozenset(
    {"!", "(", "{", "case", "do", "elif", "else", "for", "if", "select", "then", "until", "while"}
)

COMMAND_LIST_KEYS = ("argv", "command_args", "commandArgs")

COMMAND_SEQUENCE_KEYS = ("commands",)

COMMAND_CANDIDATE_LIST_KEYS = (*COMMAND_LIST_KEYS, *COMMAND_SEQUENCE_KEYS)

_COMMAND_LIST_KEYS = COMMAND_LIST_KEYS

_DOCKER_ALWAYS_SENSITIVE_SUBCOMMANDS = frozenset({"login", "push", "run"})

_DOCKER_BUILD_SUBCOMMANDS = frozenset({"build"})

_DOCKER_BUILDX_BUILD_SUBCOMMANDS = frozenset({"b", "build"})

_DOCKER_BUILD_SECRET_FLAGS = frozenset({"--allow", "--secret", "--ssh"})

_DOCKER_BUILD_OUTPUT_FLAGS = frozenset(
    {"--cache-to", "--iidfile", "--load", "--metadata-file", "--output", "--push", "-o"}
)

_DOCKER_BUILD_METADATA_FLAGS = frozenset({"--annotation", "--label"})

_DOCKER_GLOBAL_OPTIONS_WITH_VALUES = frozenset(
    {
        "--config",
        "--context",
        "--host",
        "--log-level",
        "--tlscacert",
        "--tlscert",
        "--tlskey",
        "-c",
        "-H",
        "-l",
    }
)

_DOCKER_GLOBAL_FLAG_OPTIONS = frozenset({"--debug", "--tls", "--tlsverify"})

_DOCKER_GLOBAL_SENSITIVE_CONTEXT_OPTIONS = frozenset(
    {"--config", "--context", "--host", "--tlscacert", "--tlscert", "--tlskey", "-c", "-H"}
)

_DOCKER_GLOBAL_SENSITIVE_CONTEXT_FLAGS = frozenset({"--tls", "--tlsverify"})

_DOCKER_SENSITIVE_CONTEXT_ENV_KEYS = frozenset(
    {
        "COMPOSE_ENV_FILES",
        "DOCKER_CERT_PATH",
        "DOCKER_CONFIG",
        "DOCKER_CONTEXT",
        "DOCKER_HOST",
        "DOCKER_TLS_VERIFY",
    }
)

_DOCKER_COMPOSE_SUBCOMMAND = "compose"

_DOCKER_COMPOSE_OPTIONS_WITH_VALUES = frozenset(
    {
        "--ansi",
        "--env-file",
        "--file",
        "--parallel",
        "--profile",
        "--profiles",
        "--project-directory",
        "--project-name",
        "--progress",
        "-f",
        "-p",
    }
)

_DOCKER_COMPOSE_FLAG_OPTIONS = frozenset(
    {"--all-resources", "--compatibility", "--dry-run", "--no-ansi", "--no-interpolate", "--verbose", "--volumes", "-q"}
)

_DOCKER_COMPOSE_SAFE_SUBCOMMANDS = frozenset(
    {
        "build",
        "config",
        "create",
        "down",
        "events",
        "images",
        "logs",
        "ls",
        "pause",
        "port",
        "ps",
        "pull",
        "restart",
        "rm",
        "start",
        "stop",
        "top",
        "unpause",
        "up",
        "version",
        "wait",
    }
)

_DOCKER_COMPOSE_SENSITIVE_SUBCOMMANDS = frozenset({"cp", "exec", "publish", "push", "run", "watch"})

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

_SAFE_PYTHON_MODULE_COMMANDS = frozenset({"pytest", "ruff"})

_TRUSTED_INTERPRETER_INSTALL_ROOTS = (
    Path("/home/linuxbrew/.linuxbrew"),
    Path("/opt/homebrew"),
    Path("/opt/hostedtoolcache/Python"),
    Path("/usr/local"),
)

_SAFE_PYTHON_MODULE_SHADOW_PATHS = {
    "pytest": (
        "pytest.py",
        "pytest.pyc",
        "pytest/__init__.py",
        "pytest/__init__.pyc",
        "pytest/__main__.py",
        "pytest/__main__.pyc",
    ),
    "ruff": (
        "ruff.py",
        "ruff.pyc",
        "ruff/__init__.py",
        "ruff/__init__.pyc",
        "ruff/__main__.py",
        "ruff/__main__.pyc",
    ),
}

_PYTEST_OPTION_CONFIG_PATHS = (
    "pytest.toml",
    ".pytest.toml",
    "pytest.ini",
    ".pytest.ini",
    "pyproject.toml",
    "tox.ini",
    "setup.cfg",
)

_PYTEST_UNSAFE_ENV_KEYS = frozenset({"PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTHONHOME", "PYTHONPATH", "PYTHONUSERBASE"})

_SHELL_STARTUP_ENV_KEYS = frozenset({"BASH_ENV", "ENV", "ZDOTDIR"})

_PYTEST_SAFE_FLAGS_WITH_VALUES = frozenset({"-k", "-m", "--maxfail", "--tb"})

_PYTEST_SAFE_FLAGS = frozenset({"-q", "-s", "-v", "-x", "--disable-warnings", "--quiet", "--verbose"})

_PYTHON_INTERPRETER_OPTIONS_WITH_VALUES = frozenset({"--check-hash-based-pycs", "-W", "-X"})

_PYTHON_MODULE_MUTATING_FLAGS = {
    "mypy": frozenset({"--install-types"}),
    "pytest": frozenset({"--basetemp", "--debug", "--junitxml"}),
    "ruff": frozenset({"--add-noqa"}),
}

_PYTHON_MODULE_MUTATING_SUBCOMMANDS = {
    "ruff": frozenset({"format"}),
}

_PYTHON_MODULE_OPTIONS_WITH_VALUES = {
    "ruff": frozenset({"--cache-dir", "--color", "--config"}),
}

_SAFE_STATIC_SHELL_COMMANDS = frozenset({"echo", "printf", "true"})

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

_SHELL_SCRIPT_INTERPRETER_COMMANDS = frozenset({"ash", "bash", "dash", "sh", "zsh", ".", "source"})

_SHELL_COMMAND_STRING_INTERPRETERS = frozenset({"ash", "bash", "dash", "sh", "zsh"})

_DESTRUCTIVE_SHELL_COMMANDS = frozenset(
    {
        "chmod",
        "chown",
        "dd",
        "del",
        "erase",
        "mv",
        "perl",
        "python",
        "python3",
        "rd",
        "remove-item",
        "rm",
        "rmdir",
        "ruby",
        "tee",
        "truncate",
        "unlink",
    }
)

_UNMODELED_INLINE_INTERPRETER_COMMANDS = frozenset({"perl", "ruby"})

_SAFE_SHELL_REDIRECT_TARGETS = frozenset(
    {
        "/dev/null",
        "/dev/stdout",
        "/dev/stderr",
        "nul",
    }
)

_READ_ONLY_LOOKUP_COMMANDS = frozenset(
    {"cat", "date", "fd", "find", "grep", "egrep", "fgrep", "head", "ls", "pwd", "rg", "sed", "tail"}
)

_READ_ONLY_LOOKUP_FILTERS = frozenset({"cat", "grep", "egrep", "fgrep", "head", "rg", "sed", "tail"})

_READ_ONLY_SEARCH_EXECUTION_FLAGS = {
    "rg": frozenset({"--config-path", "--hostname-bin", "--pre", "--pre-glob"}),
}

_FIND_EXEC_PLACEHOLDER_TARGET = "guard-find-placeholder.py"

_FIND_EXEC_ACTION_FLAGS = frozenset({"-exec", "-execdir", "-ok", "-okdir"})

_FIND_EXEC_TERMINATOR_TOKENS = frozenset({";", r"\;", "+"})

__all__ = [
    "COMMAND_CANDIDATE_LIST_KEYS",
    "COMMAND_LIST_KEYS",
    "COMMAND_SEQUENCE_KEYS",
    "_COMMAND_KEYS",
    "_COMMAND_LIST_KEYS",
    "_DESTRUCTIVE_SHELL_COMMANDS",
    "_DOCKER_ALWAYS_SENSITIVE_SUBCOMMANDS",
    "_DOCKER_BUILDX_BUILD_SUBCOMMANDS",
    "_DOCKER_BUILDX_FLAG_OPTIONS",
    "_DOCKER_BUILDX_OPTIONS_WITH_VALUES",
    "_DOCKER_BUILD_ARG_SECRET_MARKERS",
    "_DOCKER_BUILD_ARG_TOKEN_PREFIXES",
    "_DOCKER_BUILD_METADATA_FLAGS",
    "_DOCKER_BUILD_OUTPUT_FLAGS",
    "_DOCKER_BUILD_SECRET_FLAGS",
    "_DOCKER_BUILD_SUBCOMMANDS",
    "_DOCKER_COMPOSE_FLAG_OPTIONS",
    "_DOCKER_COMPOSE_OPTIONS_WITH_VALUES",
    "_DOCKER_COMPOSE_SAFE_SUBCOMMANDS",
    "_DOCKER_COMPOSE_SENSITIVE_SUBCOMMANDS",
    "_DOCKER_COMPOSE_SUBCOMMAND",
    "_DOCKER_GLOBAL_FLAG_OPTIONS",
    "_DOCKER_GLOBAL_OPTIONS_WITH_VALUES",
    "_DOCKER_GLOBAL_SENSITIVE_CONTEXT_FLAGS",
    "_DOCKER_GLOBAL_SENSITIVE_CONTEXT_OPTIONS",
    "_DOCKER_SENSITIVE_CONTEXT_ENV_KEYS",
    "_FILE_READ_TOOL_NAMES",
    "_FILE_WRITE_TOOL_NAMES",
    "_FIND_EXEC_ACTION_FLAGS",
    "_FIND_EXEC_PLACEHOLDER_TARGET",
    "_FIND_EXEC_TERMINATOR_TOKENS",
    "_GH_PR_OPTION_VALUE_FLAGS",
    "_PATH_KEYS",
    "_PATH_LIST_KEYS",
    "_PYTEST_OPTION_CONFIG_PATHS",
    "_PYTEST_SAFE_FLAGS",
    "_PYTEST_SAFE_FLAGS_WITH_VALUES",
    "_PYTEST_UNSAFE_ENV_KEYS",
    "_PYTHON_INTERPRETER_OPTIONS_WITH_VALUES",
    "_PYTHON_MODULE_MUTATING_FLAGS",
    "_PYTHON_MODULE_MUTATING_SUBCOMMANDS",
    "_PYTHON_MODULE_OPTIONS_WITH_VALUES",
    "_READ_ONLY_LOOKUP_COMMANDS",
    "_READ_ONLY_LOOKUP_FILTERS",
    "_READ_ONLY_SEARCH_EXECUTION_FLAGS",
    "_SAFE_PYTHON_MODULE_COMMANDS",
    "_SAFE_PYTHON_MODULE_SHADOW_PATHS",
    "_SAFE_SHELL_REDIRECT_TARGETS",
    "_SAFE_STATIC_SHELL_COMMANDS",
    "_SHELL_COMMAND_STRING_INTERPRETERS",
    "_SHELL_CONTROL_PREFIX_TOKENS",
    "_SHELL_SCRIPT_INTERPRETER_COMMANDS",
    "_SHELL_STARTUP_ENV_KEYS",
    "_SHELL_TOOL_NAMES",
    "_SUDO_OPTION_VALUE_FLAGS",
    "_SUDO_OPTION_VALUE_LONG_FLAGS",
    "_TRUSTED_INTERPRETER_INSTALL_ROOTS",
    "_UNMODELED_INLINE_INTERPRETER_COMMANDS",
]
