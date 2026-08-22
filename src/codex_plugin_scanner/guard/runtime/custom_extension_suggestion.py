"""Decide which observed CLIs are worth offering as custom extensions."""

from __future__ import annotations

from typing import Literal

LocalCliKind = Literal["executable", "script"]

_SEARCH_TOOLS = frozenset({"rg", "ripgrep", "ag", "ack", "fd", "fzf", "grep", "egrep", "fgrep"})
_IDENTITY_TOOLS = frozenset({"whoami", "id", "groups", "logname", "users", "who", "w"})
_RECORDER_TOOLS = frozenset({"script", "scriptreplay", "typescript", "asciinema"})
_TEST_RUNNER_NAMES = frozenset(
    {
        "vitest",
        "jest",
        "mocha",
        "ava",
        "tap",
        "jasmine",
        "karma",
        "pytest",
        "py.test",
        "nosetests",
        "unittest",
        "phpunit",
        "rspec",
        "playwright",
        "cypress",
    }
)
_GENERIC_NAMES = frozenset(
    {
        "script",
        "test",
        "tests",
        "run",
        "start",
        "build",
        "main",
        "index",
        "app",
        "bin",
        "cli",
        "tool",
        "tools",
        "helper",
        "util",
        "utils",
        "cmd",
        "exec",
        "tmp",
        "temp",
        "out",
        "output",
        "data",
        "default",
        "command",
    }
)
_RESERVED_TOOL_NAMES = frozenset({"hol-guard", "hol_guard", "guard"})
_PACKAGE_STORE_MARKERS = (
    "/node_modules/",
    "\\node_modules\\",
    "/.pnpm/",
    "/.venv/",
    "/venv/",
    "/site-packages/",
    "/__pycache__/",
    "/.nvm/",
    "/nvm/versions/",
)
_SYSTEM_BIN_PREFIXES = ("/bin/", "/usr/bin/", "/usr/sbin/", "/sbin/")
_PATH_CLASSES = frozenset({"unknown", "package-store", "system-bin", "user-tool"})
_WINDOWS_SYSTEM_PREFIXES = ("/windows/system32/", "/windows/syswow64/", "/windows/system/")
_SCRIPT_SUFFIXES = frozenset({"py", "js", "mjs", "cjs", "ts", "tsx", "jsx", "rb", "sh"})
COMMON_SHELL_UTILITIES = frozenset(
    {
        "[",
        "alias",
        "awk",
        "basename",
        "base64",
        "bat",
        "cat",
        "cd",
        "chmod",
        "chown",
        "clear",
        "column",
        "cp",
        "curl",
        "cut",
        "date",
        "df",
        "diff",
        "dirname",
        "du",
        "echo",
        "env",
        "false",
        "file",
        "find",
        "grep",
        "gzip",
        "head",
        "hexdump",
        "history",
        "hostname",
        "htop",
        "jq",
        "kill",
        "less",
        "ln",
        "ls",
        "lsof",
        "man",
        "md5",
        "mkdir",
        "more",
        "mv",
        "nano",
        "nc",
        "nice",
        "nl",
        "nohup",
        "nvim",
        "open",
        "paste",
        "patch",
        "pbcopy",
        "pbpaste",
        "ping",
        "printf",
        "ps",
        "pwd",
        "readlink",
        "realpath",
        "reset",
        "rev",
        "rm",
        "rmdir",
        "rsync",
        "scp",
        "sed",
        "seq",
        "sha256sum",
        "shasum",
        "sleep",
        "sort",
        "ssh",
        "stat",
        "stty",
        "sudo",
        "tail",
        "tar",
        "tee",
        "test",
        "time",
        "timeout",
        "tmux",
        "top",
        "touch",
        "tput",
        "tr",
        "true",
        "tty",
        "type",
        "uname",
        "uniq",
        "unalias",
        "unzip",
        "vim",
        "watch",
        "wc",
        "wget",
        "which",
        "xargs",
        "xxd",
        "yes",
        "yq",
        "zip",
        *_SEARCH_TOOLS,
        *_IDENTITY_TOOLS,
        *_RECORDER_TOOLS,
    }
)
_MIN_CLI_SCORE = 15


def is_common_shell_utility(name: str) -> bool:
    return _normalize_tool_name(name) in COMMON_SHELL_UTILITIES


def is_suggestable_custom_tool(
    *,
    name: str,
    kind: LocalCliKind,
    source_path: str | None = None,
    observed_count: int = 0,
    help_status: str | None = None,
    surface: str = "cli",
) -> bool:
    """Return whether an observed CLI is worth offering as a custom extension."""

    if surface in {"mcp", "package-scripts"}:
        return True
    return (
        suggestion_score(
            name=name,
            kind=kind,
            source_path=source_path,
            observed_count=observed_count,
            help_status=help_status,
            surface=surface,
        )
        >= _MIN_CLI_SCORE
    )


def suggestion_score(
    *,
    name: str,
    kind: LocalCliKind,
    source_path: str | None = None,
    observed_count: int = 0,
    help_status: str | None = None,
    surface: str = "cli",
) -> int:
    """Return a ranking score. Zero means hide the suggestion."""

    if surface in {"mcp", "package-scripts"}:
        return 100
    if not _name_is_suggestable(name):
        return 0
    if _path_is_junk(source_path):
        return 0
    score = 10
    if _name_is_distinctive(name):
        score += 20
    if observed_count >= 2:
        score += 10
    if observed_count >= 5:
        score += 10
    if help_status == "ok":
        score += 10
        if kind == "script":
            score += 5
    path_class = _path_class(source_path)
    if path_class == "user-tool":
        score += 5
    if path_class == "system-bin":
        score -= 20
    return max(score, 0)


def observation_path_class(source_path: str | None) -> str:
    """Return a path class token that can be stored without the raw path."""

    return _path_class(source_path)


def common_utility_reject_message(name: str) -> str:
    """Return operator-facing copy when a pasted command is a common tool."""

    normalized = _normalize_tool_name(name)
    if normalized in _SEARCH_TOOLS:
        return f"{normalized} is a common search tool, not a custom extension."
    if normalized in _IDENTITY_TOOLS:
        return f"{normalized} is a built-in identity command, not a custom extension."
    if normalized in _RECORDER_TOOLS:
        return f"{normalized} is a built-in terminal recorder, not a custom extension."
    return f"{normalized} is a built-in shell command, not a custom extension."


def _name_is_suggestable(name: str) -> bool:
    normalized = _normalize_tool_name(name)
    keys = _name_keys(normalized)
    if keys & COMMON_SHELL_UTILITIES or keys & _RESERVED_TOOL_NAMES:
        return False
    if keys & _TEST_RUNNER_NAMES or keys & _GENERIC_NAMES:
        return False
    return not _looks_like_test_file(normalized)


def _name_is_distinctive(name: str) -> bool:
    normalized = _normalize_tool_name(name)
    stem = normalized.split(".", 1)[0]
    if "-" in normalized or "_" in normalized:
        return len(stem) >= 4
    if "." in normalized:
        return stem not in _GENERIC_NAMES and len(stem) >= 3
    return len(normalized) >= 6


def _looks_like_test_file(name: str) -> bool:
    lowered = name.lower()
    if lowered.startswith("test_") and lowered.endswith(".py"):
        return True
    stem, separator, suffix = lowered.rpartition(".")
    if separator == "" or suffix not in _SCRIPT_SUFFIXES:
        return False
    return stem.endswith(".test") or stem.endswith(".spec") or stem.endswith("_test") or stem.endswith("_spec")


def _path_is_junk(source_path: str | None) -> bool:
    return _path_class(source_path) == "package-store"


def _path_class(source_path: str | None) -> str:
    if not source_path:
        return "unknown"
    if source_path in _PATH_CLASSES:
        return source_path
    posix = source_path.replace("\\", "/")
    lowered = posix.lower()
    padded = f"/{lowered.strip('/')}/"
    if any(marker in padded or marker in lowered for marker in _PACKAGE_STORE_MARKERS):
        return "package-store"
    if any(lowered == prefix[:-1] or lowered.startswith(prefix) for prefix in _SYSTEM_BIN_PREFIXES):
        return "system-bin"
    if _is_windows_system_bin(lowered):
        return "system-bin"
    return "user-tool"


def _is_windows_system_bin(posix_lower: str) -> bool:
    remainder = posix_lower
    if len(remainder) >= 2 and remainder[1] == ":":
        remainder = remainder[2:]
    if remainder.startswith("//?/"):
        remainder = remainder[4:]
        if len(remainder) >= 2 and remainder[1] == ":":
            remainder = remainder[2:]
    if not remainder.startswith("/"):
        remainder = f"/{remainder}"
    return any(remainder.startswith(prefix) for prefix in _WINDOWS_SYSTEM_PREFIXES)


def _name_keys(normalized: str) -> set[str]:
    keys = {normalized}
    if "." in normalized:
        keys.add(normalized.split(".", 1)[0])
    return keys


def _normalize_tool_name(name: str) -> str:
    base = name.strip().lower()
    if base.endswith(".exe") or base.endswith(".cmd"):
        return base.rsplit(".", 1)[0]
    return base
