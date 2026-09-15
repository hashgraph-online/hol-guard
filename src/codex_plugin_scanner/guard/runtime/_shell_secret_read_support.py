"""Private parsing and path helpers for shell secret-read assessment."""

from __future__ import annotations

import re
from dataclasses import replace
from pathlib import Path

from ._shell_execution_context_support import (
    SHELL_CWD_MISSING_DIRECTORY,
    SHELL_CWD_NOT_DIRECTORY,
    SHELL_CWD_UNREADABLE_DIRECTORY,
    split_shell_tokens,
)
from .command_model import CanonicalCommand, CommandSegment
from .home_path_text import expand_home, normalize_path
from .secret_sensitivity import classify_secret_path
from .shell_execution_context import ShellExecutionSegment

_SHELLS = frozenset({"sh", "bash", "dash", "ash", "zsh", "ksh", "fish", "source", "."})
_SCRIPT_SUFFIXES = (
    ".sh",
    ".bash",
    ".zsh",
    ".ksh",
    ".fish",
    ".py",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".rb",
    ".pl",
)
_OTHER_READERS = frozenset({"base64", "xxd", "od", "hexdump", "strings", "tac", "less", "more", "sort", "uniq", "wc"})
_MAX_SCRIPTS = 16
_MAX_DEPTH = 4
_MAX_TOTAL_BYTES = 128 * 1024
_MAX_INLINE_SCRIPT_BYTES = 64 * 1024
_PYTHON_EXECUTABLE = re.compile(r"pythonw?(?:\d+(?:\.\d+)*)?(?:\.exe)?$", re.IGNORECASE)
_LITERAL_READ = re.compile(
    r"(?:\bopen|\breadFile(?:Sync)?|\bcreateReadStream|\bBun\.file|\bload_dotenv)"
    r"\s*\(\s*(['\"])([^'\"\n\x00]{1,4096})\1"
)
_PATH_READ = re.compile(
    r"\bPath\s*\(\s*(['\"])([^'\"\n\x00]{1,4096})\1\s*\)"
    r"\s*\.\s*(?:read_text|read_bytes|open)\s*\("
)
_SHORT_CIRCUITING_CD_FAILURES = frozenset(
    {SHELL_CWD_MISSING_DIRECTORY, SHELL_CWD_NOT_DIRECTORY, SHELL_CWD_UNREADABLE_DIRECTORY}
)
_FLOW_OPERATORS = frozenset({"&&", "||", "|", ";", "&"})


def _literal_read_paths(source: str) -> tuple[str, ...]:
    """Return bounded literal file operands from supported inline runtimes."""

    return tuple(match.group(2) for pattern in (_LITERAL_READ, _PATH_READ) for match in pattern.finditer(source))


def _python_executable(name: str) -> bool:
    return _PYTHON_EXECUTABLE.fullmatch(name) is not None


def _command_may_need_read_assessment(command_text: str) -> bool:
    """Skip filesystem modeling when syntax cannot read files or launch local code."""

    try:
        tokens = split_shell_tokens(command_text)
    except ValueError:
        return True
    interesting = {
        *_SHELLS,
        *_OTHER_READERS,
        "cat",
        "head",
        "tail",
        "sed",
        "grep",
        "egrep",
        "fgrep",
        "rg",
        "read",
        "command",
        "exec",
        "node",
        "bun",
        "ruby",
        "perl",
    }
    for token in tokens:
        if "<" in token:
            return True
        normalized = token.strip()
        if not normalized:
            continue
        name = "." if normalized == "." else Path(normalized).name.lower()
        if name in interesting or _python_executable(name):
            return True
        if _path_qualified(normalized):
            return True
    return False


def _sensitive_path(value: str, *, cwd: Path | None, home_dir: Path | None) -> str | None:
    """Classify a literal or metadata-resolved alias without opening secrets."""

    match = classify_secret_path(value, cwd=cwd, home_dir=home_dir)
    if match is not None:
        return match.path
    lexical = Path(normalize_path(expand_home(value, home_dir), cwd))
    roots = tuple(root for root in (cwd, home_dir) if root is not None)
    if not lexical.is_absolute() or not any(lexical.is_relative_to(root) for root in roots):
        return None
    try:
        resolved = lexical.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return None
    match = classify_secret_path(str(resolved), cwd=cwd, home_dir=home_dir)
    return match.path if match is not None else None


def _unwrap_execution_builtin(
    executable: str,
    args: tuple[str, ...],
) -> tuple[str | None, tuple[str, ...], bool]:
    """Unwrap literal command/exec prefixes or report ambiguous execution."""

    name = Path(executable or "").name.lower()
    if name == "command":
        index = 0
        lookup_only = False
        while index < len(args):
            arg = args[index]
            if arg == "--":
                index += 1
                break
            if arg.startswith("-"):
                flags = arg[1:]
                if not flags or any(flag not in "pVv" for flag in flags):
                    return None, (), True
                lookup_only = lookup_only or "v" in flags or "V" in flags
                index += 1
                continue
            break
        if lookup_only:
            return None, (), False
        if index >= len(args):
            return None, (), False
        return args[index], args[index + 1 :], False
    if name == "exec":
        index = 0
        while index < len(args):
            arg = args[index]
            if arg == "--":
                index += 1
                break
            if arg == "-a":
                if index + 1 >= len(args):
                    return None, (), True
                index += 2
                continue
            if arg in {"-c", "-l"}:
                index += 1
                continue
            if arg.startswith("-"):
                return None, (), True
            break
        if index >= len(args):
            return None, (), False
        return args[index], args[index + 1 :], False
    return executable, args, False


def _direct_secret_read_paths_from_tokens(
    tokens: tuple[str, ...],
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> tuple[str, ...]:
    """Recover direct reader operands when the full command exceeds parser bounds."""

    from .secret_file_request_services.local_read_operands import _shell_segment_file_operand_tokens

    if not tokens:
        return ()
    executable, args, ambiguous = _unwrap_execution_builtin(tokens[0], tokens[1:])
    if ambiguous or executable is None:
        return ()
    name = "." if executable == "." else Path(executable).name.lower()
    args_list = list(args)
    candidates = list(_shell_segment_file_operand_tokens([name, *args_list]))
    if name in _OTHER_READERS:
        candidates.extend(arg for arg in args_list if not arg.startswith("-"))
    if name in {"source", "."}:
        candidates.extend(args_list[:1])
    for index, token in enumerate(args_list[:-1]):
        if re.fullmatch(r"\d*<|\d*<>", token):
            candidates.append(args_list[index + 1])
    for token in args_list:
        match = re.fullmatch(r"\d*<(?!<)(.+)", token)
        if match is not None:
            candidates.append(match.group(1))
    return tuple(
        dict.fromkeys(
            path for value in candidates if (path := _sensitive_path(value, cwd=cwd, home_dir=home_dir)) is not None
        )
    )


def direct_secret_read_paths(
    command: CanonicalCommand,
    *,
    cwd: Path | None,
    home_dir: Path | None,
) -> tuple[str, ...]:
    """Find direct credential reads for a command whose cwd is already proven."""

    from .secret_file_request_services.local_read_operands import _shell_segment_file_operand_tokens

    candidates: list[str] = []
    for segment in command.segments:
        executable, args, ambiguous = _unwrap_execution_builtin(
            segment.executable or "",
            segment.arguments,
        )
        if ambiguous or executable is None:
            continue
        name = "." if executable == "." else Path(executable).name.lower()
        args_list = list(args)
        candidates.extend(_shell_segment_file_operand_tokens([name, *args_list]))
        if name in _OTHER_READERS:
            candidates.extend(arg for arg in args_list if not arg.startswith("-"))
        if name in {"source", "."}:
            candidates.extend(args_list[:1])
        if name in {"node", "bun", "ruby", "perl"} or _python_executable(name):
            for index, arg in enumerate(args_list[:-1]):
                if arg in {"-c", "-e", "--eval", "-p", "--print"}:
                    candidates.extend(_literal_read_paths(args_list[index + 1]))
                elif arg.startswith(("--eval=", "--print=")):
                    candidates.extend(_literal_read_paths(arg.split("=", 1)[1]))
    for redirect in command.redirects:
        if redirect.operator.lstrip("0123456789") in {"<", "<>"}:
            candidates.append(redirect.target)
    return tuple(
        dict.fromkeys(
            path for value in candidates if (path := _sensitive_path(value, cwd=cwd, home_dir=home_dir)) is not None
        )
    )


def _shell_command_string(executable: str, args: tuple[str, ...]) -> tuple[str | None, bool]:
    """Return a literal shell command string and whether command-string mode was requested."""

    name = "." if executable == "." else Path(executable).name.lower()
    if name not in _SHELLS:
        return None, False
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            return None, False
        if arg == "--command":
            return (args[index + 1] if index + 1 < len(args) else None), True
        if arg.startswith("--command="):
            return arg.split("=", 1)[1], True
        if arg == "-s":
            return None, False
        if arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:]:
            from .interpreter_options import shell_interpreter_command_payload

            parsed = shell_interpreter_command_payload([executable, *args], 0)
            return (parsed.script_text if parsed is not None else None), True
        if arg in {"-o", "-O", "+o", "+O", "--rcfile", "--init-file"}:
            index += 2
            continue
        if not arg.startswith(("-", "+")):
            return None, False
        index += 1
    return None, False


def _script_operand(executable: str, args: tuple[str, ...]) -> tuple[str, bool] | None:
    """Return one literal local script operand that can be inspected safely."""

    name = "." if executable == "." else Path(executable).name.lower()
    is_shell = name in _SHELLS
    is_interpreter = name in {"node", "ruby", "perl"} or _python_executable(name)
    if is_shell or is_interpreter:
        index = 0
        while index < len(args):
            arg = args[index]
            if (
                arg in {"-c", "-e", "--eval", "-m", "--command"}
                or (is_shell and arg == "-s")
                or (is_shell and arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:])
            ):
                return None
            if arg == "--":
                index += 1
                break
            if arg in {"-o", "-O", "+o", "+O", "--rcfile", "--init-file"}:
                index += 2
                continue
            if not arg.startswith(("-", "+")):
                break
            index += 1
        if index < len(args) and args[index] != "-":
            return args[index], is_shell
    if name == "bun" and args and args[0].endswith(_SCRIPT_SUFFIXES):
        return args[0], False
    if executable.endswith(_SCRIPT_SUFFIXES) and ("/" in executable or executable.startswith(".")):
        return executable, executable.endswith((".sh", ".bash", ".zsh", ".ksh", ".fish"))
    return None


def _known_python_module_launch(executable: str, args: tuple[str, ...], *, cwd: Path | None) -> bool:
    """Return True for a trusted tooling module handled by dedicated policy."""

    name = Path(executable or "").name.lower()
    if not _python_executable(name):
        return False
    from .secret_file_request_services.constants_core import _SAFE_PYTHON_MODULE_COMMANDS
    from .secret_file_request_services.interpreter_observers import _python_module_may_be_shadowed
    from .secret_file_request_services.pytest_config_safety import _python_module_root_from_args

    module_root = _python_module_root_from_args(list(args))
    return bool(module_root in _SAFE_PYTHON_MODULE_COMMANDS and not _python_module_may_be_shadowed(module_root, cwd))


def _python_module_launch(executable: str, args: tuple[str, ...], *, cwd: Path | None) -> bool:
    """Return True when Python may import mutable workspace code via ``-m``."""

    name = Path(executable or "").name.lower()
    if not _python_executable(name):
        return False
    if _known_python_module_launch(executable, args, cwd=cwd):
        return False
    for index, arg in enumerate(args):
        if arg == "--":
            return False
        if arg == "-m" or (arg.startswith("-m") and len(arg) > 2):
            return True
        if arg in {"-W", "-X"} and index + 1 < len(args):
            continue
        if not arg.startswith("-"):
            return False
    return False


def _interpreter_stdin_launch(executable: str, args: tuple[str, ...]) -> bool:
    """Return True when an interpreter executes source supplied on stdin."""

    name = Path(executable or "").name.lower()
    if name not in {"node", "bun", "ruby", "perl"} and not _python_executable(name):
        return False
    inline_flags = {"-c", "-e", "--eval", "-p", "--print"}
    if any(arg in inline_flags or arg.startswith(("--eval=", "--print=")) for arg in args):
        return False
    return "-" in args


def _interpreter_inline_launch(executable: str, args: tuple[str, ...]) -> bool:
    """Return True for literal inline-code modes whose file reads were already scanned."""

    name = Path(executable or "").name.lower()
    if name not in {"node", "bun", "ruby", "perl"} and not _python_executable(name):
        return False
    for arg in args:
        if arg == "--":
            return False
        if arg in {"-c", "-e", "--eval", "-p", "--print"} or arg.startswith(("--eval=", "--print=")):
            return True
        if not arg.startswith("-"):
            return False
    return False


def _path_qualified(executable: str) -> bool:
    return bool(executable) and ("/" in executable or "\\" in executable or executable.startswith("."))


def _local_executable_operand(
    executable: str,
    *,
    cwd: Path | None,
    home_dir: Path | None,
    roots: tuple[Path, ...],
) -> str | None:
    """Return a path-qualified executable only when it is inside a guarded local root."""

    if not _path_qualified(executable):
        return None
    lexical = Path(normalize_path(expand_home(executable, home_dir), cwd))
    if not lexical.is_absolute() or not any(lexical.is_relative_to(root) for root in roots):
        return None
    return executable


def _parse_execution_segment(
    execution: ShellExecutionSegment,
    *,
    raw_model: CanonicalCommand,
    raw_segment: CommandSegment | None,
) -> CanonicalCommand | None:
    """Keep source syntax and require agreement with the cwd model.

    Re-quoting decoded tokens changes input redirections into ordinary argv
    and can erase command/exec ambiguity. The raw command parser deliberately
    skips transparent-wrapper normalization for this inspection path.
    """

    if not execution.complete or execution.effective_cwd is None or raw_segment is None:
        return None
    try:
        if split_shell_tokens(raw_segment.text) != execution.tokens:
            return None
    except ValueError:
        return None
    return replace(
        raw_model,
        segments=(raw_segment,),
        redirects=tuple(
            redirect
            for redirect in raw_model.redirects
            if raw_segment.start <= redirect.start and redirect.end <= raw_segment.end
        ),
        embedded_commands=(),
    )


def _segment_may_touch_local_data(execution: ShellExecutionSegment) -> bool:
    """Keep unknown file/code access closed without treating stdout as a file."""

    from .secret_file_request_services.local_read_operands import _shell_segment_file_operand_tokens

    if not execution.tokens:
        return False
    token = execution.tokens[0]
    executable = "." if token == "." else Path(token).name.lower()
    args = list(execution.tokens[1:])
    has_input_redirect = any(re.match(r"^\d*<(?!<)", item) for item in execution.tokens)
    if has_input_redirect or _shell_segment_file_operand_tokens([executable, *args]):
        return True
    if executable in _OTHER_READERS:
        return any(not arg.startswith("-") for arg in args)
    return (
        executable in {*_SHELLS, "command", "exec", "node", "bun", "ruby", "perl"}
        or _python_executable(executable)
        or _path_qualified(token)
    )


def _flow_operator_before(execution: ShellExecutionSegment) -> str | None:
    return next((token for token in reversed(execution.control_before) if token in _FLOW_OPERATORS), None)


def _failed_cd_short_circuit_state(
    execution: ShellExecutionSegment,
    *,
    active: bool,
) -> tuple[bool, bool]:
    """Return the failed-cd state and whether this segment is provably unreachable."""

    operator = _flow_operator_before(execution)
    if operator in {"||", ";", "&"}:
        active = False
    if execution.directory_operation is not None and execution.reason_code in _SHORT_CIRCUITING_CD_FAILURES:
        return True, False
    return active, bool(active and operator in {"&&", "|"})
