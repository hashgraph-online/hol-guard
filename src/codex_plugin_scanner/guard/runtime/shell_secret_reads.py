"""Bounded, non-executing evidence for shell reads and local script launches.

A script without detected secret references is not a proof of safety. Imports,
computed paths and subprocesses can still access local data, so script launches
retain an execution floor. Inspection can only raise or explain that floor.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from pathlib import Path

from ._shell_execution_context_support import (
    SHELL_CWD_MISSING_DIRECTORY,
    SHELL_CWD_NOT_DIRECTORY,
    SHELL_CWD_UNREADABLE_DIRECTORY,
    SHELL_CWD_UNRESOLVED_PARENT_SHELL,
    SHELL_CWD_WORKSPACE_ESCAPE,
    split_shell_tokens,
)
from .command_model import CanonicalCommand, CommandSegment, parse_shell_command
from .data_flow import extract_heredocs
from .home_path_text import expand_home, normalize_path
from .secret_sensitivity import classify_secret_path
from .shell_execution_context import ShellExecutionSegment, model_shell_execution_context

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


@dataclass(frozen=True, slots=True)
class ShellReadAssessment:
    sensitive_paths: tuple[str, ...]
    script_sources: tuple[tuple[str, str], ...]
    script_requested: bool
    incomplete: bool

    @property
    def requires_review(self) -> bool:
        """Keep uncertainty fail-closed once this classifier owns the request."""

        return bool(self.sensitive_paths) or self.script_requested or self.incomplete

    @property
    def identity_sha256(self) -> str:
        """Bind approvals to both discovered paths and inspected source bytes."""

        payload = (self.sensitive_paths, self.script_sources, self.script_requested, self.incomplete)
        return hashlib.sha256(json.dumps(payload, separators=(",", ":")).encode()).hexdigest()


def _python_executable(name: str) -> bool:
    return _PYTHON_EXECUTABLE.fullmatch(name) is not None


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
            return None, True
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


def _python_module_launch(executable: str, args: tuple[str, ...]) -> bool:
    """Return True when Python can import mutable workspace code via -m."""

    name = Path(executable or "").name.lower()
    if not _python_executable(name):
        return False
    for arg in args:
        if arg == "--":
            return False
        if arg == "-m":
            return True
        if not arg.startswith("-"):
            return False
    return False


def _interpreter_inline_launch(executable: str, args: tuple[str, ...]) -> bool:
    """Return True for literal inline-code modes whose file reads were already scanned."""

    name = Path(executable or "").name.lower()
    if name not in {"node", "bun", "ruby", "perl"} and not _python_executable(name):
        return False
    for arg in args:
        if arg == "--":
            return False
        if arg in {"-", "-c", "-e", "--eval", "-p", "--print"} or arg.startswith(("--eval=", "--print=")):
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


def assess_shell_reads(
    command_text: str,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> ShellReadAssessment:
    """Assess direct and script-mediated reads without executing inspected code."""

    from .secret_file_request_services.credential_exfiltration import _read_small_runtime_text_file
    from .secret_file_request_services.sensitive_read_pipeline import _resolved_runtime_path, _runtime_read_roots

    roots = _runtime_read_roots(cwd, home_dir)
    pending = [(command_text, cwd, 0)]
    sensitive: list[str] = []
    sources: list[tuple[str, str]] = []
    visited: set[str] = set()
    requested = False
    incomplete = False
    total_bytes = 0
    while pending:
        text, current_cwd, depth = pending.pop()
        # A literal delay cannot change cwd or introduce a file read. Inspect
        # its conditional successor conservatively without inventing a cwd
        # failure for the delay itself.
        delay = re.match(r"^\s*sleep\s+([1-9]\d{0,3})\s*&&\s*", text)
        if delay is not None and int(delay.group(1)) <= 3600:
            text = text[delay.end() :]
        context = model_shell_execution_context(
            text,
            cwd=current_cwd,
            workspace_root=cwd,
            home_dir=home_dir,
        )
        if not context.segments:
            if any(marker in text for marker in (".env", "credentials", ".npmrc", ".pypirc", ".netrc")):
                incomplete = True
            continue
        if context.reason_code == SHELL_CWD_WORKSPACE_ESCAPE and home_dir is not None:
            # Inspection may follow a proven directory inside the same home
            # even when execution policy has a narrower workspace boundary.
            alternate = model_shell_execution_context(
                text, cwd=current_cwd or home_dir, workspace_root=home_dir, home_dir=home_dir
            )
            first = alternate.segments[0] if alternate.segments else None
            literal_cd = (
                first is not None
                and first.directory_operation == "cd"
                and not first.control_before
                and len(first.tokens) == 2
                and (Path(first.tokens[1]).is_absolute() or first.tokens[1].startswith("~/"))
            )
            if alternate.complete and (current_cwd is not None or literal_cd):
                context = alternate
            elif current_cwd is None:
                from .secret_file_request_services.source_edit_context import (
                    low_risk_compound_developer_execution_context,
                )

                proven = low_risk_compound_developer_execution_context(text, home_dir=home_dir)
                if proven is not None and proven.complete:
                    context = proven
        raw_model = parse_shell_command(text, cwd=current_cwd, home_dir=home_dir, normalize_wrappers=False)
        raw_segments = tuple(segment for segment in raw_model.segments if segment.execution_context.startswith("top:"))
        aligned = len(raw_segments) == len(context.segments)
        heredocs = extract_heredocs(raw_model.normalized_text)
        failed_cd_short_circuit = False
        for index, execution in enumerate(context.segments):
            failed_cd_short_circuit, unreachable = _failed_cd_short_circuit_state(
                execution,
                active=failed_cd_short_circuit,
            )
            if unreachable:
                continue
            raw_segment = raw_segments[index] if aligned else None
            if (
                index == 0
                and raw_segment is not None
                and raw_segment.executable in {"source", "."}
                and not execution.control_before
                and context.reason_code == SHELL_CWD_UNRESOLVED_PARENT_SHELL
                and context.initial_cwd is not None
            ):
                # A first source invocation reads its operand before sourced
                # code can change the caller's cwd. Later segments stay closed.
                execution = replace(execution, effective_cwd=context.initial_cwd, complete=True, reason_code=None)
            model = _parse_execution_segment(execution, raw_model=raw_model, raw_segment=raw_segment)
            owned_substitutions = tuple(
                embedded
                for embedded in raw_model.embedded_commands
                if embedded.kind == "substitution"
                and raw_segment is not None
                and (
                    raw_segment.start <= embedded.start < raw_segment.end
                    or any(
                        raw_segment.start <= item.operator_start < raw_segment.end
                        and item.body_start <= embedded.start < item.end
                        for item in heredocs
                    )
                )
            )
            if model is None:
                if _segment_may_touch_local_data(execution) or owned_substitutions:
                    requested = True
                    incomplete = True
                continue
            effective_cwd = execution.effective_cwd
            for substitution in owned_substitutions:
                if depth >= _MAX_DEPTH or len(substitution.text.encode("utf-8")) > _MAX_INLINE_SCRIPT_BYTES:
                    requested = True
                    incomplete = True
                else:
                    pending.append((substitution.text, effective_cwd, depth + 1))
            sensitive.extend(direct_secret_read_paths(model, cwd=effective_cwd, home_dir=home_dir))
            if len(model.segments) > 1:
                # Embedded commands are included by the command parser but do
                # not have independently proven cwd contexts here.
                requested = True
                incomplete = True
            primary = model.segments[0] if model.segments else None
            if primary is None:
                continue
            executable, arguments, unwrap_incomplete = _unwrap_execution_builtin(
                primary.executable or "",
                primary.arguments,
            )
            if unwrap_incomplete:
                requested = True
                incomplete = True
                continue
            if executable is None:
                continue
            name = "." if executable == "." else Path(executable).name.lower()
            owned_heredocs = tuple(item for item in heredocs if primary.start <= item.operator_start < primary.end)
            for heredoc in owned_heredocs:
                if name in _SHELLS:
                    requested = True
                    if depth >= _MAX_DEPTH or len(heredoc.body.encode("utf-8")) > _MAX_INLINE_SCRIPT_BYTES:
                        incomplete = True
                    else:
                        pending.append((heredoc.body, effective_cwd, depth + 1))
                elif name in {"node", "bun", "ruby", "perl"} or _python_executable(name):
                    sensitive.extend(
                        path
                        for literal in _literal_read_paths(heredoc.body)
                        if (path := _sensitive_path(literal, cwd=effective_cwd, home_dir=home_dir)) is not None
                    )
            payload, command_string_requested = _shell_command_string(executable, arguments)
            if command_string_requested:
                requested = True
                if payload is None or len(payload.encode("utf-8")) > _MAX_INLINE_SCRIPT_BYTES or depth >= _MAX_DEPTH:
                    incomplete = True
                else:
                    pending.append((payload, effective_cwd, depth + 1))
            if _python_module_launch(executable, arguments):
                requested = True
                incomplete = True
                continue
            if _interpreter_inline_launch(executable, arguments):
                continue
            invocation = _script_operand(executable, arguments)
            if (
                name in _SHELLS
                and executable == name
                and len(arguments) == 2
                and arguments[0] == "-n"
                and invocation is not None
            ):
                # Syntax checking reads this file but does not execute its body.
                direct = _sensitive_path(invocation[0], cwd=effective_cwd, home_dir=home_dir)
                if direct is not None:
                    sensitive.append(direct)
                continue
            if invocation is None:
                if owned_heredocs and (
                    name in _SHELLS or name in {"node", "bun", "ruby", "perl"} or _python_executable(name)
                ):
                    continue
                local_executable = _local_executable_operand(
                    executable,
                    cwd=effective_cwd,
                    home_dir=home_dir,
                    roots=roots,
                )
                if local_executable is None:
                    if _path_qualified(executable):
                        requested = True
                        incomplete = True
                    continue
                invocation = (local_executable, False)
            requested = True
            operand, is_shell = invocation
            direct = _sensitive_path(operand, cwd=effective_cwd, home_dir=home_dir)
            if direct is not None:
                sensitive.append(direct)
                continue
            literal_source = len(model.segments) == 1 and executable in {"source", "."} and effective_cwd is not None
            if (not context.complete and not literal_source) or depth >= _MAX_DEPTH or len(visited) >= _MAX_SCRIPTS:
                incomplete = True
                continue
            source = _resolved_runtime_path(
                operand,
                cwd=effective_cwd,
                home_dir=home_dir,
                allowed_roots=roots,
            )
            if source is None:
                incomplete = True
                continue
            lexical_source = Path(normalize_path(expand_home(operand, home_dir), effective_cwd))
            if source != lexical_source:
                incomplete = True
                continue
            source_name = str(source)
            if source_name in visited:
                incomplete = True
                continue
            visited.add(source_name)
            payload = _read_small_runtime_text_file(source, allowed_roots=roots)
            if payload is None:
                incomplete = True
                continue
            encoded = payload.encode("utf-8")
            total_bytes += len(encoded)
            if total_bytes > _MAX_TOTAL_BYTES:
                incomplete = True
                continue
            sources.append((source_name, hashlib.sha256(encoded).hexdigest()))
            if is_shell:
                pending.append((payload, effective_cwd, depth + 1))
            else:
                sensitive.extend(
                    path
                    for literal in _literal_read_paths(payload)
                    if (path := _sensitive_path(literal, cwd=effective_cwd, home_dir=home_dir)) is not None
                )
    return ShellReadAssessment(tuple(dict.fromkeys(sensitive)), tuple(sources), requested, incomplete)


__all__ = ("ShellReadAssessment", "assess_shell_reads", "direct_secret_read_paths")
