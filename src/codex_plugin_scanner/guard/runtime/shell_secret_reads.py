"""Bounded, non-executing evidence for shell reads and local script launches.

A script without detected secret references is not a proof of safety. Imports,
computed paths and subprocesses can still access local data, so script launches
retain an execution floor. Inspection can only raise or explain that floor.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from .command_model import CanonicalCommand, parse_shell_command
from .secret_sensitivity import classify_secret_path
from .shell_execution_context import model_shell_execution_context

_SHELLS = frozenset({"sh", "bash", "dash", "zsh", "ksh", "fish", "source", "."})
_SCRIPT_SUFFIXES = (".sh", ".bash", ".zsh", ".ksh", ".fish", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl")
_OTHER_READERS = frozenset({"base64", "xxd", "od", "hexdump", "strings", "tac", "less", "more", "sort", "uniq", "wc"})
_MAX_SCRIPTS = 16
_MAX_DEPTH = 4
_MAX_TOTAL_BYTES = 128 * 1024
_LITERAL_READ = re.compile(
    r"(?:\bopen|\breadFile(?:Sync)?|\bcreateReadStream|\bPath|\bBun\.file|\bload_dotenv)"
    r"\s*\(\s*(['\"])([^'\"\n\x00]{1,4096})\1"
)


@dataclass(frozen=True, slots=True)
class ShellReadAssessment:
    sensitive_paths: tuple[str, ...]
    script_sources: tuple[tuple[str, str], ...]
    script_requested: bool
    incomplete: bool

    @property
    def requires_review(self) -> bool:
        return bool(self.sensitive_paths) or self.script_requested

    @property
    def identity_sha256(self) -> str:
        payload = (self.sensitive_paths, self.script_sources, self.script_requested, self.incomplete)
        return hashlib.sha256(json.dumps(payload, separators=(",", ":")).encode()).hexdigest()


def _sensitive_path(value: str, *, cwd: Path | None, home_dir: Path | None) -> str | None:
    match = classify_secret_path(value, cwd=cwd, home_dir=home_dir)
    return match.path if match is not None else None


def direct_secret_read_paths(
    command: CanonicalCommand, *, cwd: Path | None, home_dir: Path | None
) -> tuple[str, ...]:
    # A grep pattern or a test filename containing "secret" is not a file read.
    from .secret_file_request_services.local_read_operands import _shell_segment_file_operand_tokens

    candidates: list[str] = []
    for segment in command.segments:
        name = Path(segment.executable or "").name.lower()
        args = list(segment.arguments)
        candidates.extend(_shell_segment_file_operand_tokens([name, *args]))
        if name in _OTHER_READERS:
            candidates.extend(arg for arg in args if not arg.startswith("-"))
        if name in {"source", "."}:
            candidates.extend(args[:1])
        if name in {"python", "python3", "node", "bun", "ruby", "perl"}:
            for index, arg in enumerate(args[:-1]):
                if arg in {"-c", "-e", "--eval", "-p", "--print"}:
                    candidates.extend(match.group(2) for match in _LITERAL_READ.finditer(args[index + 1]))
    for redirect in command.redirects:
        if redirect.operator in {"<", "<>"}:
            candidates.append(redirect.target)
    return tuple(dict.fromkeys(
        path for value in candidates
        if (path := _sensitive_path(value, cwd=cwd, home_dir=home_dir)) is not None
    ))


def _script_operand(executable: str, args: tuple[str, ...]) -> tuple[str, bool] | None:
    name = Path(executable).name.lower()
    is_shell = name in _SHELLS
    is_interpreter = name in {"python", "python3", "node", "ruby", "perl"} or bool(re.fullmatch(r"python3\.\d+", name))
    if is_shell or is_interpreter:
        index = 0
        while index < len(args):
            arg = args[index]
            if arg in {"-c", "-e", "--eval", "-m", "-s", "--command"} or (
                is_shell and arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:]
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


def assess_shell_reads(
    command_text: str, *, cwd: Path | None = None, home_dir: Path | None = None
) -> ShellReadAssessment:
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
        model = parse_shell_command(text, cwd=current_cwd, home_dir=home_dir)
        sensitive.extend(direct_secret_read_paths(model, cwd=current_cwd, home_dir=home_dir))
        context = model_shell_execution_context(text, cwd=current_cwd, workspace_root=cwd, home_dir=home_dir)
        contexts = iter(context.segments)
        for segment in model.segments:
            execution = next(contexts, None)
            effective_cwd = execution.effective_cwd if execution is not None else current_cwd
            invocation = _script_operand(segment.executable or "", segment.arguments)
            if invocation is None:
                continue
            requested = True
            operand, is_shell = invocation
            direct = _sensitive_path(operand, cwd=effective_cwd, home_dir=home_dir)
            if direct is not None:
                sensitive.append(direct)
                continue  # Never read the secret itself to classify the command.
            if not context.complete or depth >= _MAX_DEPTH or len(visited) >= _MAX_SCRIPTS:
                incomplete = True
                continue
            source = _resolved_runtime_path(operand, cwd=effective_cwd, home_dir=home_dir, allowed_roots=roots)
            if source is None:
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
                # A script inherits the caller's cwd, not its own directory.
                pending.append((payload, effective_cwd, depth + 1))
            else:
                sensitive.extend(
                    path for match in _LITERAL_READ.finditer(payload)
                    if (path := _sensitive_path(match.group(2), cwd=effective_cwd, home_dir=home_dir)) is not None
                )
    return ShellReadAssessment(tuple(dict.fromkeys(sensitive)), tuple(sources), requested, incomplete)


__all__ = ("ShellReadAssessment", "assess_shell_reads", "direct_secret_read_paths")
