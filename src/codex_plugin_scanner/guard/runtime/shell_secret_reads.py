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
    SHELL_CWD_UNRESOLVED_PARENT_SHELL,
    SHELL_CWD_WORKSPACE_ESCAPE,
)
from ._shell_secret_read_support import (
    _MAX_DEPTH,
    _MAX_INLINE_SCRIPT_BYTES,
    _MAX_SCRIPTS,
    _MAX_TOTAL_BYTES,
    _SHELLS,
    _command_may_need_read_assessment,
    _direct_secret_read_paths_from_tokens,
    _failed_cd_short_circuit_state,
    _flow_operator_before,
    _interpreter_inline_launch,
    _interpreter_stdin_launch,
    _known_python_module_launch,
    _literal_read_paths,
    _local_executable_operand,
    _parse_execution_segment,
    _path_qualified,
    _python_executable,
    _python_module_launch,
    _script_operand,
    _segment_may_touch_local_data,
    _sensitive_path,
    _shell_command_string,
    _unwrap_execution_builtin,
    direct_secret_read_paths,
)
from .command_model import parse_shell_command
from .data_flow import extract_heredocs
from .home_path_text import expand_home, normalize_path
from .shell_execution_context import model_shell_execution_context


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


def assess_shell_reads(
    command_text: str,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> ShellReadAssessment:
    """Assess direct and script-mediated reads without executing inspected code."""

    if not _command_may_need_read_assessment(command_text):
        return ShellReadAssessment((), (), False, False)

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
                sensitive.extend(
                    _direct_secret_read_paths_from_tokens(
                        execution.tokens,
                        cwd=execution.effective_cwd,
                        home_dir=home_dir,
                    )
                )
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
            shell_stdin_mode = name in _SHELLS and "-s" in arguments
            input_redirect = any(redirect.operator.lstrip("0123456789") in {"<", "<>"} for redirect in model.redirects)
            if shell_stdin_mode and (_flow_operator_before(execution) == "|" or input_redirect):
                requested = True
                incomplete = True
            if command_string_requested:
                requested = True
                if payload is None or len(payload.encode("utf-8")) > _MAX_INLINE_SCRIPT_BYTES or depth >= _MAX_DEPTH:
                    incomplete = True
                else:
                    pending.append((payload, effective_cwd, depth + 1))
            if _python_module_launch(executable, arguments, cwd=effective_cwd):
                requested = True
                incomplete = True
                continue
            if _known_python_module_launch(executable, arguments, cwd=effective_cwd):
                continue
            if _interpreter_stdin_launch(executable, arguments):
                if not owned_heredocs:
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
