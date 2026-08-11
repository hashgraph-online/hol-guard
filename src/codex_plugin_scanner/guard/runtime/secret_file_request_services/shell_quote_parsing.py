"""Shell quote, expansion, and working-directory parsing."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from ..direct_vitest import _trusted_path_command
from ..env_wrapper import parse_env_wrapper
from ..local_package_script_evidence import build_local_package_script_evidence
from ..shell_execution_context import ShellExecutionContext, model_shell_execution_context
from .constants_core import _GH_PR_OPTION_VALUE_FLAGS
from .developer_inspection import _static_shell_segment_is_safe
from .docker_requests import _shell_execution_context_validation_reason, shell_execution_context_starts_with_literal_cd
from .github_shell_capabilities import _shell_command_substitution_payloads, _shell_segment_env_index
from .shell_quote_tokens import (
    ShellTokenWithQuoteContext as _ShellTokenWithQuoteContext,
)
from .shell_quote_tokens import (
    plain_shell_token as _plain_shell_token,
)
from .shell_quote_tokens import (
    shell_token_segments as _shell_token_segments,
)
from .shell_quote_tokens import (
    shell_tokens_preserving_quote_context as _shell_tokens_preserving_quote_context,
)
from .shell_static_safety import (
    _leading_literal_cd_workspace_root,
    _shell_token_escapes_root,
    _shell_token_has_command_substitution,
    _without_safe_inspection_redirections,
)
from .shell_tokenization import _shell_segment_primary_command, _wrapper_option_tokens_consumed
from .source_edit_context import _bounded_edit_workspace_is_safe, _bounded_in_place_sed_target


def _bounded_current_workspace_source_edit_execution_context(
    command_text: str,
    *,
    cwd: Path | None,
    home_dir: Path,
) -> ShellExecutionContext | None:
    """Recognize a literal in-place substitution in the active workspace."""

    if cwd is None or any(marker in command_text for marker in ("$(", "`", "<(", ">(")):
        return None
    try:
        workspace_root = cwd.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    if workspace_root == home_dir.resolve() or not _bounded_edit_workspace_is_safe(
        workspace_root,
        home_dir=home_dir,
    ):
        return None
    modeled_command = command_text.replace("\\\r\n", " ").replace("\\\n", " ")
    context = model_shell_execution_context(
        modeled_command,
        cwd=workspace_root,
        workspace_root=workspace_root,
        home_dir=home_dir,
    )
    if _shell_execution_context_validation_reason(context) is not None:
        return None
    if context.directory_change_present or len(context.segments) not in {1, 2}:
        return None

    edit = context.segments[0]
    edit_name, edit_index = _shell_segment_primary_command(list(edit.tokens))
    if edit_name != "sed" or edit_index is None or edit.control_before:
        return None
    edit_args = _without_safe_inspection_redirections(list(edit.tokens[edit_index + 1 :]))
    if edit_args is None:
        return None
    if (
        _bounded_in_place_sed_target(
            edit_args,
            cwd=workspace_root,
            workspace_root=workspace_root,
        )
        is None
    ):
        return None
    if len(context.segments) == 1:
        return replace(context, command_text=command_text)

    label = context.segments[1]
    label_name, label_index = _shell_segment_primary_command(list(label.tokens))
    if label_name != "echo" or label_index is None or label.control_before != ("&&",):
        return None
    label_args = _without_safe_inspection_redirections(list(label.tokens[label_index + 1 :]))
    if label_args is None or not _static_shell_segment_is_safe(label_args):
        return None
    return replace(context, command_text=command_text)


def literal_cd_execution_context(
    command_text: str,
    *,
    home_dir: Path,
) -> ShellExecutionContext | None:
    """Recover a deterministic execution root from one leading literal ``cd``."""

    context = model_shell_execution_context(
        command_text,
        cwd=home_dir,
        workspace_root=home_dir,
        home_dir=home_dir,
    )
    workspace_root = _leading_literal_cd_workspace_root(context, home_dir=home_dir)
    if workspace_root is not None and workspace_root != home_dir.resolve():
        context = model_shell_execution_context(
            command_text,
            cwd=workspace_root,
            workspace_root=workspace_root,
            home_dir=home_dir,
        )
    if not shell_execution_context_starts_with_literal_cd(context):
        return None
    if _shell_execution_context_validation_reason(context) is not None:
        return None
    if len(context.segments) not in {2, 3}:
        return context if _bounded_local_runner_chain_is_safe(context, home_dir=home_dir) else None
    runner = context.segments[1]
    command_name, command_index = _shell_segment_primary_command(list(runner.tokens))
    if command_name not in {"bunx", "npx"} or command_index is None:
        return context if _bounded_local_runner_chain_is_safe(context, home_dir=home_dir) else None
    args = _without_safe_inspection_redirections(list(runner.tokens[command_index + 1 :]))
    if args is None:
        return None
    while args and args[0] in {"--bun", "--no", "--no-install"}:
        args.pop(0)
    if not args or args[0] not in {"eslint", "jest", "tsc", "vitest"}:
        return None
    runner_name = args[0]
    if any(
        _runner_argument_escapes_root(
            arg,
            cwd=runner.effective_cwd or home_dir,
            root=context.workspace_root or home_dir,
        )
        for arg in args[1:]
    ):
        return None
    runner_cwd = runner.effective_cwd
    if runner_cwd is None:
        return None
    try:
        executable = (runner_cwd / "node_modules" / ".bin" / runner_name).resolve(strict=True)
        executable.relative_to((runner_cwd / "node_modules").resolve(strict=True))
    except (OSError, RuntimeError, ValueError):
        return None
    if len(context.segments) == 3:
        output_filter = context.segments[2]
        filter_name, filter_index = _shell_segment_primary_command(list(output_filter.tokens))
        if filter_name not in {"head", "tail"} or filter_index is None:
            return None
        filter_args = list(output_filter.tokens[filter_index + 1 :])
        if output_filter.control_before != ("|",) or len(filter_args) != 1:
            return None
        count = filter_args[0]
        if not count.startswith("-") or not count[1:].isdigit() or not 1 <= int(count[1:]) <= 1000:
            return None
    return context


def _bounded_local_runner_chain_is_safe(context: ShellExecutionContext, *, home_dir: Path) -> bool:
    """Compose verified local checks, bounded output filters, and static labels."""

    workspace = context.workspace_root
    if workspace is None or not context.segments:
        return False
    index = 1
    saw_runner = False
    bun_trusted: bool | None = None
    while index < len(context.segments):
        segment = context.segments[index]
        command_name, command_index = _shell_segment_primary_command(list(segment.tokens))
        if command_name is None or command_index is None or segment.control_before not in {("&&",), (";",), ("\n",)}:
            return False
        if command_index != 0:
            return False
        args = _without_safe_inspection_redirections(list(segment.tokens[command_index + 1 :]))
        if args is None:
            return False
        if command_name == "echo":
            if not _static_shell_segment_is_safe(args):
                return False
            index += 1
            continue
        if command_name == "bun":
            if len(args) != 2 or args[0] != "run":
                return False
            if bun_trusted is None:
                bun_trusted = _trusted_path_command("bun", cwd=workspace, home_dir=home_dir)
            script_key = tuple(args)
            evidence = build_local_package_script_evidence("bun", script_key, workspace=workspace)
            if not bun_trusted or evidence is None or evidence.status != "complete":
                return False
        else:
            return False
        saw_runner = True
        index += 1
        if index < len(context.segments) and context.segments[index].control_before == ("|",):
            output_filter = context.segments[index]
            filter_name, filter_index = _shell_segment_primary_command(list(output_filter.tokens))
            if (
                filter_name not in {"head", "tail"}
                or filter_index != 0
                or not _trusted_path_command(filter_name, cwd=workspace, home_dir=home_dir)
            ):
                return False
            filter_args = _without_safe_inspection_redirections(list(output_filter.tokens[filter_index + 1 :]))
            if filter_args is None or len(filter_args) != 1:
                return False
            count = filter_args[0]
            if not count.startswith("-") or not count[1:].isdigit() or not 1 <= int(count[1:]) <= 1000:
                return False
            index += 1
    return saw_runner


def _runner_argument_escapes_root(arg: str, *, cwd: Path, root: Path) -> bool:
    if _shell_token_has_command_substitution(arg) or "$" in arg or arg.startswith("~"):
        return True
    candidate = arg.partition("=")[2] if arg.startswith("-") and "=" in arg else arg
    if candidate.startswith("~") or "$" in candidate:
        return True
    return bool(candidate) and _shell_token_escapes_root(candidate, cwd=cwd, root=root)


def _gh_pr_env_split_string_payloads_with_substitution(segment: list[_ShellTokenWithQuoteContext]) -> tuple[str, ...]:
    env_index = _shell_segment_env_index([token.plain for token in segment])
    if env_index is None:
        return ()
    parsed = parse_env_wrapper([token.plain for token in segment[env_index + 1 :]])
    payloads: list[str] = []
    for expansion in parsed.split_expansions:
        source_index = env_index + 1 + expansion.source_index
        if source_index < len(segment) and _shell_command_substitution_payloads(segment[source_index].raw):
            payloads.append(expansion.payload.strip())
    return tuple(payload for payload in payloads if payload)


def _skip_gh_pr_options(segment: list[_ShellTokenWithQuoteContext], index: int) -> int:
    while index < len(segment):
        plain = segment[index].plain
        if plain == "--":
            return index + 1
        if plain in _GH_PR_OPTION_VALUE_FLAGS:
            index += 2
            continue
        if any(plain.startswith(f"{flag}=") for flag in _GH_PR_OPTION_VALUE_FLAGS):
            index += 1
            continue
        if plain.startswith("-R") and plain != "-R":
            index += 1
            continue
        if plain.startswith("-"):
            index += 1
            continue
        break
    return index


def _skip_generic_shell_wrapper_options(
    command_name: str,
    segment: list[_ShellTokenWithQuoteContext],
    index: int,
) -> int:
    while index < len(segment):
        plain = segment[index].plain
        if plain == "--":
            return index + 1
        if not plain.startswith("-"):
            break
        index += _wrapper_option_tokens_consumed(command_name, plain)
    return index


__all__ = [
    "_bounded_current_workspace_source_edit_execution_context",
    "_gh_pr_env_split_string_payloads_with_substitution",
    "_plain_shell_token",
    "_runner_argument_escapes_root",
    "_shell_token_segments",
    "_shell_tokens_preserving_quote_context",
    "_skip_generic_shell_wrapper_options",
    "_skip_gh_pr_options",
    "literal_cd_execution_context",
]
