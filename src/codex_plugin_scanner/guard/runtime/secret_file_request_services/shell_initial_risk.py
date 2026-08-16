"""Early high-confidence shell risk classification."""

from __future__ import annotations

from pathlib import Path

from ..command_extension_interaction import CommandExtensionInteraction
from ..command_model import CanonicalCommand
from ..github_actions_read_workflow import is_nonexecuting_github_actions_read_workflow
from ..self_approval import SELF_APPROVAL_ACTION_CLASS, SELF_APPROVAL_REASON, is_guard_approval_mutation_command
from .destructive_shell_detection import _contains_shell_credential_exfiltration
from .github_pr_ephemeral_body import gh_pr_create_uses_safe_ephemeral_body
from .github_pr_expansion import (
    _gh_pr_create_body_has_shell_command_substitution,
    _gh_pr_create_has_active_shell_expansion,
    _gh_pr_edit_has_shell_command_substitution,
)
from .interpreter_trust import _contains_shell_network_file_upload
from .request_models import ToolActionRequestMatch
from .upload_arguments import _contains_encoded_or_encrypted_shell_command


def initial_shell_risk_match(
    *,
    tool_name: str,
    normalized_tool_name: str,
    command_text: str,
    detection_command_text: str,
    raw_command_text: str | None,
    cwd: Path | None,
    home_dir: Path | None,
    canonical_command: CanonicalCommand,
    extension_interaction: CommandExtensionInteraction,
    interpreter_executable_identities: tuple[dict[str, object], ...],
) -> tuple[bool, ToolActionRequestMatch | None]:
    match = _direct_shell_risk_match(
        tool_name=tool_name,
        normalized_tool_name=normalized_tool_name,
        command_text=command_text,
        detection_command_text=detection_command_text,
        cwd=cwd,
        home_dir=home_dir,
        canonical_command=canonical_command,
        interpreter_executable_identities=interpreter_executable_identities,
    )
    if match is not None:
        return True, match
    if extension_interaction.priority is not None:
        return True, ToolActionRequestMatch(
            tool_name=tool_name,
            normalized_tool_name=normalized_tool_name,
            command_text=command_text,
            action_class=extension_interaction.priority.action_class,
            reason=extension_interaction.priority.reason,
            canonical_command=canonical_command,
            interpreter_executable_identities=interpreter_executable_identities,
        )
    if gh_pr_create_uses_safe_ephemeral_body(detection_command_text) and (
        raw_command_text is None
        or raw_command_text == detection_command_text
        or gh_pr_create_uses_safe_ephemeral_body(raw_command_text)
    ):
        return True, None
    match = _github_shell_risk_match(
        tool_name=tool_name,
        normalized_tool_name=normalized_tool_name,
        command_text=command_text,
        detection_command_text=detection_command_text,
        raw_command_text=raw_command_text,
        canonical_command=canonical_command,
        interpreter_executable_identities=interpreter_executable_identities,
    )
    if match is not None:
        return True, match
    if is_nonexecuting_github_actions_read_workflow(detection_command_text, cwd=cwd) and (
        raw_command_text is None
        or raw_command_text == detection_command_text
        or is_nonexecuting_github_actions_read_workflow(raw_command_text, cwd=cwd)
    ):
        return True, None
    return False, None


def _direct_shell_risk_match(
    *,
    tool_name: str,
    normalized_tool_name: str,
    command_text: str,
    detection_command_text: str,
    cwd: Path | None,
    home_dir: Path | None,
    canonical_command: CanonicalCommand,
    interpreter_executable_identities: tuple[dict[str, object], ...],
) -> ToolActionRequestMatch | None:
    if is_guard_approval_mutation_command(detection_command_text):
        return ToolActionRequestMatch(
            tool_name=tool_name,
            normalized_tool_name=normalized_tool_name,
            command_text=command_text,
            action_class=SELF_APPROVAL_ACTION_CLASS,
            reason=SELF_APPROVAL_REASON,
            canonical_command=canonical_command,
        )
    if _contains_encoded_or_encrypted_shell_command(detection_command_text, cwd=cwd, home_dir=home_dir):
        return ToolActionRequestMatch(
            tool_name=tool_name,
            normalized_tool_name=normalized_tool_name,
            command_text=command_text,
            action_class="encoded or encrypted shell command",
            reason=(
                "Guard treats encoded or encrypted decode-and-exec shell flows as sensitive and inspects bounded "
                "payloads in-process without executing them during evaluation."
            ),
            canonical_command=canonical_command,
            interpreter_executable_identities=interpreter_executable_identities,
        )
    if _contains_shell_credential_exfiltration(detection_command_text, cwd=cwd, home_dir=home_dir):
        return ToolActionRequestMatch(
            tool_name=tool_name,
            normalized_tool_name=normalized_tool_name,
            command_text=command_text,
            action_class="credential exfiltration shell command",
            reason=(
                "Guard treats shell scripts that combine credential-looking material with outbound HTTP posting as "
                "sensitive because they can exfiltrate local secrets before the user confirms the action."
            ),
            canonical_command=canonical_command,
            interpreter_executable_identities=interpreter_executable_identities,
        )
    if _contains_shell_network_file_upload(detection_command_text, cwd=cwd, home_dir=home_dir):
        return ToolActionRequestMatch(
            tool_name=tool_name,
            normalized_tool_name=normalized_tool_name,
            command_text=command_text,
            action_class="shell file upload command",
            reason=(
                "Guard treats shell-driven local file uploads as sensitive because they can exfiltrate local file "
                "contents to a network endpoint before the user confirms the action."
            ),
            canonical_command=canonical_command,
            interpreter_executable_identities=interpreter_executable_identities,
        )
    return None


def _github_shell_risk_match(
    *,
    tool_name: str,
    normalized_tool_name: str,
    command_text: str,
    detection_command_text: str,
    raw_command_text: str | None,
    canonical_command: CanonicalCommand,
    interpreter_executable_identities: tuple[dict[str, object], ...],
) -> ToolActionRequestMatch | None:
    command_texts = (
        (detection_command_text,)
        if not raw_command_text or raw_command_text == detection_command_text
        else (detection_command_text, raw_command_text)
    )
    if any(_gh_pr_create_body_has_shell_command_substitution(text) for text in command_texts):
        action_class = "GitHub PR body shell substitution"
        reason = (
            "Guard treats command substitution inside `gh pr create --body` as sensitive because shell backticks "
            "or `$()` run before GitHub receives the PR text. Use single quotes around Markdown code spans or "
            "`--body-file` for PR descriptions."
        )
    elif any(_gh_pr_edit_has_shell_command_substitution(text) for text in command_texts):
        action_class = "GitHub PR edit shell substitution"
        reason = (
            "Guard reviews shell substitution around `gh pr edit` because it can execute local commands before "
            "GitHub receives the pull-request metadata."
        )
    elif any(_gh_pr_create_has_active_shell_expansion(text) for text in command_texts):
        action_class = "GitHub PR dynamic content"
        reason = (
            "Guard reviews `gh pr create` arguments with active shell expansion because environment variables "
            "or command substitutions can publish local secrets as pull-request metadata. Quote literal `$` "
            "and backticks with single quotes to keep static PR creation prompt-free."
        )
    else:
        return None
    return ToolActionRequestMatch(
        tool_name=tool_name,
        normalized_tool_name=normalized_tool_name,
        command_text=command_text,
        action_class=action_class,
        reason=reason,
        canonical_command=canonical_command,
        interpreter_executable_identities=interpreter_executable_identities,
    )


__all__ = ["initial_shell_risk_match"]
