"""Codex tool-output risk copy helpers."""

from __future__ import annotations


def _codex_tool_output_request_summary(
    *,
    tool_name: str,
    command_text: str,
    local_secret_source: str | None,
    merged_output_capture: bool = False,
    focused_pytest: bool = False,
) -> str:
    if local_secret_source is not None:
        return f"Codex tool `{tool_name}` read local secrets from {local_secret_source} while running `{command_text}`."
    if focused_pytest and merged_output_capture:
        return (
            f"Codex tool `{tool_name}` ran focused pytest, merged stderr into stdout while running "
            f"`{command_text}`, and the captured output looked credential-like."
        )
    if focused_pytest:
        return (
            f"Codex tool `{tool_name}` ran focused pytest and produced credential-looking output while "
            f"running `{command_text}`."
        )
    if merged_output_capture:
        return (
            f"Codex tool `{tool_name}` merged stderr into stdout while running `{command_text}`, "
            "and the captured output looked credential-like."
        )
    return f"Codex tool `{tool_name}` produced credential-looking output while running `{command_text}`."


def _codex_tool_output_runtime_summary(
    local_secret_source: str | None,
    *,
    merged_output_capture: bool = False,
    focused_pytest: bool = False,
) -> str:
    if local_secret_source is not None:
        return f"Local secrets from {local_secret_source} reached Codex tool output."
    if focused_pytest and merged_output_capture:
        return (
            "Focused pytest merged stderr into stdout and emitted credential-looking output before it reached "
            "Codex. Pytest can execute repository-controlled code, so this could be a real local secret."
        )
    if focused_pytest:
        return (
            "Focused pytest emitted credential-looking output before it reached Codex. "
            "Pytest can execute repository-controlled code, so this could be a real local secret."
        )
    if merged_output_capture:
        return "Combined stdout/stderr looked credential-like before it reached Codex."
    return "Requests a sensitive native tool action: credential-looking output reached Codex."


def _codex_tool_output_runtime_reason(
    local_secret_source: str | None,
    *,
    merged_output_capture: bool = False,
    focused_pytest: bool = False,
) -> str:
    if local_secret_source is not None:
        return (
            "Guard inspects supported Codex tool output before Codex uses it, so accidental secret reads can be "
            "stopped even when the filename was not obviously sensitive."
        )
    if focused_pytest and merged_output_capture:
        return (
            "Guard stopped this pytest output because pytest executes repository-controlled code, and merging stderr "
            "into stdout can forward real local secrets to Codex. If you only need the exit status, rerun without "
            "`2>&1` or keep stderr out of model-visible output."
        )
    if focused_pytest:
        return (
            "Guard stopped this pytest output because pytest executes repository-controlled code. "
            "Credential-looking output could be a real local secret printed by the test, not just fixture text."
        )
    if merged_output_capture:
        return (
            "Guard stopped this command shape because merging stderr into stdout can send credential-looking failure "
            "output to Codex. If you only need the exit status, rerun without `2>&1` or keep stderr out of the "
            "model-visible output."
        )
    return (
        "Guard inspects supported Codex tool output before Codex uses it, so accidental secret reads can be stopped "
        "even when the filename was not obviously sensitive."
    )


__all__ = [
    "_codex_tool_output_request_summary",
    "_codex_tool_output_runtime_reason",
    "_codex_tool_output_runtime_summary",
]
