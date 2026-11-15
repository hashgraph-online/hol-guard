"""Render ``hol-guard command test`` and ``command explain`` results.

An inspection the native runtime did not answer is shown as not evaluated, with
its reason code and recovery commands, so it cannot be read as "no match".
"""

from __future__ import annotations

from rich import box
from rich.console import Console, RenderableType
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

PayloadDict = dict[str, object]


def _coerce_object_dict(value: object) -> PayloadDict:
    if not isinstance(value, dict):
        return {}
    return {key: item for key, item in value.items() if isinstance(key, str)}


def _coerce_dict_list(value: object) -> list[PayloadDict]:
    if not isinstance(value, list):
        return []
    return [_coerce_object_dict(item) for item in value if isinstance(item, dict)]


def _coerce_string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str) and item]


def _print(console: Console, renderable: RenderableType) -> None:
    # The CLI console soft-wraps so long plain lines stay copyable, but a
    # soft-wrapped panel crops its text to one line. A native block reason or
    # a recovery step is several sentences, so these panels wrap.
    console.print(renderable, soft_wrap=False)


def render_command_inspection(console: Console, payload: dict[str, object]) -> None:
    from .render import _bullet as bullet

    status = str(payload.get("status") or "invalid")
    classification = _coerce_object_dict(payload.get("classification"))
    extensions = _coerce_dict_list(payload.get("extensions"))
    rules = _coerce_dict_list(payload.get("rules"))
    risk_classes = _coerce_string_list(payload.get("risk_classes"))
    unavailable = status == "native_unavailable"
    if unavailable:
        border_style = "red"
    elif status == "review":
        border_style = "yellow"
    else:
        border_style = "cyan"
    summary = Table.grid(padding=(0, 1))
    summary.add_row("Result", Text(_command_inspection_result_label(payload), style=f"bold {border_style}"))
    action_class = classification.get("action_class")
    summary.add_row("Action class", Text(str(action_class or _command_inspection_unmatched_label(payload))))
    if _shows_minimum_action(payload):
        summary.add_row(
            "Minimum action",
            Text(str(payload.get("minimum_action") or "review").upper(), style=f"bold {border_style}"),
        )
    if extensions:
        summary.add_row("Extension", Text(str(extensions[0].get("extension_id") or "unknown"), style="cyan"))
    if rules:
        summary.add_row("Rule", Text(str(rules[0].get("rule_id") or "unknown"), style="cyan"))
    if risk_classes:
        summary.add_row("Risk classes", Text(", ".join(risk_classes)))
    summary.add_row("Policy", Text("Not evaluated; this inspection creates no approvals or receipts", style="dim"))
    _print(console, Panel(summary, title="HOL Guard command inspection", border_style=border_style))
    _print(console, Panel(Syntax(str(payload.get("command") or ""), "bash", word_wrap=True), title="Command"))
    reason = classification.get("reason")
    if isinstance(reason, str) and reason:
        _print(console, Panel(Text(reason), title="Why", border_style=border_style))
    recovery = classification.get("recovery")
    if isinstance(recovery, str) and recovery:
        _print(console, Panel(Text(recovery), title="Next step", border_style=border_style))
    recovery_commands = _command_inspection_recovery_commands(payload)
    if recovery_commands:
        _print(console, Panel("\n".join(recovery_commands), title="Recovery commands", border_style=border_style))
    if extensions:
        alternatives = _coerce_string_list(extensions[0].get("safer_alternatives"))
        if alternatives:
            _print(console, Panel("\n".join(f"{bullet()} {item}" for item in alternatives), title="Safer approaches"))
    if str(payload.get("mode") or "") == "explain":
        trace = _coerce_dict_list(payload.get("trace"))
        trace_table = Table(title="Evaluation trace", box=box.SIMPLE_HEAD, show_lines=False)
        trace_table.add_column("Step", style="bold")
        trace_table.add_column("Result")
        trace_table.add_column("Detail")
        for item in trace:
            trace_table.add_row(
                str(item.get("step") or ""),
                str(item.get("result") or ""),
                str(item.get("detail") or ""),
            )
        _print(console, trace_table)


def _shows_minimum_action(payload: PayloadDict) -> bool:
    # A "review" result can still be a block; name it so the result line is
    # not read as an approval prompt.
    return payload.get("status") == "native_unavailable" or payload.get("minimum_action") == "block"


def _command_inspection_readiness(payload: PayloadDict) -> dict[str, object]:
    return _coerce_object_dict(payload.get("readiness"))


def _command_inspection_result_label(payload: PayloadDict) -> str:
    status = str(payload.get("status") or "invalid")
    if status != "native_unavailable":
        return status.upper()
    reason_code = str(_command_inspection_readiness(payload).get("reason_code") or "native_review_unavailable")
    # An inspection with no native answer is not a classification. Say so in the
    # result line itself so it cannot be read as a quiet "no match".
    return f"NOT EVALUATED ({reason_code})"


def _command_inspection_unmatched_label(payload: PayloadDict) -> str:
    status = str(payload.get("status") or "invalid")
    if status == "native_unavailable":
        return "Unknown: the native runtime did not answer, so nothing was classified"
    native = _coerce_object_dict(payload.get("native_decision"))
    reason_code = native.get("reason_code")
    if isinstance(reason_code, str) and reason_code:
        # The native runtime decided without an extension rule; name its
        # decision rather than saying nothing matched.
        return f"None; native decision {reason_code}"
    return "No sensitive action matched"


def _command_inspection_recovery_commands(payload: PayloadDict) -> list[str]:
    if str(payload.get("status") or "") != "native_unavailable":
        return []
    return _coerce_string_list(_command_inspection_readiness(payload).get("recovery_commands"))


def plain_text_command_inspection(payload: PayloadDict) -> str:
    classification = _coerce_object_dict(payload.get("classification"))
    extensions = _coerce_dict_list(payload.get("extensions"))
    rules = _coerce_dict_list(payload.get("rules"))
    action_class = classification.get("action_class") or _command_inspection_unmatched_label(payload)
    lines = [
        f"HOL Guard command inspection: {_command_inspection_result_label(payload)}",
        f"Command: {payload.get('command') or ''}",
        f"Action class: {action_class}",
        f"Reason: {classification.get('reason') or ''}",
        "Policy: Not evaluated; this inspection creates no approvals or receipts.",
    ]
    if _shows_minimum_action(payload):
        lines.insert(3, f"Minimum action: {str(payload.get('minimum_action') or 'review').upper()}")
    recovery = classification.get("recovery")
    if isinstance(recovery, str) and recovery:
        lines.append(f"Recovery: {recovery}")
    recovery_commands = _command_inspection_recovery_commands(payload)
    if recovery_commands:
        lines.append(f"Recovery commands: {'; '.join(recovery_commands)}")
    if extensions:
        lines.insert(3, f"Extension: {extensions[0].get('extension_id') or 'unknown'}")
    if rules:
        lines.insert(4, f"Rule: {rules[0].get('rule_id') or 'unknown'}")
    return "\n".join(lines)
