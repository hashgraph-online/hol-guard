"""Rich renderers for Guard CLI output."""

from __future__ import annotations

import json
import math
import re
import sys
import textwrap
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import TYPE_CHECKING, TextIO, TypeAlias

from ..redaction import redact_text
from .render_uninstall import render_self_uninstall

try:
    from ..redaction import redact_local_path
except ImportError:

    def _replace_home_prefix_fallback(value: str, home_value: str) -> str:
        home_prefix = home_value.rstrip("/\\")
        if not home_prefix or home_prefix in {"/", "\\"}:
            return value
        if value == home_prefix:
            return "~"
        if value.startswith(home_prefix) and len(value) > len(home_prefix) and value[len(home_prefix)] in {"/", "\\"}:
            return f"~{value[len(home_prefix) :]}"
        return value

    def redact_local_path(value: str, *, home_dir: Path | None = None) -> str:
        """Fallback for mixed installs where render.py is newer than redaction.py."""

        redacted_value = value
        if home_dir is not None:
            redacted_value = _replace_home_prefix_fallback(redacted_value, str(home_dir))
        try:
            current_home = Path.home()
        except RuntimeError:
            current_home = None
        if current_home is not None:
            redacted_value = _replace_home_prefix_fallback(redacted_value, str(current_home))
        redacted_value = re.sub(
            r"(?P<prefix>^|[\s\"'=({\[])(?P<root>/(?:Users|home)/[^/\s\"'`,;:)}\]]+)"
            r"(?P<rest>(?:/[^\s\"'`,;:)}\]]*)?)",
            r"\g<prefix>~\g<rest>",
            redacted_value,
        )
        return re.sub(
            r"(?P<prefix>^|[\s\"'=({\[])(?P<root>[A-Za-z]:[\\/]+Users[\\/]+[^\\/ \t\r\n\"'`,;:)}\]]+)"
            r"(?P<rest>(?:[\\/][^\\/ \t\r\n\"'`,;:)}\]]*)?)",
            r"\g<prefix>~\g<rest>",
            redacted_value,
        )


PayloadDict: TypeAlias = dict[str, object]
PayloadMapping: TypeAlias = Mapping[str, object]

_rich_available = False

if TYPE_CHECKING:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.table import Table
    from rich.text import Text

    _rich_available = True
else:
    try:
        from rich import box
        from rich.console import Console
        from rich.panel import Panel
        from rich.syntax import Syntax
        from rich.table import Table
        from rich.text import Text

        _rich_available = True
    except ModuleNotFoundError:

        class _FallbackBox:
            SIMPLE_HEAD = "simple_head"
            SIMPLE_HEAVY = "simple_heavy"

        class Console:
            def __init__(self, *, file: TextIO | None = None, soft_wrap: bool = False) -> None:
                self.file = sys.stdout if file is None else file
                self.soft_wrap = soft_wrap

            def print(self, *objects: object) -> None:
                self.file.write(" ".join(str(item) for item in objects))
                self.file.write("\n")

        class Panel:
            def __init__(
                self, renderable: object, *, title: str | None = None, border_style: str | None = None
            ) -> None:
                self.renderable = renderable
                self.title = title
                self.border_style = border_style

            @classmethod
            def fit(cls, renderable: object, *, title: str | None = None, border_style: str | None = None) -> Panel:
                return cls(renderable, title=title, border_style=border_style)

            def __str__(self) -> str:
                return str(self.renderable)

        class Syntax:
            def __init__(self, code: str, lexer: str, *, theme: str | None = None, word_wrap: bool = False) -> None:
                self.code = code
                self.lexer = lexer
                self.theme = theme
                self.word_wrap = word_wrap

            def __str__(self) -> str:
                return self.code

        class Table:
            def __init__(
                self,
                *,
                title: str | None = None,
                box: object | None = None,
                show_header: bool = False,
                show_lines: bool = False,
                expand: bool = False,
                padding: tuple[int, int] | None = None,
            ) -> None:
                self.title = title
                self.box = box
                self.show_header = show_header
                self.show_lines = show_lines
                self.expand = expand
                self.padding = padding
                self.columns: list[str] = []
                self.rows: list[tuple[object, ...]] = []

            @classmethod
            def grid(cls, *, padding: tuple[int, int] | None = None) -> Table:
                return cls(padding=padding)

            @property
            def row_count(self) -> int:
                return len(self.rows)

            def add_column(
                self,
                name: str,
                *,
                style: str | None = None,
                no_wrap: bool = False,
                justify: str | None = None,
                overflow: str | None = None,
            ) -> None:
                del style, no_wrap, justify, overflow
                self.columns.append(name)

            def add_row(self, *values: object) -> None:
                self.rows.append(values)

            def __str__(self) -> str:
                return "\n".join(" | ".join(str(value) for value in row) for row in self.rows)

        class Text:
            def __init__(
                self, text: str = "", *, style: str | None = None, overflow: str | None = None, no_wrap: bool = False
            ) -> None:
                self.text = text
                self.style = style
                self.overflow = overflow
                self.no_wrap = no_wrap

            def __str__(self) -> str:
                return self.text

        box = _FallbackBox()

_RICH_AVAILABLE = _rich_available

Renderer: TypeAlias = Callable[[Console, PayloadDict], None]
PlainTextRenderer: TypeAlias = Callable[[PayloadDict], str]


_MODE_ACRONYMS = frozenset({"mcp", "api", "cli"})
_SEVERITY_COLORS: dict[str, str] = {"critical": "red", "high": "yellow", "medium": "cyan", "low": "dim", "info": "dim"}
_KNOWN_MANAGED_INSTALL_MODES = {
    "codex-mcp-proxy": "Codex MCP proxy",
}
_SENSITIVE_KEY_TOKENS = ("key", "token", "auth", "secret", "password", "credential")
_NON_SECRET_STRUCTURED_KEYS = frozenset({"oauth_storage_health"})
_NON_SECRET_DIAGNOSTIC_KEYS = frozenset({"authority_error", "authority_error_message"})
_SAFE_POLICY_LITERALS = frozenset(
    {"allow", "warn", "review", "block", "require-reapproval", "sandbox-required", "strict", "balanced", "custom"}
)
_SENSITIVE_STRING_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        "*****",
    ),
    (re.compile(r"(?i)(authorization:\s*)(bearer\s+)?[^\s,;]+"), r"\1*****"),
    (re.compile(r"(?i)(api[-_ ]?key:\s*)[^\s,;]+"), r"\1*****"),
    (re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"), "*****"),
    (re.compile(r"(?i)(bearer\s+)[^\s,;]+"), r"\1*****"),
    (re.compile(r"(?im)\b(?:_authToken|npm[_ -]?token)\s*[:=]\s*[^\s]+"), "npm token redacted"),
    (re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s]+", re.IGNORECASE), "*****"),
    (
        re.compile(
            r"(?i)([a-z0-9_-]*(?:token|secret|api[-_]?key|password|credential)[a-z0-9_-]*=)(?:'[^']*'|\"[^\"]*\"|[^&\s]+)"
        ),
        r"\1*****",
    ),
)
_TRUST_SENSITIVE_STRING_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    item for item in _SENSITIVE_STRING_PATTERNS if item[0].pattern != r"(?i)(api[-_ ]?key:\s*)[^\s,;]+"
)


def emit_guard_payload(command: str, payload: PayloadDict, as_json: bool) -> None:
    """Render Guard payloads as JSON or human-friendly rich output."""

    if as_json:
        redacted_output = redact_text(_safe_json_output_text(command, payload))
        sys.stdout.write(redacted_output.text)
        sys.stdout.write("\n")
        return

    redacted_payload = _coerce_object_dict(_sanitize_payload_for_output(payload, command=command))
    if not _RICH_AVAILABLE:
        plain_renderer = _PLAIN_TEXT_RENDERERS.get(command)
        if plain_renderer is None:
            redacted_output = redact_text(_safe_json_output_text(command, payload))
            sys.stdout.write(redacted_output.text)
        else:
            sys.stdout.write(plain_renderer(redacted_payload))
        sys.stdout.write("\n")
        return

    console = Console(file=sys.stdout, soft_wrap=True)
    renderer = _RENDERERS.get(command, _render_fallback)
    renderer(console, redacted_payload)


def _redact_payload(value: object, *, key: str | None = None, command: str | None = None) -> object:
    if key in _NON_SECRET_STRUCTURED_KEYS and isinstance(value, dict):
        return {
            item_key: _redact_payload(item_value, key=item_key, command=command)
            for item_key, item_value in value.items()
        }
    if (
        key is not None
        and key not in _NON_SECRET_STRUCTURED_KEYS
        and key not in _NON_SECRET_DIAGNOSTIC_KEYS
        and any(token in key.lower() for token in _SENSITIVE_KEY_TOKENS)
    ):
        if isinstance(value, str) and value.lower() in _SAFE_POLICY_LITERALS:
            return value
        return "*****"
    if isinstance(value, dict):
        return {
            item_key: _redact_payload(item_value, key=item_key, command=command)
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [_redact_payload(item, command=command) for item in value]
    if isinstance(value, str):
        redacted = value
        patterns = (
            _TRUST_SENSITIVE_STRING_PATTERNS
            if isinstance(command, str) and command.startswith("trust.")
            else _SENSITIVE_STRING_PATTERNS
        )
        for pattern, replacement in patterns:
            redacted = pattern.sub(replacement, redacted)
        return redact_local_path(redacted)
    return value


def _render_redacted_json_payload(redacted_payload: object) -> str:
    if not isinstance(redacted_payload, dict):
        return "{}"
    return _serialize_redacted_json(redacted_payload, indent=0)


def _safe_json_output_text(command: str, payload: PayloadDict) -> str:
    json_payload = _json_payload_for_command(command, payload)
    sanitized_payload = _coerce_object_dict(_sanitize_payload_for_output(json_payload, command=command))
    return _render_redacted_json_payload(sanitized_payload)


def _plain_text_protect(payload: PayloadDict) -> str:
    if str(payload.get("mode") or "") == "status":
        lines = ["HOL Guard install protection is active."]
        supply_chain = payload.get("supply_chain")
        if isinstance(supply_chain, dict):
            status = str(supply_chain.get("status") or "").strip()
            detail = str(supply_chain.get("detail") or "").strip()
            if status:
                lines.append(f"Status: {status}")
            if detail:
                lines.append(detail)
        return "\n".join(lines)

    verdict = payload.get("verdict")
    verdict_map = _coerce_object_dict(verdict)
    action = str(verdict_map.get("action") or "review").strip() or "review"
    action_line = {
        "allow": "HOL Guard allowed this install.",
        "block": "HOL Guard blocked this install before it ran.",
        "review": "HOL Guard paused this install for review before it ran.",
        "require-reapproval": "HOL Guard paused this install for review before it ran.",
        "warn": "HOL Guard warned about this install.",
    }.get(action, f"HOL Guard decision: {action}.")
    lines = [action_line]

    request = payload.get("request")
    if isinstance(request, dict):
        command_text = _command_text(request.get("command")).strip()
        if command_text and command_text != "none":
            lines.append(f"Command: {command_text}")

    reason = str(verdict_map.get("reason") or "").strip()
    if reason:
        lines.append(f"Reason: {reason}")

    supply_chain_evaluation = payload.get("supply_chain_evaluation")
    user_copy = supply_chain_evaluation.get("user_copy") if isinstance(supply_chain_evaluation, dict) else None
    user_copy_map = _coerce_object_dict(user_copy)
    harness_message = str(user_copy_map.get("harness_message") or "").strip()
    if harness_message:
        lines.append(harness_message)

    next_step = str(user_copy_map.get("next_step") or "").strip()
    if next_step and next_step not in harness_message:
        lines.append(f"Next step: {next_step}")

    dashboard_url = str(user_copy_map.get("dashboard_url") or "").strip()
    if dashboard_url and dashboard_url not in harness_message:
        lines.append(f"Review: {dashboard_url}")

    return "\n".join(lines)


def _sanitize_payload_for_output(value: object, *, command: str | None = None) -> object:
    return _redact_payload(value, command=command)


def _json_payload_for_command(command: str, payload: PayloadDict) -> PayloadDict:
    json_renderer = _JSON_RENDERERS.get(command)
    if json_renderer is None:
        return dict(payload)
    return json_renderer(dict(payload))


def _render_settings_json_payload(redacted_payload: PayloadDict) -> PayloadDict:
    settings = redacted_payload.get("settings")
    safe_keys = (
        "mode",
        "security_level",
        "default_action",
        "unknown_publisher_action",
        "changed_hash_action",
        "new_network_domain_action",
        "subprocess_action",
        "risk_actions",
        "risk_action_overrides",
        "harness_risk_actions",
        "approval_wait_timeout_seconds",
        "approval_surface_policy",
        "telemetry",
        "sync",
    )
    safe_settings = {key: settings[key] for key in safe_keys if isinstance(settings, dict) and key in settings}
    return {
        "generated_at": redacted_payload.get("generated_at"),
        "guard_home": redacted_payload.get("guard_home"),
        "config_path": redacted_payload.get("config_path"),
        "settings": safe_settings,
    }


def _serialize_redacted_json(value: object, *, indent: int) -> str:
    if isinstance(value, dict):
        if not value:
            return "{}"
        child_indent = indent + 2
        entries = [
            (
                f"{' ' * child_indent}{json.dumps(str(item_key))}: "
                f"{_serialize_redacted_json(item_value, indent=child_indent)}"
            )
            for item_key, item_value in value.items()
        ]
        return "{\n" + ",\n".join(entries) + "\n" + (" " * indent) + "}"
    if isinstance(value, list):
        if not value:
            return "[]"
        child_indent = indent + 2
        items = [f"{' ' * child_indent}{_serialize_redacted_json(item, indent=child_indent)}" for item in value]
        return "[\n" + ",\n".join(items) + "\n" + (" " * indent) + "]"
    try:
        return json.dumps(value)
    except TypeError:
        return json.dumps(str(value))


_JSON_RENDERERS: dict[str, Callable[[PayloadDict], PayloadDict]] = {
    "settings": _render_settings_json_payload,
}


def _render_detect(console: Console, payload: dict[str, object]) -> None:
    detections = _coerce_dict_list(payload.get("harnesses"))
    total_artifacts = sum(len(_coerce_dict_list(item.get("artifacts"))) for item in detections)
    attention_count = sum(1 for item in detections if _status_label(item) != "Ready" or _warning_count(item) > 0)
    console.print(
        Panel.fit(
            f"[bold]HOL Guard local harness status[/bold]\n"
            f"{len(detections)} harnesses • {total_artifacts} artifacts • {attention_count} need attention",
            border_style="cyan",
        )
    )
    console.print(_build_harness_table(detections))
    for detection in detections:
        _render_harness_detail(console, detection)
    if attention_count > 0:
        console.print(
            "[yellow]Run `hol-guard doctor <harness>` for harness-specific drift and runtime diagnostics.[/yellow]"
        )


def _render_start(console: Console, payload: dict[str, object]) -> None:
    harnesses = _coerce_dict_list(payload.get("harnesses"))
    console.print(
        Panel.fit(
            f"[bold]HOL Guard first run[/bold]\n"
            f"{len(harnesses)} harnesses detected • {payload.get('receipt_count', 0)} receipts recorded • "
            f"{payload.get('pending_approvals', 0)} approvals waiting",
            border_style="cyan",
        )
    )
    console.print(_build_cloud_summary_panel(payload))
    console.print(_build_product_table(harnesses))
    if payload.get("approval_center_url"):
        console.print(f"Approval center: [bold]{payload.get('approval_center_url')}[/bold]")
    console.print(_build_steps_panel(_coerce_dict_list(payload.get("next_steps"))))


def _render_init(console: Console, payload: dict[str, object]) -> None:
    plan = _coerce_dict_list(payload.get("plan"))
    if plan:
        console.print(_init_plan_panel(plan, str(payload.get("status") or "initialized")))
    dashboard = payload.get("dashboard")
    apps = payload.get("apps")
    cloud = payload.get("cloud")
    notifications = payload.get("desktop_notifications")
    dashboard_payload = _coerce_object_dict(dashboard)
    apps_payload = _coerce_object_dict(apps)
    cloud_payload = _coerce_object_dict(cloud)
    notification_payload = _coerce_object_dict(notifications)
    managed_installs = _coerce_dict_list(apps_payload.get("managed_installs"))
    summary = Table.grid(padding=(0, 1))
    summary.add_row("Dashboard", _init_dashboard_summary(dashboard_payload))
    summary.add_row("Apps", _init_apps_summary(apps_payload, len(managed_installs)))
    summary.add_row("Cloud", _init_cloud_summary(cloud_payload))
    summary.add_row("Notifications", _init_notification_summary(notification_payload))
    status = str(payload.get("status") or "initialized")
    title = _init_panel_title(status)
    border_style = "red" if status == "needs_attention" else "cyan"
    console.print(Panel(summary, title=title, border_style=border_style))
    if managed_installs:
        console.print(_managed_install_batch_table(managed_installs))
    guidance = notification_payload.get("guidance")
    if isinstance(guidance, str) and guidance:
        console.print(Panel(guidance, title="Notification setup", border_style="blue"))
    console.print(_build_steps_panel(_coerce_dict_list(payload.get("next_steps"))))


def _render_command_inspection(console: Console, payload: dict[str, object]) -> None:
    status = str(payload.get("status") or "invalid")
    classification = _coerce_object_dict(payload.get("classification"))
    extensions = _coerce_dict_list(payload.get("extensions"))
    rules = _coerce_dict_list(payload.get("rules"))
    risk_classes = _coerce_string_list(payload.get("risk_classes"))
    border_style = "yellow" if status == "review" else "cyan"
    summary = Table.grid(padding=(0, 1))
    summary.add_row("Result", Text(status.upper(), style=f"bold {border_style}"))
    action_class = classification.get("action_class")
    summary.add_row("Action class", Text(str(action_class or "No sensitive action matched")))
    if extensions:
        summary.add_row("Extension", Text(str(extensions[0].get("extension_id") or "unknown"), style="cyan"))
    if rules:
        summary.add_row("Rule", Text(str(rules[0].get("rule_id") or "unknown"), style="cyan"))
    if risk_classes:
        summary.add_row("Risk classes", Text(", ".join(risk_classes)))
    summary.add_row("Policy", Text("Not evaluated; this inspection creates no approvals or receipts", style="dim"))
    console.print(Panel(summary, title="HOL Guard command inspection", border_style=border_style))
    console.print(Panel(Syntax(str(payload.get("command") or ""), "bash", word_wrap=True), title="Command"))
    reason = classification.get("reason")
    if isinstance(reason, str) and reason:
        console.print(Panel(Text(reason), title="Why", border_style=border_style))
    if extensions:
        alternatives = _coerce_string_list(extensions[0].get("safer_alternatives"))
        if alternatives:
            console.print(Panel("\n".join(f"• {item}" for item in alternatives), title="Safer approaches"))
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
        console.print(trace_table)


def _render_command_extensions(console: Console, payload: dict[str, object]) -> None:
    extensions = _coerce_dict_list(payload.get("extensions"))
    table = Table(title="Built-in command safety extensions", box=box.SIMPLE_HEAD, show_lines=False)
    table.add_column("Extension", style="bold cyan", no_wrap=True)
    table.add_column("Version", no_wrap=True)
    table.add_column("Coverage")
    table.add_column("Rules")
    table.add_column("Purpose")
    for extension in extensions:
        table.add_row(
            str(extension.get("extension_id") or ""),
            str(extension.get("version") or ""),
            str(len(_coerce_string_list(extension.get("action_classes")))),
            str(extension.get("rule_count") or 0),
            str(extension.get("description") or ""),
        )
    console.print(table)


def _render_command_setup(console: Console, payload: dict[str, object]) -> None:
    detections = _coerce_dict_list(payload.get("detections"))
    table = Table(title="Command ecosystem setup", box=box.SIMPLE_HEAD, show_lines=False)
    table.add_column("Ecosystem", style="bold cyan", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Detected from")
    table.add_column("Protection")
    for detection in detections:
        marker_names = _coerce_string_list(detection.get("project_markers"))
        executables = _coerce_string_list(detection.get("available_executables"))
        evidence = [*(f"file:{name}" for name in marker_names), *(f"command:{name}" for name in executables)]
        detected = bool(detection.get("detected"))
        recommended = bool(detection.get("recommended"))
        if recommended:
            status = "recommended"
            style = "green"
        elif detected:
            status = "available"
            style = "cyan"
        else:
            status = "not detected"
            style = "dim"
        table.add_row(
            str(detection.get("extension_id") or ""),
            status,
            ", ".join(evidence) or "none",
            str(detection.get("delegated_protection") or "command rules"),
            style=style,
        )
    console.print(table)
    console.print("[dim]Detection is read-only. No Guard settings were changed.[/dim]")


def _plain_text_command_inspection(payload: PayloadDict) -> str:
    classification = _coerce_object_dict(payload.get("classification"))
    extensions = _coerce_dict_list(payload.get("extensions"))
    rules = _coerce_dict_list(payload.get("rules"))
    lines = [
        f"HOL Guard command inspection: {str(payload.get('status') or 'invalid').upper()}",
        f"Command: {payload.get('command') or ''}",
        f"Action class: {classification.get('action_class') or 'No sensitive action matched'}",
        f"Reason: {classification.get('reason') or ''}",
        "Policy: Not evaluated; this inspection creates no approvals or receipts.",
    ]
    if extensions:
        lines.insert(3, f"Extension: {extensions[0].get('extension_id') or 'unknown'}")
    if rules:
        lines.insert(4, f"Rule: {rules[0].get('rule_id') or 'unknown'}")
    return "\n".join(lines)


def _plain_text_command_extensions(payload: PayloadDict) -> str:
    extensions = _coerce_dict_list(payload.get("extensions"))
    lines = [f"Built-in command safety extensions ({len(extensions)})"]
    lines.extend(f"{item.get('extension_id')} {item.get('version')} - {item.get('description')}" for item in extensions)
    return "\n".join(lines)


def _plain_text_command_setup(payload: PayloadDict) -> str:
    detections = _coerce_dict_list(payload.get("detections"))
    lines = [f"Recommended command ecosystems ({payload.get('recommended_count') or 0})"]
    for item in detections:
        if not item.get("recommended"):
            continue
        lines.append(f"{item.get('extension_id')} - recommended")
    lines.append("Detection is read-only. No Guard settings were changed.")
    return "\n".join(lines)


def _init_plan_panel(plan: list[dict[str, object]], status: str) -> Panel:
    table = Table.grid(padding=(0, 1))
    for step in plan:
        decision = str(step.get("decision") or "pending").replace("_", " ")
        title = str(step.get("title") or step.get("id") or "Step")
        command = str(step.get("command") or "")
        table.add_row(_init_decision_label(decision), f"[bold]{title}[/bold]", command)
        detail = step.get("detail")
        if isinstance(detail, str) and detail:
            table.add_row("", f"[dim]{detail}[/dim]", "")
    border = "red" if status == "needs_attention" else ("yellow" if status == "approval_required" else "cyan")
    return Panel(table, title="Progressive init plan", border_style=border)


def _init_decision_label(decision: str) -> str:
    if decision == "approved":
        return "[green]approved[/green]"
    if decision == "skipped":
        return "[yellow]skipped[/yellow]"
    return "[blue]pending[/blue]"


def _init_panel_title(status: str) -> str:
    if status == "approval_required":
        return "HOL Guard init needs approval"
    if status == "needs_attention":
        return "HOL Guard init needs attention"
    return "HOL Guard initialized"


def _init_skip_reason(payload: dict[str, object]) -> str:
    return str(payload.get("reason") or "not approved").replace("_", " ")


def _init_dashboard_summary(payload: dict[str, object]) -> str:
    if bool(payload.get("skipped")):
        return f"skipped ({_init_skip_reason(payload)})"
    if payload.get("error"):
        return f"not opened ({payload.get('error')})"
    opened = "opened" if bool(payload.get("opened")) else "ready"
    url = payload.get("browser_url") or payload.get("approval_center_url") or "local approval center"
    return f"{opened}: {url}"


def _init_apps_summary(payload: dict[str, object], count: int) -> str:
    if bool(payload.get("skipped")):
        return f"skipped ({_init_skip_reason(payload)})"
    if payload.get("error"):
        return f"needs attention ({payload.get('error')})"
    return f"{count} app install{'s' if count != 1 else ''} checked"


def _init_cloud_summary(payload: dict[str, object]) -> str:
    if bool(payload.get("skipped")):
        return f"skipped ({_init_skip_reason(payload)})"
    if payload.get("error"):
        return f"needs attention ({payload.get('error')})"
    if bool(payload.get("connected")):
        return "connected"
    status = payload.get("status") or payload.get("state") or "waiting"
    return str(status).replace("_", " ")


def _init_notification_summary(payload: dict[str, object]) -> str:
    if bool(payload.get("skipped")):
        return f"skipped ({_init_skip_reason(payload)})"
    if payload.get("error"):
        return f"needs attention ({payload.get('error')})"
    if not bool(payload.get("supported")):
        return "not supported on this OS"
    states = []
    if bool(payload.get("preview_sent")):
        states.append("preview sent")
    if bool(payload.get("settings_opened")):
        states.append("settings opened")
    if bool(payload.get("already_prompted")):
        states.append("already prompted")
    return ", ".join(states) if states else "ready"


def _render_status(console: Console, payload: dict[str, object]) -> None:
    harnesses = _coerce_dict_list(payload.get("harnesses"))
    console.print(
        Panel.fit(
            f"[bold]HOL Guard status[/bold]\n"
            f"{payload.get('managed_harnesses', 0)} managed harnesses • "
            f"{payload.get('receipt_count', 0)} receipts • "
            f"{payload.get('pending_approvals', 0)} approvals • "
            f"sync {'connected' if payload.get('sync_configured') else 'local only'}",
            border_style="cyan",
        )
    )
    console.print(_build_cloud_summary_panel(payload))
    console.print(_build_product_table(harnesses))
    if payload.get("approval_center_url"):
        console.print(f"Approval center: [bold]{payload.get('approval_center_url')}[/bold]")
    review_items = [item for item in harnesses if _coerce_int(item.get("review_count")) > 0]
    if review_items:
        console.print(
            Panel(
                "\n".join(
                    f"• {item.get('harness')}: run [bold]{item.get('review_command')}[/bold]" for item in review_items
                ),
                title="Needs review",
                border_style="yellow",
            )
        )


def _render_bootstrap(console: Console, payload: dict[str, object]) -> None:
    harness = payload.get("recommended_harness") or "none"
    bootstrap_install = payload.get("bootstrap_install")
    install_summary = _bootstrap_install_summary(bootstrap_install, fallback_harness=str(harness))
    body = Table.grid(padding=(0, 1))
    body.add_row("Recommended harness", str(harness))
    body.add_row("Approval center", str(payload.get("approval_center_url") or "not running"))
    body.add_row("Daemon ready", _bool_label(bool(payload.get("approval_center_reachable"))))
    body.add_row("Install", install_summary)
    alias = payload.get("shell_alias")
    if isinstance(alias, dict):
        body.add_row("Protect alias", str(alias.get("snippet") or "not configured"))
    console.print(Panel(body, title="Guard bootstrap", border_style="cyan"))
    console.print(_build_steps_panel(_coerce_dict_list(payload.get("next_steps"))))


def _bootstrap_install_summary(bootstrap_install: object, *, fallback_harness: str) -> str:
    if not isinstance(bootstrap_install, dict):
        return "not changed"
    harness = str(bootstrap_install.get("harness") or fallback_harness)
    reason = str(bootstrap_install.get("reason") or "")
    if bool(bootstrap_install.get("installed")):
        if reason == "repaired_managed_install":
            return f"repaired Guard install for {harness}"
        return f"installed for {harness}"
    if reason == "already_managed":
        return f"already managing {harness}"
    if reason == "skipped_by_flag":
        return "Install skipped for now"
    if reason == "no_harness_detected":
        return "No supported harness detected yet"
    return reason.replace("_", " ").strip() or "not changed"


def _render_doctor(console: Console, payload: dict[str, object]) -> None:
    if "desktop_notifications" in payload:
        desktop = payload.get("desktop_notifications")
        if not isinstance(desktop, dict):
            desktop = {}
        summary = Table.grid(padding=(0, 1))
        summary.add_row("Platform", f"[bold]{desktop.get('platform', 'unknown')}[/bold]")
        summary.add_row("Supported", _bool_label(bool(desktop.get("supported"))))
        summary.add_row("Preview sent", _bool_label(bool(desktop.get("preview_sent"))))
        summary.add_row("Settings opened", _bool_label(bool(desktop.get("settings_opened"))))
        summary.add_row("Already prompted", _bool_label(bool(desktop.get("already_prompted"))))
        notifier_path = desktop.get("notifier_path")
        if notifier_path:
            summary.add_row("Notifier", str(notifier_path))
        settings_url = desktop.get("settings_url")
        if settings_url:
            summary.add_row("Settings URL", str(settings_url))
        console.print(Panel(summary, title="Guard notification setup", border_style="cyan"))
    elif "adapters" in payload:
        tables = _coerce_string_list(payload.get("tables"))
        console.print(
            Panel.fit(
                f"[bold]HOL Guard doctor[/bold]\n{len(tables)} local tables checked",
                border_style="cyan",
            )
        )
        adapters = _coerce_dict_list(payload.get("adapters"))
        console.print(_build_harness_table(adapters))
    elif "harnesses" in payload and all("install_aliases" in h for h in _coerce_dict_list(payload.get("harnesses"))):
        contracts = _coerce_dict_list(payload.get("harnesses"))
        table = Table(title="HOL Guard supported harnesses", box=box.SIMPLE_HEAD, show_lines=False)
        table.add_column("Harness", style="bold cyan", no_wrap=True)
        table.add_column("Install alias", style="dim")
        table.add_column("Events")
        table.add_column("Native approval")
        table.add_column("Known blind spots")
        for contract in contracts:
            aliases = ", ".join(_coerce_string_list(contract.get("install_aliases")))
            events = ", ".join(_coerce_string_list(contract.get("event_surfaces")))
            native = "\u2713" if bool(contract.get("native_approval")) else "-"
            blind_spots = str(contract.get("known_blind_spots") or "")
            table.add_row(
                str(contract.get("harness", "")),
                aliases,
                events,
                native,
                textwrap.shorten(blind_spots, width=60),
            )
        console.print(table)
    else:
        warnings = _coerce_string_list(payload.get("warnings"))
        summary = Table.grid(padding=(0, 1))
        summary.add_row("Harness", f"[bold]{payload.get('harness', 'unknown')}[/bold]")
        summary.add_row("Installed", _bool_label(bool(payload.get("installed"))))
        summary.add_row("Command", _bool_label(bool(payload.get("command_available"))))
        summary.add_row("Artifacts", str(len(_coerce_dict_list(payload.get("artifacts")))))
        registry = payload.get("runtime_detector_registry")
        if isinstance(registry, dict):
            registry_state = "enabled" if bool(registry.get("enabled")) else "disabled"
            timeout_ms = registry.get("timeout_ms")
            summary.add_row("Detector registry", f"{registry_state}, {timeout_ms} ms")
        connect_health = payload.get("connect_health")
        if isinstance(connect_health, dict):
            oauth_storage_health = connect_health.get("oauth_storage_health")
            if isinstance(oauth_storage_health, dict):
                summary.add_row("OAuth storage", str(oauth_storage_health.get("state") or "unknown"))
            latest_connect_state = connect_health.get("latest_connect_state")
            if isinstance(latest_connect_state, dict):
                connect_status = str(latest_connect_state.get("status") or "unknown")
                milestone = str(latest_connect_state.get("milestone") or "unknown")
                summary.add_row("Connect state", f"{connect_status}, {milestone}")
            recovery_command = connect_health.get("connect_recovery_command")
            if isinstance(recovery_command, str) and recovery_command.strip():
                summary.add_row("Recovery", recovery_command)
        summary.add_row("Warnings", str(len(warnings)))
        console.print(Panel(summary, title="Guard doctor", border_style="cyan"))
        if warnings:
            warning_text = "\n".join(
                textwrap.fill(
                    f"• {warning}",
                    width=72,
                    subsequent_indent="  ",
                )
                for warning in warnings
            )
            console.print(Panel(Text(warning_text), title="Attention", border_style="yellow"))
        runtime_probe = payload.get("runtime_probe")
        if isinstance(runtime_probe, dict):
            console.print(_build_runtime_probe_panel(runtime_probe))
        artifacts = _coerce_dict_list(payload.get("artifacts"))
        if artifacts:
            console.print(_build_artifact_table(artifacts))
        supply_chain = payload.get("supply_chain")
        if isinstance(supply_chain, dict):
            console.print(_build_supply_chain_posture_panel(supply_chain))
    trust = payload.get("trust")
    if isinstance(trust, dict):
        console.print(_build_trust_doctor_panel(trust))
    perf_items = payload.get("detector_perf")
    if isinstance(perf_items, list) and perf_items:
        perf_table = Table(title="Detector performance", box=box.SIMPLE_HEAVY, show_header=True)
        perf_table.add_column("Detector", style="bold")
        perf_table.add_column("Status")
        perf_table.add_column("ms", justify="right")
        perf_table.add_column("Slow?")
        for item in perf_items:
            slow = bool(item.get("slow"))
            perf_table.add_row(
                str(item.get("detector_id", "")),
                str(item.get("status", "")),
                str(item.get("elapsed_ms", 0)),
                "[red]yes[/red]" if slow else "no",
            )
        console.print(perf_table)
    console.print(_build_diagnostic_command_panel())


def _build_trust_doctor_panel(trust: dict[str, object]) -> Panel:
    body = Table.grid(padding=(0, 1))
    body.add_row("Mode", str(trust.get("mode") or "unknown"))
    body.add_row("Runtime", str(trust.get("runtime_protection") or "unknown"))
    body.add_row("Remembered rules", str(trust.get("remembered_rules") or "unknown"))
    body.add_row("Cloud policies", str(trust.get("cloud_policies") or "unknown"))
    body.add_row("Passive OS prompts", "blocked" if trust.get("passive_prompt_allowed") is False else "unknown")
    passive_read_guarantee = trust.get("passive_read_guarantee")
    if isinstance(passive_read_guarantee, str) and passive_read_guarantee.strip():
        body.add_row("Prompt-free reads", passive_read_guarantee.strip())
    checks = trust.get("checks")
    if isinstance(checks, dict):
        body.add_row("Local rules protected", _bool_label(bool(checks.get("local_rules_protected"))))
        body.add_row("Passive no-UI check", _bool_label(bool(checks.get("passive_no_ui"))))
    approval_center = trust.get("approval_center")
    if isinstance(approval_center, dict):
        body.add_row("Approval center", str(approval_center.get("approval_url_base") or "inactive"))
        if approval_center.get("port") is not None:
            body.add_row("Approval port", str(approval_center.get("port")))
        detail = approval_center.get("detail")
        if isinstance(detail, str) and detail.strip():
            body.add_row("Approval route", textwrap.fill(detail.strip(), width=72))
    official_install = trust.get("official_install")
    if isinstance(official_install, dict):
        version = official_install.get("version") or "unknown"
        update_command = official_install.get("update_command") or "hol-guard update"
        body.add_row("Installed package", f"hol-guard {version}")
        body.add_row("Install mode", str(official_install.get("installation_mode") or "unknown"))
        body.add_row("Install check", str(official_install.get("active_command_status") or "unknown"))
        active_command_path = official_install.get("active_command_path")
        if isinstance(active_command_path, str) and active_command_path.strip():
            body.add_row("Active command", active_command_path.strip())
        body.add_row("Update", str(update_command))
    summary = trust.get("summary")
    if isinstance(summary, str) and summary.strip():
        body.add_row("Summary", textwrap.fill(summary.strip(), width=72))
    actions = _coerce_string_list(trust.get("recommended_actions"))
    if actions:
        body.add_row("Next", "\n".join(textwrap.fill(f"* {action}", width=72) for action in actions))
    border_style = "green" if str(trust.get("remembered_rules") or "") == "enforced" else "yellow"
    return Panel(body, title="Local trust", border_style=border_style)


def _render_trust_doctor(console: Console, payload: dict[str, object]) -> None:
    console.print(_build_trust_doctor_panel(payload))
    console.print(_build_diagnostic_command_panel())


def _render_trust_explain(console: Console, payload: dict[str, object]) -> None:
    rule = payload.get("rule")
    if not isinstance(rule, dict):
        _render_fallback(console, payload)
        return
    body = Table.grid(padding=(0, 1))
    body.add_row("Rule", str(payload.get("rule_id") or "unknown"))
    body.add_row("Scope", str(rule.get("scope") or "unknown"))
    body.add_row("Action", str(rule.get("action") or "unknown"))
    body.add_row("Source", str(rule.get("source") or "unknown"))
    body.add_row("Authority", str(payload.get("rule_status_label") or "unknown"))
    integrity_status = rule.get("integrity_status")
    if integrity_status is not None:
        body.add_row("Integrity", str(integrity_status))
    updated_at = rule.get("updated_at")
    if updated_at is not None:
        body.add_row("Updated", str(updated_at))
    rule_status_reason = payload.get("rule_status_reason")
    if isinstance(rule_status_reason, str) and rule_status_reason.strip():
        body.add_row("Why", textwrap.fill(rule_status_reason.strip(), width=72))
    trust_status = payload.get("trust_status")
    if isinstance(trust_status, dict):
        body.add_row("Runtime", str(trust_status.get("runtime_protection") or "unknown"))
        body.add_row("Local trust", str(trust_status.get("remembered_rules") or "unknown"))
        body.add_row("Cloud", str(trust_status.get("cloud_policies") or "unknown"))
    console.print(Panel(body, title="Remembered rule authority", border_style="cyan"))


def _render_run(console: Console, payload: dict[str, object]) -> None:
    blocked = bool(payload.get("blocked"))
    launched = bool(payload.get("launched"))
    dry_run = bool(payload.get("dry_run"))
    authority_error = payload.get("authority_error")
    has_authority_error = isinstance(authority_error, str) and bool(authority_error.strip())
    artifacts = _coerce_dict_list(payload.get("artifacts"))
    visible_artifacts = (
        [] if has_authority_error else [artifact for artifact in artifacts if _run_artifact_should_be_visible(artifact)]
    )
    summarized_artifacts = _summarize_run_artifacts(visible_artifacts)
    title = (
        "Launch refused: inconsistent decision" if has_authority_error else _run_title(blocked=blocked, dry_run=dry_run)
    )
    border_style = "red" if blocked else "green"
    body = Table.grid(padding=(0, 1))
    approval_delivery = payload.get("approval_delivery")
    body.add_row("Harness", f"[bold]{payload.get('harness', 'unknown')}[/bold]")
    body.add_row("Mode", "dry run" if dry_run else "launch")
    authority_message = payload.get("authority_error_message")
    outcome = (
        str(authority_message)
        if has_authority_error and isinstance(authority_message, str) and authority_message.strip()
        else _run_outcome_text(blocked=blocked, dry_run=dry_run, launched=launched)
    )
    body.add_row("Outcome", outcome)
    if has_authority_error:
        body.add_row("Authority error", str(authority_error))
    body.add_row("Artifacts", str(len(summarized_artifacts)))
    if blocked and not has_authority_error:
        needs_review = sum(1 for artifact in visible_artifacts if _artifact_needs_review(artifact))
        body.add_row("Needs review", str(needs_review))
    body.add_row("Receipts", str(payload.get("receipts_recorded", 0)))
    if isinstance(approval_delivery, dict) and approval_delivery.get("summary"):
        body.add_row("Prompt route", str(approval_delivery.get("summary")))
    if payload.get("approval_center_url"):
        body.add_row("Approval center", str(payload.get("approval_center_url")))
    if payload.get("review_hint"):
        body.add_row("Review", str(payload.get("review_hint")))
    if launched:
        body.add_row("Command", _command_text(payload.get("launch_command")))
    console.print(Panel(body, title=title, border_style=border_style))
    if summarized_artifacts:
        console.print(_build_run_artifact_table(summarized_artifacts))
    steps = _build_run_steps(payload, blocked=blocked, dry_run=dry_run)
    if steps:
        console.print(_build_steps_panel(steps))
    approval_requests = _coerce_dict_list(payload.get("approval_requests"))
    if approval_requests:
        console.print(_build_approval_table(approval_requests, title="Queued approvals"))


def _render_diff(console: Console, payload: dict[str, object]) -> None:
    changed = bool(payload.get("changed"))
    title = "Changes detected" if changed else "No changes detected"
    border_style = "yellow" if changed else "green"
    console.print(
        Panel.fit(
            f"[bold]{title}[/bold]\n{len(_coerce_dict_list(payload.get('artifacts')))} artifacts in diff view",
            border_style=border_style,
        )
    )
    console.print(_build_artifact_result_table(_coerce_dict_list(payload.get("artifacts"))))


def _render_receipts(console: Console, payload: dict[str, object]) -> None:
    receipts = _coerce_dict_list(payload.get("items"))
    console.print(
        Panel.fit(
            f"[bold]Recent Guard receipts[/bold]\n{len(receipts)} local decisions recorded",
            border_style="cyan",
        )
    )
    table = Table(box=box.SIMPLE_HEAVY, show_header=True)
    table.add_column("Date", style="dim", no_wrap=True)
    table.add_column("Time", style="dim", no_wrap=True)
    table.add_column("Harness", style="cyan")
    table.add_column("Artifact", style="bold")
    table.add_column("Decision")
    table.add_column("Capabilities", style="blue")
    table.add_column("Changed fields", style="magenta")
    for receipt in receipts:
        date_text, time_text = _timestamp_parts(receipt.get("timestamp"))
        table.add_row(
            date_text,
            time_text,
            str(receipt.get("harness", "unknown")),
            str(receipt.get("artifact_name") or receipt.get("artifact_id") or "unknown"),
            _action_text(str(receipt.get("policy_decision", "warn"))),
            str(receipt.get("capabilities_summary") or "unknown"),
            ", ".join(_coerce_string_list(receipt.get("changed_capabilities"))) or "none",
        )
    console.print(table)


def _render_inventory(console: Console, payload: dict[str, object]) -> None:
    items = _coerce_dict_list(payload.get("items"))
    console.print(
        Panel.fit(
            f"[bold]Local Guard inventory[/bold]\n{len(items)} tracked artifact{'s' if len(items) != 1 else ''}",
            border_style="cyan",
        )
    )
    table = Table(box=box.SIMPLE_HEAVY, show_header=True)
    table.add_column("Artifact", style="bold")
    table.add_column("Harness", style="cyan")
    table.add_column("Type")
    table.add_column("Scope")
    table.add_column("Verdict")
    table.add_column("Present")
    for item in items:
        table.add_row(
            str(item.get("artifact_name") or item.get("artifact_id") or "unknown"),
            str(item.get("harness") or "unknown"),
            str(item.get("artifact_type") or "artifact"),
            str(item.get("source_scope") or "unknown"),
            _action_text(str(item.get("last_policy_action") or "warn")),
            _bool_label(bool(item.get("present"))),
        )
    console.print(table)


def _render_policies(console: Console, payload: dict[str, object]) -> None:
    if "counts" in payload or payload.get("operation") == "migrate-local-integrity":
        counts = _coerce_object_dict(payload.get("counts"))
        degraded_reasons = _coerce_string_list(payload.get("degraded_reasons"))
        body = Table.grid(padding=(0, 1))
        body.add_row("Mode", str(payload.get("mode") or "unknown"))
        body.add_row("Enforcement", str(payload.get("enforcement") or "unknown"))
        body.add_row("Backend", str(payload.get("backend") or "unknown"))
        body.add_row("Local rows", str(_coerce_int(payload.get("local_rows_scanned"))))
        if payload.get("key_id"):
            body.add_row("Integrity key", "present")
        if payload.get("backup_path"):
            body.add_row("Backup", str(payload.get("backup_path")))
        trust_status = payload.get("trust_status")
        if isinstance(trust_status, dict):
            body.add_row("Runtime protection", str(trust_status.get("runtime_protection") or "unknown"))
            body.add_row("Remembered rules", str(trust_status.get("remembered_rules") or "unknown"))
            body.add_row("Cloud policies", str(trust_status.get("cloud_policies") or "unknown"))
        if "cleared" in payload:
            body.add_row("Cleared", str(_coerce_int(payload.get("cleared"))))
        for label, key in (
            ("Valid", "valid"),
            ("Unsigned", "missing_integrity"),
            ("Tampered", "tampered"),
            ("Unknown key", "unknown_key"),
            ("Rolled back", "rollback_detected"),
            ("Degraded", "degraded_mode"),
        ):
            body.add_row(label, str(_coerce_int(counts.get(key))))
        if degraded_reasons:
            body.add_row("Reasons", ", ".join(degraded_reasons))
        title = "Guard policy integrity"
        if "backup_path" in payload:
            title = "Guard policy migration"
        elif "clear_invalid" in payload:
            title = "Guard policy repair"
        elif "items" in payload:
            title = "Guard policy verify"
        border_style = "red" if payload.get("error") else "cyan"
        console.print(Panel(body, title=title, border_style=border_style))
        if payload.get("error"):
            console.print(str(payload.get("error")))
            return
        invalid_items = _coerce_dict_list(payload.get("items"))
        if not invalid_items:
            return
        table = Table(box=box.SIMPLE_HEAVY, show_header=True)
        table.add_column("Harness", style="cyan")
        table.add_column("Action")
        table.add_column("Artifact", style="bold")
        table.add_column("Integrity")
        table.add_column("Updated")
        for item in invalid_items:
            table.add_row(
                str(item.get("harness") or "unknown"),
                _action_text(str(item.get("action") or "warn")),
                str(item.get("artifact_id") or "all artifacts"),
                str(item.get("integrity_status") or "unknown"),
                str(item.get("updated_at") or "unknown"),
            )
        console.print(table)
        return
    if "cleared" in payload or "error" in payload:
        error = payload.get("error")
        cleared = _coerce_int(payload.get("cleared"))
        scope = str(payload.get("harness") or "all harnesses")
        source = payload.get("source")
        body = Table.grid(padding=(0, 1))
        body.add_row("Outcome", str(error) if error else f"cleared {cleared} decision{'s' if cleared != 1 else ''}")
        body.add_row("Harness", scope)
        if source:
            body.add_row("Source", str(source))
        console.print(
            Panel(
                body,
                title="Guard rules clear",
                border_style="red" if error else "green",
            )
        )
        return
    items = _coerce_dict_list(payload.get("items"))
    console.print(
        Panel.fit(
            f"[bold]Guard remembered rules and Cloud policies[/bold]\n"
            f"{len(items)} active rule{'s' if len(items) != 1 else ''}",
            border_style="cyan",
        )
    )
    table = Table(box=box.SIMPLE_HEAVY, show_header=True)
    table.add_column("Harness", style="cyan")
    table.add_column("Scope")
    table.add_column("Action")
    table.add_column("Integrity")
    table.add_column("Artifact", style="bold")
    table.add_column("Publisher")
    table.add_column("Owner")
    table.add_column("Expires")
    for item in items:
        table.add_row(
            str(item.get("harness") or "unknown"),
            str(item.get("scope") or "harness"),
            _action_text(str(item.get("action") or "warn")),
            str(item.get("integrity_status") or "remote"),
            str(item.get("artifact_id") or "all artifacts"),
            str(item.get("publisher") or "—"),
            str(item.get("owner") or "—"),
            str(item.get("expires_at") or "never"),
        )
    console.print(table)


def _render_advisories(console: Console, payload: dict[str, object]) -> None:
    items = _coerce_dict_list(payload.get("items"))
    console.print(
        Panel.fit(
            f"[bold]Guard advisories[/bold]\n{len(items)} cached advisory{'s' if len(items) != 1 else ''}",
            border_style="cyan",
        )
    )
    console.print(_build_advisory_table(items))


def _build_advisory_table(items: list[dict[str, object]], *, title: str | None = None) -> Table:
    table = Table(title=title, box=box.SIMPLE_HEAVY, show_header=True)
    table.add_column("Publisher", style="bold")
    table.add_column("Severity")
    table.add_column("Headline")
    table.add_column("Updated", style="dim")
    for item in items:
        table.add_row(
            str(item.get("publisher") or "unknown"),
            str(item.get("severity") or "info"),
            str(item.get("headline") or item.get("cache_key") or "advisory"),
            str(item.get("updated_at") or "unknown"),
        )
    return table


def _render_events(console: Console, payload: dict[str, object]) -> None:
    items = _coerce_dict_list(payload.get("items"))
    console.print(
        Panel.fit(
            f"[bold]Guard lifecycle events[/bold]\n{len(items)} local event{'s' if len(items) != 1 else ''}",
            border_style="cyan",
        )
    )
    table = Table(box=box.SIMPLE_HEAVY, show_header=True)
    table.add_column("When", style="dim", no_wrap=True)
    table.add_column("Event", style="bold")
    table.add_column("Summary")
    for item in items:
        event_name = str(item.get("event_name") or "unknown")
        payload_item = item.get("payload")
        summary = event_name
        if isinstance(payload_item, dict):
            summary = str(
                payload_item.get("artifact_name")
                or payload_item.get("artifact_id")
                or payload_item.get("sync_url")
                or event_name
            )
        table.add_row(str(item.get("occurred_at") or "unknown"), event_name, summary)
    console.print(table)


def _render_approvals(console: Console, payload: dict[str, object]) -> None:
    approval_url = payload.get("approval_url")
    if isinstance(approval_url, str) and approval_url:
        body = Table.grid(padding=(0, 1))
        body.add_row("Request", str(payload.get("request_id", "")))
        body.add_row("URL", f"[bold]{approval_url}[/bold]")
        console.print(Panel(body, title="Open approval", border_style="cyan"))
        return
    if "title" in payload and "body" in payload:
        body = Table.grid(padding=(0, 1))
        body.add_row("Status", str(payload["title"]))
        body.add_row("Next step", str(payload["body"]))
        console.print(Panel(body, title="Approval resolved", border_style="green"))
        return
    if payload.get("error"):
        console.print(Panel(str(payload.get("error")), title="Approval error", border_style="red"))
        return
    if "history_cleared" in payload or "cleared_policies" in payload:
        error = payload.get("error")
        body = Table.grid(padding=(0, 1))
        body.add_row(
            "Outcome",
            str(error) if error else "approval history reset",
        )
        body.add_row("Harness", str(payload.get("harness") or "all harnesses"))
        source = payload.get("source")
        if source:
            body.add_row("Source", str(source))
        body.add_row("Policy decisions", str(_coerce_int(payload.get("cleared_policies"))))
        body.add_row("Resolved requests", str(_coerce_int(payload.get("cleared_resolved_requests"))))
        console.print(
            Panel(
                body,
                title="Approval history",
                border_style="red" if error else "green",
            )
        )
        return
    if payload.get("resolved"):
        item = payload.get("item")
        if isinstance(item, dict):
            body = Table.grid(padding=(0, 1))
            body.add_row("Artifact", str(item.get("artifact_name") or item.get("artifact_id") or "unknown"))
            body.add_row("Harness", str(item.get("harness") or "unknown"))
            body.add_row("Action", _action_text(str(item.get("resolution_action") or "warn")))
            body.add_row("Scope", str(item.get("resolution_scope") or "artifact"))
            console.print(Panel(body, title="Approval resolved", border_style="green"))
            return
    items = _coerce_dict_list(payload.get("items"))
    console.print(
        Panel.fit(
            f"[bold]Pending Guard approvals[/bold]\n{len(items)} item{'s' if len(items) != 1 else ''} waiting",
            border_style="yellow" if items else "green",
        )
    )
    if payload.get("approval_center_url"):
        console.print(f"Approval center: [bold]{payload.get('approval_center_url')}[/bold]")
    console.print(_build_approval_table(items, title=None))


def _render_managed_install(console: Console, payload: dict[str, object]) -> None:
    skill_scan = _coerce_dict_list(payload.get("skill_scan"))
    supply_chain_risks = _coerce_dict_list(payload.get("supply_chain_risks"))
    safe_decode_risks = _coerce_dict_list(payload.get("safe_decode_risks"))
    sandbox_analysis = _coerce_dict_list(payload.get("sandbox_analysis"))
    if bool(payload.get("self_uninstall")):
        render_self_uninstall(console, payload)
    managed_install = payload.get("managed_install")
    if isinstance(managed_install, dict):
        _render_single_managed_install(console, managed_install)
    else:
        managed_installs = _coerce_dict_list(payload.get("managed_installs"))
        if not managed_installs:
            if (
                not bool(payload.get("self_uninstall"))
                and not skill_scan
                and not supply_chain_risks
                and not safe_decode_risks
                and not sandbox_analysis
            ):
                _render_fallback(console, payload)
                return
        else:
            console.print(
                Panel(
                    _managed_install_batch_summary(payload, managed_installs),
                    title="Guard managed harnesses",
                    border_style="cyan",
                )
            )
            console.print(_managed_install_batch_table(managed_installs))
            notes = _managed_install_batch_notes(managed_installs)
            if notes:
                console.print(_notes_panel(notes))
    if skill_scan:
        _render_skill_scan_results(console, skill_scan)
    if supply_chain_risks:
        _render_supply_chain_risk_results(console, supply_chain_risks)
    if safe_decode_risks:
        _render_safe_decode_results(console, safe_decode_risks)
    if sandbox_analysis:
        _render_sandbox_results(console, sandbox_analysis)


def _render_apps(console: Console, payload: dict[str, object]) -> None:
    if payload.get("managed_install") or payload.get("managed_installs"):
        _render_managed_install(console, payload)
    else:
        _render_fallback(console, payload)
    dry_run_effect = payload.get("dry_run_effect")
    if isinstance(dry_run_effect, str) and dry_run_effect:
        console.print(Panel(dry_run_effect, title="Dry run", border_style="yellow"))
    cloud_app = payload.get("cloud_app")
    if not isinstance(cloud_app, dict):
        return
    body = Table.grid(padding=(0, 1))
    browser_opened = bool(cloud_app.get("browser_opened"))
    body.add_row("Cloud page", str(cloud_app.get("app_url") or "unknown"))
    body.add_row("Local daemon", str(cloud_app.get("daemon_url") or "unknown"))
    body.add_row("Browser", "opened" if browser_opened else "manual open required")
    next_action = cloud_app.get("next_action")
    if isinstance(next_action, dict):
        body.add_row("Next", str(next_action.get("label") or "Open Guard Cloud app page"))
        body.add_row(
            "Recovery",
            "Rerun the command; Guard opens the authenticated URL without printing the local token.",
        )
    console.print(
        Panel(
            body,
            title="Guard Cloud app connect",
            border_style="green" if browser_opened else "yellow",
        )
    )


def _render_supply_chain_risk_results(console: Console, supply_chain_risks: list[dict[str, object]]) -> None:
    table = Table(box=box.SIMPLE_HEAVY, show_header=True, expand=True)
    table.add_column("Signal", overflow="fold")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Confidence", no_wrap=True)
    table.add_column("Explanation", overflow="fold")
    for entry in supply_chain_risks:
        severity = str(entry.get("severity", "medium")).lower()
        severity_color = _SEVERITY_COLORS.get(severity, "white")
        table.add_row(
            str(entry.get("signal_id", "?")),
            f"[{severity_color}]{severity}[/{severity_color}]",
            str(entry.get("confidence", "?")),
            str(entry.get("plain_reason", "")),
        )
    console.print(
        Panel(
            table,
            title=f"[bold yellow]Supply chain risks — {len(supply_chain_risks)} signal(s)[/bold yellow]",
            border_style="yellow",
        )
    )


def _render_safe_decode_results(console: Console, safe_decode_risks: list[dict[str, object]]) -> None:
    table = Table(box=box.SIMPLE_HEAVY, show_header=True, expand=True)
    table.add_column("Signal", overflow="fold")
    table.add_column("Layers", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Explanation", overflow="fold")
    for entry in safe_decode_risks:
        severity = str(entry.get("severity", "medium")).lower()
        severity_color = _SEVERITY_COLORS.get(severity, "white")
        layers = str(entry.get("technical_detail") or "")
        table.add_row(
            str(entry.get("signal_id", "?")),
            layers[:60] if layers else "-",
            f"[{severity_color}]{severity}[/{severity_color}]",
            str(entry.get("plain_reason", "")),
        )
    console.print(
        Panel(
            table,
            title=f"[bold magenta]Encoded payload risks — {len(safe_decode_risks)} signal(s)[/bold magenta]",
            border_style="magenta",
        )
    )


def _render_sandbox_results(console: Console, sandbox_analysis: list[dict[str, object]]) -> None:
    table = Table(box=box.SIMPLE_HEAVY, show_header=True, expand=True)
    table.add_column("Signal", overflow="fold")
    table.add_column("Writes", justify="right", no_wrap=True)
    table.add_column("Network", justify="right", no_wrap=True)
    table.add_column("Processes", justify="right", no_wrap=True)
    table.add_column("Timed out", no_wrap=True)
    table.add_column("Exit code", no_wrap=True)
    for entry in sandbox_analysis:
        signals = _coerce_string_list(entry.get("signals_detected"))
        signal_text = ", ".join(signals) if signals else "—"
        writes = _coerce_string_list(entry.get("writes"))
        network = _coerce_string_list(entry.get("network_attempts"))
        processes = _coerce_string_list(entry.get("process_attempts"))
        timed_out = bool(entry.get("timed_out"))
        exit_code = entry.get("exit_code")
        table.add_row(
            signal_text,
            str(len(writes)),
            str(len(network)),
            str(len(processes)),
            "[red]yes[/red]" if timed_out else "no",
            str(exit_code) if exit_code is not None else "—",
        )
    console.print(
        Panel(
            table,
            title=f"[bold magenta]Sandbox analysis — {len(sandbox_analysis)} result(s)[/bold magenta]",
            border_style="magenta",
        )
    )


def _render_skill_scan_results(console: Console, skill_scan: list[dict[str, object]]) -> None:
    table = Table(box=box.SIMPLE_HEAVY, show_header=True, expand=True)
    table.add_column("Skill file", overflow="fold")
    table.add_column("Risks", justify="right", no_wrap=True)
    table.add_column("Severities", no_wrap=True)
    table.add_column("Signals", overflow="fold")
    for entry in skill_scan:
        severity_text = ", ".join(_coerce_string_list(entry.get("severities")))
        signal_text = " ".join(_coerce_string_list(entry.get("signal_ids")))
        risk_count = str(entry.get("risk_count", 0))
        table.add_row(str(entry.get("skill_path", "?")), risk_count, severity_text, signal_text)
    console.print(
        Panel(
            table,
            title=f"[bold red]Skill security scan — {len(skill_scan)} file(s) with risks[/bold red]",
            border_style="red",
        )
    )


def _managed_install_workspace_label(workspace: object) -> str:
    if isinstance(workspace, str) and workspace.strip():
        return workspace.strip()
    return "global (~/.cursor)"


def _managed_install_config_label(manifest: dict[str, object]) -> str:
    for key in ("config_path", "managed_config_path"):
        value = manifest.get(key)
        if isinstance(value, str) and value.strip():
            return _short_path(value.strip())
    hooks_path = manifest.get("managed_hooks_path")
    if isinstance(hooks_path, str) and hooks_path.strip():
        return f"hooks updated ({_short_path(hooks_path.strip())})"
    return "no config changed"


def _render_single_managed_install(console: Console, managed_install: dict[str, object]) -> None:
    manifest = managed_install.get("manifest")
    notes = _managed_install_notes(managed_install, manifest)
    body = Table.grid(padding=(0, 1))
    body.add_row("Harness", f"[bold]{managed_install.get('harness', 'unknown')}[/bold]")
    body.add_row("Protection", _managed_install_state_text(managed_install))
    body.add_row("Workspace", _managed_install_workspace_label(managed_install.get("workspace")))
    if isinstance(manifest, dict):
        mode = _managed_install_mode_text(manifest.get("mode"))
        if mode is not None:
            body.add_row("Mode", mode)
        body.add_row("Config", _managed_install_config_label(manifest))
        managed_servers = _coerce_string_list(manifest.get("managed_servers"))
        if managed_servers:
            body.add_row("Managed servers", str(len(managed_servers)))
        skipped_servers = _coerce_string_list(manifest.get("skipped_servers"))
        if skipped_servers:
            body.add_row("Skipped servers", str(len(skipped_servers)))
        if manifest.get("shim_command"):
            body.add_row("Launcher", str(manifest.get("shim_command")))
    console.print(Panel(body, title="Guard install state", border_style="cyan"))
    if notes:
        console.print(_notes_panel(notes))


def _managed_install_batch_summary(payload: dict[str, object], managed_installs: list[dict[str, object]]) -> Table:
    installed_count = sum(1 for item in managed_installs if bool(item.get("active")))
    removed_count = len(managed_installs) - installed_count
    body = Table.grid(padding=(0, 1))
    body.add_row("Harnesses", str(len(managed_installs)))
    if payload.get("auto_detected") is not None:
        body.add_row("Selection", "Auto-detected" if bool(payload.get("auto_detected")) else "Requested")
    body.add_row("Protection", f"{installed_count} installed • {removed_count} removed")
    return body


def _managed_install_batch_table(managed_installs: list[dict[str, object]]) -> Table:
    table = Table(box=box.SIMPLE_HEAVY, show_header=True, expand=True)
    table.add_column("Harness", style="bold", no_wrap=True)
    table.add_column("State", no_wrap=True)
    table.add_column("Mode", overflow="fold")
    table.add_column("Servers", justify="right", no_wrap=True)
    table.add_column("Config", overflow="fold")
    for item in managed_installs:
        manifest = item.get("manifest")
        mode = _managed_install_mode_text(manifest.get("mode")) if isinstance(manifest, dict) else None
        managed_servers = _coerce_string_list(manifest.get("managed_servers")) if isinstance(manifest, dict) else []
        config_path = manifest.get("config_path") if isinstance(manifest, dict) else None
        table.add_row(
            str(item.get("harness") or "unknown"),
            _managed_install_state_text(item),
            mode or "—",
            str(len(managed_servers)) if managed_servers else "—",
            _short_path(config_path) if config_path else "no config changed",
        )
    return table


def _managed_install_batch_notes(managed_installs: list[dict[str, object]]) -> list[str]:
    notes: list[str] = []
    for item in managed_installs:
        harness = str(item.get("harness") or "unknown")
        manifest = item.get("manifest")
        for note in _managed_install_notes(item, manifest):
            notes.append(f"{harness}: {note}")
    return notes


def _notes_panel(notes: list[str]) -> Panel:
    return Panel(
        Text("\n".join(f"• {note}" for note in notes), overflow="fold", no_wrap=False),
        title="Notes",
        border_style="blue",
    )


def _render_decision(console: Console, payload: dict[str, object]) -> None:
    decision = payload.get("decision")
    if not isinstance(decision, dict):
        _render_fallback(console, payload)
        return
    body = Table.grid(padding=(0, 1))
    body.add_row("Harness", f"[bold]{decision.get('harness', 'unknown')}[/bold]")
    body.add_row("Scope", str(decision.get("scope", "harness")))
    body.add_row("Action", _action_text(str(decision.get("action", "warn"))))
    body.add_row("Artifact", str(decision.get("artifact_id") or "all artifacts"))
    if decision.get("publisher"):
        body.add_row("Publisher", str(decision.get("publisher")))
    if decision.get("reason"):
        body.add_row("Reason", str(decision.get("reason")))
    console.print(Panel(body, title="Policy updated", border_style="green"))


def _render_login(console: Console, payload: dict[str, object]) -> None:
    console.print(
        Panel.fit(
            f"[bold]Guard sync endpoint saved[/bold]\nEndpoint: {payload.get('sync_url', 'unknown')}",
            border_style="green",
        )
    )


def _render_connect(console: Console, payload: dict[str, object]) -> None:
    if "connected" in payload or "browser_opened" in payload or "status" in payload:
        body = Table.grid(padding=(0, 1))
        milestone = str(payload.get("milestone") or "")
        body.add_row("Browser opened", _bool_label(bool(payload.get("browser_opened"))))
        body.add_row(
            "Browser paired",
            _bool_label(bool(payload.get("completed_at")) or str(payload.get("status") or "") == "connected"),
        )
        body.add_row("Connection", _connect_status_text(payload))
        if milestone:
            body.add_row("Next step", _connect_milestone_text(payload))
        cloud_pairing_url = payload.get("cloud_pairing_url") or payload.get("connect_url") or "unknown"
        body.add_row("Cloud URL", str(cloud_pairing_url))
        body.add_row("Sync endpoint", str(payload.get("sync_url") or "unknown"))
        recovery_command = payload.get("recovery_command")
        if isinstance(recovery_command, str) and recovery_command.strip():
            body.add_row("Recovery command", recovery_command)
        repair_message = payload.get("repair_message")
        if isinstance(repair_message, str) and repair_message.strip():
            body.add_row("Repair note", repair_message)
        sync_payload = payload.get("sync")
        should_render_sync_counts = False
        if isinstance(sync_payload, dict):
            receipts_stored = _coerce_int(sync_payload.get("receipts_stored"))
            inventory_value = sync_payload.get("inventory_tracked", sync_payload.get("inventory"))
            inventory_tracked = _coerce_int(inventory_value)
            should_render_sync_counts = any(
                (
                    milestone == "first_sync_succeeded",
                    receipts_stored > 0,
                    inventory_tracked > 0,
                )
            )
            if should_render_sync_counts:
                body.add_row("Receipts stored", str(receipts_stored))
                body.add_row("Inventory tracked", str(inventory_tracked))
        sync_message = _connect_sync_note_text(payload)
        if sync_message is not None:
            body.add_row("Sync note", sync_message)
        console.print(Panel(body, title="Guard connect", border_style="green"))
        return

    border_style = _cloud_border_style(str(payload.get("cloud_state") or "local_only"))
    console.print(
        Panel.fit(
            f"[bold]HOL Guard connect[/bold]\n"
            f"{payload.get('cloud_state_label', 'Local only')} • "
            f"{payload.get('receipt_count', 0)} receipts • "
            f"{payload.get('pending_approvals', 0)} approvals",
            border_style=border_style,
        )
    )
    console.print(_build_cloud_summary_panel(payload))
    sync_result = payload.get("sync_result")
    if isinstance(sync_result, dict):
        body = Table.grid(padding=(0, 1))
        body.add_row("Synced at", str(sync_result.get("synced_at") or "unknown"))
        body.add_row("Receipts stored", str(sync_result.get("receipts_stored") or 0))
        body.add_row("Advisories stored", str(sync_result.get("advisories_stored") or 0))
        body.add_row("Remote policies", str(sync_result.get("remote_policies_stored") or 0))
        console.print(Panel(body, title="Connect sync", border_style="green"))
    if payload.get("sync_error"):
        console.print(Panel(str(payload.get("sync_error")), title="Connect failed", border_style="red"))
    if payload.get("approval_center_url"):
        console.print(f"Approval center: [bold]{payload.get('approval_center_url')}[/bold]")
    console.print(_build_product_table(_coerce_dict_list(payload.get("harnesses"))))
    console.print(_build_steps_panel(_coerce_dict_list(payload.get("next_steps"))))


def _render_dashboard(console: Console, payload: dict[str, object]) -> None:
    body = Table.grid(padding=(0, 1))
    body.add_row("Dashboard", str(payload.get("approval_center_url") or "unknown"))
    if payload.get("opened") is not None:
        body.add_row("Browser opened", _bool_label(bool(payload.get("opened"))))
    console.print(Panel(body, title="HOL Guard dashboard", border_style="cyan"))


def _render_sync(console: Console, payload: dict[str, object]) -> None:
    body = Table.grid(padding=(0, 1))
    body.add_row("Synced at", str(payload.get("synced_at") or "unknown"))
    body.add_row("Receipts sent", str(payload.get("receipts") or 0))
    body.add_row("Inventory tracked", str(payload.get("inventory_tracked", payload.get("inventory")) or 0))
    body.add_row("Receipts stored", str(payload.get("receipts_stored") or 0))
    body.add_row("Advisories stored", str(payload.get("advisories_stored") or 0))
    remote_policies_stored = payload.get("remote_policies_stored")
    exceptions_stored = payload.get("exceptions_stored")
    pain_signals_uploaded = payload.get("pain_signals_uploaded")
    if remote_policies_stored is not None:
        body.add_row("Remote policies", str(remote_policies_stored or 0))
    if exceptions_stored is not None:
        body.add_row("Exceptions stored", str(exceptions_stored or 0))
    if pain_signals_uploaded is not None:
        body.add_row("Pain signals uploaded", str(pain_signals_uploaded or 0))
    console.print(Panel(body, title="Guard sync complete", border_style="green"))
    ecosystem_support = _coerce_dict_list(payload.get("ecosystem_support"))
    if ecosystem_support:
        console.print(_build_ecosystem_support_table(ecosystem_support))


def _managed_install_state_text(managed_install: dict[str, object]) -> str:
    return "Installed" if bool(managed_install.get("active")) else "Removed"


def _build_ecosystem_support_table(items: list[dict[str, object]]) -> Table:
    table = Table(title="Ecosystem support", box=box.SIMPLE_HEAVY, show_header=True)
    table.add_column("Ecosystem", style="bold")
    table.add_column("Coverage")
    for item in items:
        table.add_row(
            str(item.get("display_name") or item.get("ecosystem") or "unknown"),
            str(item.get("support_label") or "Monitor-only"),
        )
    return table


def _managed_install_mode_text(mode: object) -> str | None:
    if not isinstance(mode, str) or not mode.strip():
        return None
    normalized = mode.strip().lower()
    if normalized in _KNOWN_MANAGED_INSTALL_MODES:
        return _KNOWN_MANAGED_INSTALL_MODES[normalized]
    words = []
    for part in normalized.split("-"):
        lowered = part.lower()
        if lowered in _MODE_ACRONYMS:
            words.append(lowered.upper())
        else:
            words.append(lowered.capitalize())
    return " ".join(words)


def _managed_install_notes(managed_install: dict[str, object], manifest: object) -> list[str]:
    if not isinstance(manifest, dict):
        if not bool(managed_install.get("active")):
            return ["Guard removed the managed wrapper configuration for this harness."]
        return []
    notes = _coerce_string_list(manifest.get("notes"))
    skipped_servers = _coerce_string_list(manifest.get("skipped_servers"))
    if skipped_servers:
        notes.append(f"Skipped existing server entries: {', '.join(skipped_servers)}")
    source_config_paths = _coerce_string_list(manifest.get("source_config_paths"))
    if source_config_paths:
        notes.append(f"Source configs: {', '.join(source_config_paths)}")
    if not notes and not bool(managed_install.get("active")):
        notes.append("Guard removed the managed wrapper configuration for this harness.")
    return notes


def _render_update(console: Console, payload: dict[str, object]) -> None:
    body = Table.grid(padding=(0, 1))
    body.add_row("Current version", str(payload.get("current_version") or "unknown"))
    body.add_row("Installer", str(payload.get("installer") or "unknown"))
    command = payload.get("command")
    if isinstance(command, list) and command:
        body.add_row("Command", " ".join(str(part) for part in command))
    body.add_row("Dry run", _bool_label(bool(payload.get("dry_run"))))
    version_check = payload.get("version_check")
    if isinstance(version_check, dict):
        latest_version = version_check.get("latest_version")
        if isinstance(latest_version, str) and latest_version.strip():
            body.add_row("Latest PyPI version", latest_version.strip())
    if payload.get("resulting_version"):
        body.add_row("Resulting version", str(payload.get("resulting_version")))
    if payload.get("editable_install") is not None:
        body.add_row("Editable install", _bool_label(bool(payload.get("editable_install"))))
    if payload.get("changed") is not None:
        body.add_row("Changed", _bool_label(bool(payload.get("changed"))))
    if payload.get("message"):
        body.add_row("Message", str(payload.get("message")))
    status = str(payload.get("status") or "unknown")
    border_style = {
        "planned": "blue",
        "current": "blue",
        "stale": "yellow",
        "blocked": "red",
        "updated": "green",
        "skipped": "yellow",
        "failed": "red",
    }.get(status, "red")
    console.print(Panel(body, title=f"Guard update: {status}", border_style=border_style))
    notes = _coerce_string_list(payload.get("notes"))
    stdout = str(payload.get("stdout") or "").strip()
    stderr = str(payload.get("stderr") or "").strip()
    error = str(payload.get("error") or "").strip()
    if notes:
        console.print(Panel("\n".join(f"• {note}" for note in notes), title="Notes", border_style="blue"))
    if status in {"updated", "failed"} and stdout and stdout != str(payload.get("message") or "").strip():
        console.print(Panel(stdout, title="stdout", border_style="green"))
    if status == "failed" and stderr:
        console.print(Panel(stderr, title="stderr", border_style="yellow"))
    if error:
        console.print(Panel(error, title="error", border_style="red"))
    if payload.get("managed_install") or payload.get("managed_installs"):
        _render_managed_install(console, payload)


def _connect_status_text(payload: dict[str, object]) -> str:
    status = str(payload.get("status") or "unknown")
    milestone = str(payload.get("milestone") or "")
    if status == "connected" and milestone == "sync_not_available":
        return "This device is protected locally"
    if status == "connected" and milestone == "first_sync_pending":
        reason = _connect_reason_text(payload)
        if _connect_reason_requires_login(reason) or _connect_reason_requires_paid_plan(reason):
            return "This device is protected locally"
        return "This device is connected"
    if status == "connected" and milestone == "first_sync_succeeded":
        return "This device is connected to Guard Cloud"
    if status == "waiting":
        return "Browser approval pending"
    if status == "retry_required":
        return "Retry required"
    if status == "expired":
        return "Expired"
    return status


def _connect_milestone_text(payload: dict[str, object]) -> str:
    milestone = str(payload.get("milestone") or "")
    if milestone == "waiting_for_browser":
        return "Waiting for browser approval"
    if milestone == "sync_not_available":
        return "Upgrade to sync this device to Guard Cloud"
    if milestone == "first_sync_pending":
        reason = _connect_reason_text(payload)
        if _connect_reason_requires_login(reason):
            return "Sign in to finish Guard Cloud setup"
        if _connect_reason_requires_paid_plan(reason):
            return "Upgrade to sync this device to Guard Cloud"
        return "First Guard Cloud proof is on the way"
    if milestone == "first_sync_succeeded":
        return "Guard Cloud is tracking this device"
    if milestone == "first_sync_failed":
        return "First shared proof needs another try"
    if milestone == "expired":
        return "The request expired before pairing finished"
    return milestone.replace("_", " ")


def _connect_reason_text(payload: dict[str, object]) -> str:
    return str(payload.get("reason") or payload.get("sync_message") or "").strip().lower()


def _connect_reason_requires_login(reason: str) -> bool:
    return any(
        marker in reason
        for marker in (
            "not logged in",
            "sign in",
            "logged out",
            "login",
            "logout",
            "unauthorized",
            "401",
            "reauthoriz",
        )
    )


def _connect_reason_requires_paid_plan(reason: str) -> bool:
    return any(
        marker in reason
        for marker in (
            "paid guard plan",
            "paid plan",
            "guard plan required",
            "pro or team plan",
            "requires a pro",
            "requires a team",
            "upgrade your plan",
            "upgrade to",
            "subscription required",
            "not included in your plan",
            "guard sync requires",
        )
    )


def _connect_sync_note_text(payload: dict[str, object]) -> str | None:
    message = str(payload.get("sync_message") or "").strip()
    if not message:
        return None
    reason = message.lower()
    if _connect_reason_requires_login(reason):
        return "Local protection is active. Sign in on the Guard connect page to finish Guard Cloud setup."
    if _connect_reason_requires_paid_plan(reason):
        return (
            "Local protection is active. Upgrade your Guard plan to sync shared "
            "proof, receipts, and Fleet history to Guard Cloud."
        )
    return message


def _render_hook(console: Console, payload: dict[str, object]) -> None:
    body = Table.grid(padding=(0, 1))
    body.add_row("Recorded", _bool_label(bool(payload.get("recorded"))))
    body.add_row("Artifact", str(payload.get("artifact_name") or payload.get("artifact_id") or "unknown"))
    body.add_row("Decision", _action_text(str(payload.get("policy_action", "warn"))))
    if payload.get("risk_summary"):
        body.add_row("Why", str(payload.get("risk_summary")))
    if payload.get("path_summary"):
        body.add_row("Path", str(payload.get("path_summary")))
    if payload.get("approval_center_url"):
        body.add_row("Approval center", str(payload.get("approval_center_url")))
    if payload.get("review_hint"):
        body.add_row("Review", str(payload.get("review_hint")))
    console.print(Panel(body, title="Guard hook event", border_style="cyan"))


def _cisco_status_text(status: str) -> Text:
    styles = {
        "enabled": "green",
        "skipped": "yellow",
        "unavailable": "yellow",
        "failed": "red",
    }
    return Text(status, style=styles.get(status, "white"))


def _render_cisco_evidence(console: Console, payload: dict[str, object]) -> None:
    cisco_evidence = payload.get("cisco_evidence")
    if not isinstance(cisco_evidence, dict):
        return
    body = Table.grid(padding=(0, 1))
    body.add_row("Mode", str(cisco_evidence.get("mode", "offline-only")).replace("-", " "))
    body.add_row("Status", _cisco_status_text(str(cisco_evidence.get("status", "skipped"))))
    body.add_row("Findings", str(cisco_evidence.get("finding_count", 0)))
    body.add_row("Targets", str(cisco_evidence.get("target_count", 0)))
    body.add_row("Summary", str(cisco_evidence.get("summary", "No Cisco MCP evidence collected.")))
    for integration in _coerce_dict_list(cisco_evidence.get("integrations")):
        body.add_row(
            str(integration.get("name", "cisco-mcp-scanner")),
            str(integration.get("message", "No Cisco MCP detail available.")),
        )
    console.print(Panel(body, title="Cisco static scan evidence", border_style="blue"))


def _build_consumer_summary_table(payload: dict[str, object]) -> Table:
    recommendation = payload.get("policy_recommendation")
    manifest = payload.get("capability_manifest")
    threat_intelligence = payload.get("threat_intelligence")
    evidence_bundle = payload.get("trust_evidence_bundle")
    provenance_record = payload.get("provenance_record")
    artifact_snapshot = payload.get("artifact_snapshot")
    artifact_path = "."
    if isinstance(artifact_snapshot, dict):
        artifact_path = str(artifact_snapshot.get("path") or artifact_snapshot.get("artifact_path") or ".")
    artifact_name = Path(artifact_path).name or artifact_path
    ecosystems = _coerce_string_list(manifest.get("ecosystems")) if isinstance(manifest, dict) else []
    categories = _coerce_string_list(manifest.get("category_names")) if isinstance(manifest, dict) else []
    packages = _coerce_dict_list(manifest.get("packages")) if isinstance(manifest, dict) else []
    severity_counts = (
        evidence_bundle.get("severity_counts")
        if isinstance(evidence_bundle, dict) and isinstance(evidence_bundle.get("severity_counts"), dict)
        else {}
    )
    body = Table.grid(padding=(0, 1))
    body.add_row("Name", artifact_name)
    body.add_row("Artifact", artifact_path)
    body.add_row("Ecosystems", ", ".join(ecosystems) or "unknown")
    if categories:
        body.add_row("Categories", ", ".join(categories))
    if packages:
        body.add_row("Packages", str(len(packages)))
    if isinstance(recommendation, dict):
        body.add_row("Recommended action", _action_text(str(recommendation.get("action", "review"))))
        body.add_row("Reason", str(recommendation.get("reason") or "No recommendation detail provided."))
    if isinstance(threat_intelligence, dict):
        body.add_row("Highest severity", str(threat_intelligence.get("highest_severity") or "info"))
        body.add_row("Finding count", str(threat_intelligence.get("finding_count") or 0))
    elif severity_counts:
        body.add_row(
            "Findings",
            ", ".join(f"{key}:{value}" for key, value in severity_counts.items() if value) or "none",
        )
    if isinstance(provenance_record, dict) and provenance_record.get("trust_score") is not None:
        body.add_row("Trust score", str(provenance_record.get("trust_score")))
    return body


def _render_consumer_evidence_panels(console: Console, payload: dict[str, object]) -> None:
    evidence_bundle = payload.get("trust_evidence_bundle")
    if isinstance(evidence_bundle, dict):
        severity_counts = evidence_bundle.get("severity_counts")
        integrations = _coerce_dict_list(evidence_bundle.get("integrations"))
        summary = Table.grid(padding=(0, 1))
        if isinstance(severity_counts, dict):
            summary.add_row(
                "By severity",
                ", ".join(f"{key}:{value}" for key, value in severity_counts.items() if value) or "none",
            )
        if integrations:
            summary.add_row(
                "Integrations",
                ", ".join(
                    str(item.get("name") or "integration") for item in integrations if item.get("name") is not None
                )
                or "none",
            )
        if summary.row_count > 0:
            console.print(Panel(summary, title="Evidence summary", border_style="yellow"))
        findings = _coerce_string_list(evidence_bundle.get("findings"))
        if findings:
            console.print(
                Panel(
                    "\n".join(f"• {item}" for item in findings[:5]),
                    title="Evidence highlights",
                    border_style="yellow",
                )
            )


def _render_scan(console: Console, payload: dict[str, object]) -> None:
    console.print(Panel(_build_consumer_summary_table(payload), title="Consumer scan", border_style="cyan"))
    _render_consumer_evidence_panels(console, payload)
    _render_cisco_evidence(console, payload)


def _render_deep_scan(console: Console, payload: dict[str, object]) -> None:
    scan_type = str(payload.get("scan_type") or "unknown")
    status = str(payload.get("status") or "unknown")
    body = Table.grid(padding=(0, 1))
    body.add_row("Type", scan_type)
    body.add_row("Status", _cisco_status_text(status))
    body.add_row("Mode", str(payload.get("mode") or "auto"))
    body.add_row("Findings", str(payload.get("finding_count") or 0))
    body.add_row("Targets", str(payload.get("targets_scanned") or 0))
    body.add_row("Analyzers", str(payload.get("analyzers_used") or 0))
    if payload.get("message"):
        body.add_row("Message", str(payload["message"]))
    console.print(Panel(body, title=f"Deep scan — {scan_type}", border_style="cyan"))
    findings = _coerce_dict_list(payload.get("scanner_evidence") or payload.get("findings"))
    if findings:
        table = Table(box=box.SIMPLE_HEAVY, show_header=True)
        table.add_column("Severity", style="bold")
        table.add_column("Title")
        table.add_column("Category")
        for finding in findings[:50]:
            sev = str(finding.get("severity") or "info")
            table.add_row(
                sev,
                str(finding.get("title") or finding.get("rule_id") or "unknown"),
                str(finding.get("category") or ""),
            )
        if len(findings) > 50:
            table.add_row("…", f"and {len(findings) - 50} more", "")
        console.print(table)


def _render_explain(console: Console, payload: dict[str, object]) -> None:
    advisories = _coerce_dict_list(payload.get("advisories"))
    if "artifact_snapshot" in payload:
        console.print(Panel(_build_consumer_summary_table(payload), title="Path evidence", border_style="cyan"))
        _render_consumer_evidence_panels(console, payload)
        _render_cisco_evidence(console, payload)
        if advisories:
            console.print(_build_advisory_table(advisories, title="Matching advisories"))
        return
    artifact = payload.get("artifact")
    if not isinstance(artifact, dict):
        _render_fallback(console, payload)
        return
    latest_receipt = payload.get("latest_receipt")
    latest_diff = payload.get("latest_diff")
    body = Table.grid(padding=(0, 1))
    body.add_row("Artifact", str(artifact.get("artifact_name") or artifact.get("artifact_id") or "unknown"))
    body.add_row("Harness", str(artifact.get("harness") or "unknown"))
    body.add_row("Type", str(artifact.get("artifact_type") or "artifact"))
    body.add_row("Scope", str(artifact.get("source_scope") or "unknown"))
    body.add_row("Present", _bool_label(bool(artifact.get("present"))))
    if isinstance(latest_receipt, dict):
        body.add_row("Latest decision", _action_text(str(latest_receipt.get("policy_decision") or "warn")))
        body.add_row("Receipt time", str(latest_receipt.get("timestamp") or "unknown"))
    if isinstance(latest_diff, dict):
        changed_fields = ", ".join(_coerce_string_list(latest_diff.get("changed_fields"))) or "no field changes"
        body.add_row("Latest diff", changed_fields)
        body.add_row("Current hash", str(latest_diff.get("current_hash") or "unknown"))
    body.add_row("Advisories", str(len(advisories)))
    console.print(Panel(body, title="Guard artifact evidence", border_style="cyan"))
    if advisories:
        console.print(_build_advisory_table(advisories, title="Matching advisories"))


def _render_preflight(console: Console, payload: dict[str, object]) -> None:
    install_verdict = payload.get("install_verdict")
    install_target = payload.get("install_target")
    body = Table.grid(padding=(0, 1))
    if isinstance(install_target, dict):
        body.add_row("Target", str(install_target.get("path") or "."))
        body.add_row("Harness", str(install_target.get("intended_harness") or "not specified"))
    if isinstance(install_verdict, dict):
        body.add_row("Install verdict", _action_text(str(install_verdict.get("action") or "review")))
        body.add_row("Can install", _bool_label(bool(install_verdict.get("can_install"))))
        body.add_row("Reason", str(install_verdict.get("reason") or "unknown"))
    threat_intelligence = payload.get("threat_intelligence")
    if isinstance(threat_intelligence, dict):
        body.add_row("Verdict source", str(threat_intelligence.get("verdict_source") or "local-scan"))
        body.add_row("Highest severity", str(threat_intelligence.get("highest_severity") or "info"))
        body.add_row("Findings", str(threat_intelligence.get("finding_count") or 0))
    console.print(Panel(body, title="Install-time preflight", border_style="cyan"))
    console.print(Panel(_build_consumer_summary_table(payload), title="Artifact scan", border_style="blue"))
    _render_consumer_evidence_panels(console, payload)
    _render_cisco_evidence(console, payload)


def _render_protect(console: Console, payload: dict[str, object]) -> None:
    if str(payload.get("mode") or "") == "status":
        body = Table.grid(padding=(0, 1))
        body.add_row("Mode", "status")
        console.print(Panel(body, title="Install protection", border_style="cyan"))
        supply_chain = payload.get("supply_chain")
        if isinstance(supply_chain, dict):
            console.print(_build_supply_chain_posture_panel(supply_chain))
        return
    verdict = payload.get("verdict")
    request = payload.get("request")
    body = Table.grid(padding=(0, 1))
    if isinstance(request, dict):
        body.add_row("Command", _command_text(request.get("command")))
        body.add_row("Kind", str(request.get("install_kind") or "unknown"))
    if isinstance(verdict, dict):
        action = str(verdict.get("action") or "review")
        body.add_row("Action", _action_text(action))
        body.add_row("Executed", _bool_label(bool(payload.get("executed"))))
        body.add_row("Reason", str(verdict.get("reason") or "unknown"))
    console.print(Panel(body, title="Install protection", border_style="cyan"))
    supply_chain_evaluation = payload.get("supply_chain_evaluation")
    if isinstance(supply_chain_evaluation, dict):
        user_copy = supply_chain_evaluation.get("user_copy")
        if isinstance(user_copy, dict):
            harness_message = str(user_copy.get("harness_message") or "").strip()
            if harness_message:
                console.print(
                    Panel(
                        Text(harness_message, no_wrap=False, overflow="fold"),
                        title="Guard guidance",
                        border_style="magenta",
                    )
                )
    supply_chain = payload.get("supply_chain")
    if isinstance(supply_chain, dict):
        console.print(_build_supply_chain_posture_panel(supply_chain))
    risk_signals = _coerce_string_list(verdict.get("risk_signals")) if isinstance(verdict, dict) else []
    if risk_signals:
        console.print(
            Panel(
                "\n".join(f"• {item}" for item in risk_signals),
                title="Risk signals",
                border_style="yellow",
            )
        )
    targets = _coerce_dict_list(payload.get("targets"))
    if targets:
        table = Table(box=box.SIMPLE_HEAVY, show_header=True)
        table.add_column("Target", style="bold")
        table.add_column("Type")
        table.add_column("Ecosystem")
        table.add_column("Spec")
        for item in targets:
            table.add_row(
                str(item.get("artifact_name") or "unknown"),
                str(item.get("artifact_type") or "artifact"),
                str(item.get("ecosystem") or "unknown"),
                str(item.get("raw_spec") or item.get("package_name") or "unknown"),
            )
        console.print(table)


def _render_fallback(console: Console, payload: dict[str, object]) -> None:
    console.print(
        Syntax(
            _render_redacted_json_payload(payload),
            "json",
            theme="ansi_dark",
            word_wrap=True,
        )
    )


def _build_supply_chain_posture_panel(supply_chain: dict[str, object]) -> Panel:
    body = Table.grid(padding=(0, 1))
    body.add_row("Status", str(supply_chain.get("status") or "unknown"))
    body.add_row(
        "Protection",
        str(supply_chain.get("health_status") or supply_chain.get("status") or "unknown"),
    )
    detail = supply_chain.get("detail")
    if detail:
        body.add_row("Detail", str(detail))
    bundle = supply_chain.get("bundle")
    if isinstance(bundle, dict):
        if bundle.get("bundle_version"):
            body.add_row("Bundle", str(bundle.get("bundle_version")))
        if bundle.get("tier"):
            body.add_row("Tier", str(bundle.get("tier")))
        if bundle.get("workspace_id"):
            body.add_row("Workspace", str(bundle.get("workspace_id")))
        if bundle.get("next_refresh_at"):
            body.add_row("Next refresh", str(bundle.get("next_refresh_at")))
    policy = supply_chain.get("policy")
    if isinstance(policy, dict):
        body.add_row("Security", str(policy.get("security_level") or "unknown"))
        body.add_row("Cloud advisories", str(policy.get("cloud_advisory_action") or "unknown"))
    ecosystems = _coerce_dict_list(supply_chain.get("supported_ecosystems"))
    if ecosystems:
        support_summary = ", ".join(
            f"{item.get('display_name') or item.get('ecosystem')}: {item.get('support_label') or item.get('label')}"
            for item in ecosystems[:5]
        )
        if len(ecosystems) > 5:
            support_summary = f"{support_summary}, +{len(ecosystems) - 5} more"
        body.add_row("Coverage", support_summary)
    return Panel(body, title="Supply-chain firewall", border_style="cyan")


def _build_harness_table(detections: list[dict[str, object]]) -> Table:
    table = Table(box=box.SIMPLE_HEAVY, show_header=True)
    table.add_column("Harness", style="bold")
    table.add_column("Status")
    table.add_column("Command")
    table.add_column("Artifacts", justify="right")
    table.add_column("Warnings", justify="right")
    for detection in detections:
        table.add_row(
            str(detection.get("harness", "unknown")),
            _status_text(detection),
            _bool_label(bool(detection.get("command_available"))),
            str(len(_coerce_dict_list(detection.get("artifacts")))),
            str(_warning_count(detection)),
        )
    return table


def _build_product_table(harnesses: list[dict[str, object]]) -> Table:
    table = Table(box=box.SIMPLE_HEAVY, show_header=True)
    table.add_column("Harness", style="bold")
    table.add_column("Managed")
    table.add_column("Artifacts", justify="right")
    table.add_column("Review", justify="right")
    table.add_column("Recommended action")
    for harness in harnesses:
        table.add_row(
            str(harness.get("harness", "unknown")),
            _bool_label(bool(harness.get("managed"))),
            str(harness.get("artifact_count", 0)),
            str(harness.get("review_count", 0)),
            _next_action_label(harness),
        )
    return table


def _next_action_label(harness: dict[str, object]) -> str:
    next_action = str(harness.get("next_action") or "install")
    review_count = _coerce_int(harness.get("review_count"))
    if next_action == "install-harness":
        return "Install harness first"
    if next_action == "install":
        return "Install Guard"
    if next_action == "review":
        return f"Review {review_count} change{'s' if review_count != 1 else ''}"
    if next_action == "run":
        return "Run through Guard"
    return next_action.replace("-", " ").strip() or "Check status"


def _build_steps_panel(steps: Sequence[PayloadMapping]) -> Panel:
    lines = []
    for step in steps:
        title = str(step.get("title", "Next step"))
        command = str(step.get("command", ""))
        detail = str(step.get("detail", ""))
        lines.append(f"[bold]{title}[/bold]\n  {command}\n  {detail}")
    return Panel("\n\n".join(lines), title="Next steps", border_style="green")


def _build_diagnostic_command_panel() -> Panel:
    return Panel(
        "\n".join(
            (
                "Use status for current posture: hol-guard status",
                "Use doctor for setup and runtime probes: hol-guard doctor <harness>",
                "Use diff for changed artifacts: hol-guard diff <harness>",
                "Use events for the local timeline: hol-guard events",
            )
        ),
        title="Which diagnostic command?",
        border_style="blue",
    )


def _render_harness_detail(console: Console, detection: dict[str, object]) -> None:
    artifacts = _coerce_dict_list(detection.get("artifacts"))
    warnings = _coerce_string_list(detection.get("warnings"))
    if not artifacts and not warnings:
        return
    body = Table.grid(padding=(0, 1))
    body.add_row("Status", _status_text(detection))
    config_paths = _coerce_string_list(detection.get("config_paths"))
    body.add_row("Config", "\n".join(_short_path(path) for path in config_paths) or "none")
    if warnings:
        body.add_row("Warnings", "\n".join(f"• {warning}" for warning in warnings))
    console.print(Panel(body, title=str(detection.get("harness", "unknown")), border_style="blue"))
    if artifacts:
        console.print(_build_artifact_table(artifacts))


def _build_artifact_table(artifacts: list[dict[str, object]]) -> Table:
    table = Table(box=box.SIMPLE_HEAVY, show_header=True)
    table.add_column("Artifact", style="bold")
    table.add_column("Type")
    table.add_column("Scope")
    table.add_column("Transport")
    table.add_column("Source")
    for artifact in artifacts:
        table.add_row(
            str(artifact.get("name") or artifact.get("artifact_id") or "unknown"),
            str(artifact.get("artifact_type") or "unknown"),
            str(artifact.get("source_scope") or "unknown"),
            str(artifact.get("transport") or "config"),
            _artifact_source_text(artifact),
        )
    return table


def _build_artifact_result_table(artifacts: list[dict[str, object]]) -> Table:
    table = Table(box=box.SIMPLE_HEAVY, show_header=True)
    table.add_column("Artifact", style="bold")
    table.add_column("Changed")
    table.add_column("Policy")
    table.add_column("Fields")
    table.add_column("Risk")
    for artifact in artifacts:
        table.add_row(
            str(artifact.get("artifact_name") or artifact.get("artifact_id") or "unknown"),
            _bool_label(bool(artifact.get("changed"))),
            _action_text(str(artifact.get("policy_action", "warn"))),
            ", ".join(_coerce_string_list(artifact.get("changed_fields"))) or "none",
            str(artifact.get("risk_summary") or "no obvious secret/network signal"),
        )
    return table


def _build_run_artifact_table(artifacts: list[dict[str, str]]) -> Table:
    table = Table(title="What changed", box=box.SIMPLE_HEAVY, show_header=True)
    table.add_column("Artifact", style="bold")
    table.add_column("Guard saw")
    table.add_column("Reason")
    table.add_column("Risk")
    for artifact in artifacts:
        table.add_row(
            artifact["artifact_name"],
            artifact["change_summary"],
            artifact["reason_summary"],
            artifact["risk_summary"],
        )
    return table


def _run_title(*, blocked: bool, dry_run: bool) -> str:
    if blocked and dry_run:
        return "Dry run paused for review"
    if blocked:
        return "Blocked before launch"
    if dry_run:
        return "Dry run complete"
    return "Launch allowed"


def _run_outcome_text(*, blocked: bool, dry_run: bool, launched: bool) -> str:
    if blocked and dry_run:
        return "Guard found artifacts that need review before a real launch."
    if blocked:
        return "Guard paused the launch until you review the artifacts that need attention."
    if dry_run:
        return "Guard reviewed the current config without launching the harness."
    if launched:
        return "Guard approved the launch and handed control to the harness."
    return "Guard finished the check without launching the harness."


def _build_run_steps(payload: dict[str, object], *, blocked: bool, dry_run: bool) -> list[dict[str, str]]:
    harness = str(payload.get("harness") or "codex")
    authority_error = payload.get("authority_error")
    if isinstance(authority_error, str) and authority_error:
        return [
            {
                "title": "Repair and rescan Guard authority",
                "command": f"hol-guard doctor {harness}",
                "detail": (
                    "Guard refused to use contradictory decision fields. Diagnose or repair the local Guard "
                    "installation, then retry the original guarded command."
                ),
            }
        ]
    approval_center_url = payload.get("approval_center_url")
    review_hint = payload.get("review_hint")
    rerun_command = payload.get("rerun_command")
    diff_command = payload.get("diff_command")
    approvals_command = payload.get("approvals_command")
    if blocked and dry_run:
        review_command = (
            str(rerun_command) if isinstance(rerun_command, str) and rerun_command else f"hol-guard run {harness}"
        )
        inspect_command = (
            str(diff_command) if isinstance(diff_command, str) and diff_command else f"hol-guard diff {harness}"
        )
        review_detail = (
            str(review_hint)
            if isinstance(review_hint, str) and review_hint
            else "Rerun without --dry-run to review the full blocker set and continue into the harness launch."
        )
        steps = [
            {
                "title": "Resolve the blocked launch",
                "command": review_command,
                "detail": review_detail,
            },
        ]
        if approval_center_url:
            approval_command = (
                str(approvals_command)
                if isinstance(approvals_command, str) and approvals_command
                else "hol-guard approvals"
            )
            steps.append(
                {
                    "title": "Open the approvals queue",
                    "command": approval_command,
                    "detail": (
                        "Review any queued approval requests after the prompt appears, then retry the guarded command."
                    ),
                }
            )
        steps.append(
            {
                "title": "Inspect only the changed config entries (optional)",
                "command": inspect_command,
                "detail": (
                    "See the config-level diff only. This view can omit policy-only blockers "
                    "Guard still needs you to review."
                ),
            },
        )
        return steps
    if blocked and isinstance(review_hint, str) and review_hint:
        if approval_center_url:
            command = (
                str(approvals_command)
                if isinstance(approvals_command, str) and approvals_command
                else "hol-guard approvals"
            )
        elif isinstance(rerun_command, str) and rerun_command:
            command = str(rerun_command)
        else:
            command = f"hol-guard run {harness}"
        return [{"title": "Resolve the blocked launch", "command": command, "detail": review_hint}]
    if dry_run:
        launch_command = (
            str(rerun_command) if isinstance(rerun_command, str) and rerun_command else f"hol-guard run {harness}"
        )
        return [
            {
                "title": "Launch for real",
                "command": launch_command,
                "detail": "Dry run finished cleanly; rerun without --dry-run when you are ready to launch.",
            }
        ]
    return []


def _summarize_run_artifacts(artifacts: list[dict[str, object]]) -> list[dict[str, str]]:
    summarized: list[dict[str, str]] = []
    used_indexes: set[int] = set()
    for index, artifact in enumerate(artifacts):
        if index in used_indexes:
            continue
        partner_index = _find_replaced_artifact_partner(artifacts, index, used_indexes)
        if partner_index is not None:
            used_indexes.add(index)
            used_indexes.add(partner_index)
            primary, secondary = _replacement_pair(artifact, artifacts[partner_index])
            summarized.append(
                {
                    "artifact_name": _artifact_display_name(primary),
                    "change_summary": "definition replaced",
                    "reason_summary": (
                        "Guard saw the previous definition disappear and a new definition with the same name appear, "
                        "so it is asking for a fresh approval."
                    ),
                    "risk_summary": _artifact_risk_text(primary, secondary),
                    "policy_action": str(primary.get("policy_action") or "review"),
                }
            )
            continue
        used_indexes.add(index)
        summarized.append(
            {
                "artifact_name": _artifact_display_name(artifact),
                "change_summary": _artifact_change_summary(artifact),
                "reason_summary": _artifact_reason_text(artifact),
                "risk_summary": _artifact_risk_text(artifact),
                "policy_action": str(artifact.get("policy_action") or "review"),
            }
        )
    return summarized


def _find_replaced_artifact_partner(
    artifacts: list[dict[str, object]],
    index: int,
    used_indexes: set[int],
) -> int | None:
    artifact = artifacts[index]
    fields = set(_coerce_string_list(artifact.get("changed_fields")))
    if fields not in ({"first_seen"}, {"removed"}):
        return None
    target_fields = {"removed"} if fields == {"first_seen"} else {"first_seen"}
    artifact_name = _artifact_display_name(artifact)
    policy_action = str(artifact.get("policy_action") or "")
    artifact_label = str(artifact.get("artifact_label") or "")
    artifact_identity = _artifact_replacement_identity(artifact)
    for partner_index in range(index + 1, len(artifacts)):
        if partner_index in used_indexes:
            continue
        partner = artifacts[partner_index]
        if _artifact_display_name(partner) != artifact_name:
            continue
        if set(_coerce_string_list(partner.get("changed_fields"))) != target_fields:
            continue
        if policy_action and str(partner.get("policy_action") or "") != policy_action:
            continue
        if artifact_label and str(partner.get("artifact_label") or "") != artifact_label:
            continue
        if _artifact_replacement_identity(partner) != artifact_identity:
            continue
        return partner_index
    return None


def _replacement_pair(
    first: dict[str, object],
    second: dict[str, object],
) -> tuple[dict[str, object], dict[str, object]]:
    if set(_coerce_string_list(first.get("changed_fields"))) == {"first_seen"}:
        return first, second
    return second, first


def _artifact_display_name(artifact: dict[str, object]) -> str:
    return str(artifact.get("artifact_name") or artifact.get("artifact_id") or "unknown")


def _artifact_replacement_identity(artifact: dict[str, object]) -> tuple[tuple[str, str], ...]:
    identity_keys = ("source_scope", "config_path", "publisher")
    identity: list[tuple[str, str]] = []
    for key in identity_keys:
        value = artifact.get(key)
        if value in (None, ""):
            continue
        identity.append((key, str(value)))
    return tuple(identity)


def _artifact_change_summary(artifact: dict[str, object]) -> str:
    fields = set(_coerce_string_list(artifact.get("changed_fields")))
    if fields == {"first_seen"}:
        return "new artifact"
    if fields == {"removed"}:
        return "removed from config"
    if "prompt_request" in fields:
        return "prompt requested secret access"
    if "file_read_request" in fields:
        return "protected file read requested"
    if "command" in fields or "args" in fields:
        return "launch command changed"
    if "url" in fields or "transport" in fields:
        return "connection target changed"
    if "publisher" in fields or "source_scope" in fields:
        return "publisher or source changed"
    if "env_keys" in fields:
        return "environment access changed"
    labels = [_field_label(field) for field in _coerce_string_list(artifact.get("changed_fields"))]
    if not labels:
        return "no material change"
    if len(labels) == 1:
        return f"{labels[0]} changed"
    if len(labels) == 2:
        return f"{labels[0]} and {labels[1]} changed"
    return "multiple settings changed"


def _field_label(field: str) -> str:
    labels = {
        "artifact_type": "artifact type",
        "args": "launch arguments",
        "command": "launch command",
        "config_path": "config location",
        "env_keys": "environment access",
        "publisher": "publisher",
        "source_scope": "source scope",
        "transport": "transport",
        "url": "remote endpoint",
    }
    return labels.get(field, field.replace("_", " "))


def _artifact_reason_text(artifact: dict[str, object]) -> str:
    reason = artifact.get("why_now")
    if isinstance(reason, str) and reason:
        return reason
    policy_action = str(artifact.get("policy_action") or "review")
    if policy_action == "allow":
        return "Guard matched an existing allow rule for this exact definition."
    if policy_action == "block":
        return "Guard blocked this definition because the configured policy does not trust it yet."
    if policy_action == "sandbox-required":
        return "Guard requires extra isolation before this launch can continue."
    return "Guard found a meaningful config change and paused the launch for review."


def _artifact_risk_text(*artifacts: dict[str, object]) -> str:
    for artifact in artifacts:
        for key in ("risk_summary", "risk_headline"):
            value = artifact.get(key)
            if isinstance(value, str) and value:
                return value
    return "No obvious secret-access or network signal was detected in the launch definition."


def _run_artifact_should_be_visible(artifact: dict[str, object]) -> bool:
    if bool(artifact.get("changed")):
        return True
    return str(artifact.get("policy_action") or "allow") in {
        "review",
        "require-reapproval",
        "sandbox-required",
        "block",
    }


def _artifact_needs_review(artifact: dict[str, object]) -> bool:
    return str(artifact.get("policy_action") or "allow") in {
        "review",
        "require-reapproval",
        "sandbox-required",
        "block",
    }


def _build_approval_table(items: list[dict[str, object]], *, title: str | None) -> Table:
    table = Table(title=title, box=box.SIMPLE_HEAVY, show_header=True)
    table.add_column("Request", style="dim", no_wrap=True)
    table.add_column("Harness", style="cyan")
    table.add_column("Artifact", style="bold")
    table.add_column("Changed", style="magenta")
    table.add_column("Risk")
    table.add_column("Recommendation")
    table.add_column("Resolve", style="blue")
    if not items:
        table.add_row("—", "—", "No pending approvals", "—", "—", "—", "—")
        return table
    for item in items:
        approval_url = item.get("approval_url")
        fallback_cli = item.get("fallback_cli_command")
        review_cmd = str(item.get("review_command") or "hol-guard approvals")
        if approval_url and fallback_cli:
            resolve_text = f"{approval_url}\n  or: {fallback_cli}"
        elif approval_url:
            resolve_text = str(approval_url)
        else:
            resolve_text = review_cmd
        table.add_row(
            str(item.get("request_id") or "unknown"),
            str(item.get("harness") or "unknown"),
            str(item.get("artifact_name") or item.get("artifact_id") or "unknown"),
            ", ".join(_coerce_string_list(item.get("changed_fields"))) or "none",
            str(item.get("risk_summary") or "no obvious secret/network signal"),
            _action_text(str(item.get("policy_action") or "warn")),
            resolve_text,
        )
    return table


def _build_runtime_probe_panel(runtime_probe: dict[str, object]) -> Panel:
    body = Table.grid(padding=(0, 1))
    body.add_row("Command", _command_text(runtime_probe.get("command")))
    body.add_row("Succeeded", _bool_label(bool(runtime_probe.get("ok"))))
    if runtime_probe.get("return_code") is not None:
        body.add_row("Return code", str(runtime_probe.get("return_code")))
    if runtime_probe.get("reported_artifacts") is not None:
        body.add_row("CLI artifacts", str(runtime_probe.get("reported_artifacts")))
    if runtime_probe.get("stderr"):
        body.add_row("stderr", str(runtime_probe.get("stderr")))
    if runtime_probe.get("stdout"):
        stdout = _clean_terminal_output(str(runtime_probe.get("stdout")))
        preview = "\n".join(stdout.splitlines()[:6])
        body.add_row("stdout", preview)
    return Panel(body, title="Runtime probe", border_style="magenta")


def _build_cloud_summary_panel(payload: dict[str, object]) -> Panel:
    cloud_state = str(payload.get("cloud_state") or "local_only")
    body = Table.grid(padding=(0, 1))
    body.add_row("State", f"[bold]{payload.get('cloud_state_label', 'Local only')}[/bold]")
    body.add_row("Summary", str(payload.get("cloud_state_detail") or "Guard is protecting this machine locally."))
    body.add_row("Home", str(payload.get("dashboard_url") or "https://hol.org/guard"))
    if payload.get("inbox_url"):
        body.add_row("Inbox", str(payload.get("inbox_url")))
    if payload.get("fleet_url"):
        body.add_row("Fleet", str(payload.get("fleet_url")))
    body.add_row("Connect guide", str(payload.get("connect_url") or "https://hol.org/guard/connect"))
    if payload.get("sync_url"):
        body.add_row("Sync endpoint", str(payload.get("sync_url")))
    if payload.get("last_sync_at"):
        body.add_row("Last sync", str(payload.get("last_sync_at")))
    if payload.get("cloud_policy_bundle_version"):
        body.add_row("Cloud policy", str(payload.get("cloud_policy_bundle_version")))
    if payload.get("cloud_policy_bundle_hash"):
        body.add_row("Bundle hash", str(payload.get("cloud_policy_bundle_hash")))
    if payload.get("cloud_policy_rollout_state"):
        body.add_row("Rollout", str(payload.get("cloud_policy_rollout_state")))
    if payload.get("cloud_policy_sync_error"):
        body.add_row("Policy sync", str(payload.get("cloud_policy_sync_error")))
    body.add_row("Cached advisories", str(payload.get("advisory_count") or 0))
    if payload.get("advisory_headline"):
        body.add_row("Latest advisory", str(payload.get("advisory_headline")))
    if payload.get("team_policy_name"):
        body.add_row("Team policy", str(payload.get("team_policy_name")))
    elif payload.get("team_policy_active"):
        body.add_row("Team policy", "active")
    if payload.get("watchlist_enabled"):
        body.add_row("Watchlist", "enabled")
    if payload.get("team_alerts_enabled"):
        body.add_row("Team alerts", "enabled")
    return Panel(body, title="Local to cloud", border_style=_cloud_border_style(cloud_state))


def _cloud_border_style(cloud_state: str) -> str:
    if cloud_state == "paired_active":
        return "green"
    if cloud_state == "paired_waiting":
        return "yellow"
    return "cyan"


def _artifact_source_text(artifact: dict[str, object]) -> str:
    url = artifact.get("url")
    if isinstance(url, str) and url:
        return url
    command = artifact.get("command")
    args = _coerce_string_list(artifact.get("args"))
    if isinstance(command, str) and command:
        return " ".join([command, *args]).strip()
    return _short_path(str(artifact.get("config_path") or "unknown"))


def _status_label(detection: dict[str, object]) -> str:
    installed = bool(detection.get("installed"))
    command_available = bool(detection.get("command_available"))
    if installed and command_available:
        return "Ready"
    if installed:
        return "Config only"
    return "Not found"


def _status_text(detection: dict[str, object]) -> Text:
    label = _status_label(detection)
    style = {"Ready": "green", "Config only": "yellow", "Not found": "red"}[label]
    return Text(label, style=style)


def _warning_count(detection: dict[str, object]) -> int:
    return len(_coerce_string_list(detection.get("warnings")))


def _bool_label(value: bool) -> Text:
    return Text("yes" if value else "no", style="green" if value else "red")


def _action_text(action: str) -> Text:
    styles = {
        "allow": "green",
        "warn": "yellow",
        "review": "yellow",
        "require-reapproval": "magenta",
        "sandbox-required": "cyan",
        "block": "red",
    }
    return Text(action, style=styles.get(action, "white"))


def _command_text(command: object) -> str:
    if isinstance(command, list):
        return " ".join(str(item) for item in command)
    return str(command or "none")


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


def _coerce_int(value: object) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            return 0
        return int(value)
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return 0
        try:
            return int(stripped)
        except ValueError:
            return 0
    return 0


def _short_path(value: object) -> str:
    if not isinstance(value, str) or not value:
        return "unknown"
    path = Path(value)
    try:
        relative = path.expanduser().resolve().relative_to(Path.home().resolve())
    except ValueError:
        parts = path.parts[-3:]
        return str(Path(*parts)) if parts else value
    return f"~/{relative}"


def _timestamp_parts(value: object) -> tuple[str, str]:
    if not isinstance(value, str) or not value:
        return ("unknown", "--:--")
    normalized = value.replace("T", " ").replace("+00:00", "Z")
    return (normalized[:10], normalized[11:16])


def _clean_terminal_output(value: str) -> str:
    return re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", value)


_PLAIN_TEXT_RENDERERS: dict[str, PlainTextRenderer] = {
    "command-extensions": _plain_text_command_extensions,
    "command-inspection": _plain_text_command_inspection,
    "command-setup": _plain_text_command_setup,
    "protect": _plain_text_protect,
}


_RENDERERS: dict[str, Renderer] = {
    "command-extensions": _render_command_extensions,
    "command-inspection": _render_command_inspection,
    "command-setup": _render_command_setup,
    "approvals": _render_approvals,
    "init": _render_init,
    "start": _render_start,
    "status": _render_status,
    "dashboard": _render_dashboard,
    "connect": _render_connect,
    "bootstrap": _render_bootstrap,
    "detect": _render_detect,
    "doctor": _render_doctor,
    "trust.doctor": _render_trust_doctor,
    "trust.explain": _render_trust_explain,
    "run": _render_run,
    "diff": _render_diff,
    "receipts": _render_receipts,
    "inventory": _render_inventory,
    "policies": _render_policies,
    "exceptions": _render_policies,
    "advisories": _render_advisories,
    "events": _render_events,
    "abom": _render_fallback,
    "install": _render_managed_install,
    "uninstall": _render_managed_install,
    "apps": _render_apps,
    "allow": _render_decision,
    "deny": _render_decision,
    "login": _render_login,
    "sync": _render_sync,
    "supply-chain-explain": _render_fallback,
    "supply-chain-scan": _render_fallback,
    "supply-chain-sync": _render_fallback,
    "update": _render_update,
    "hook": _render_hook,
    "protect": _render_protect,
    "preflight": _render_preflight,
    "scan": _render_scan,
    "deep-scan": _render_deep_scan,
    "explain": _render_explain,
}
