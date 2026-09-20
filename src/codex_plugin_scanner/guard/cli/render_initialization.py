"""initialization presentation for Guard CLI output."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from .render import Console, Panel, PayloadMapping, Table
    from .render_context import RenderContext


def _render_detect(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    detections = view._coerce_dict_list(payload.get("harnesses"))
    total_artifacts = sum(len(view._coerce_dict_list(item.get("artifacts"))) for item in detections)
    attention_count = sum(
        1 for item in detections if view._status_label(item) != "Ready" or view._warning_count(item) > 0
    )
    console.print(
        view.Panel.fit(
            f"[bold]HOL Guard local harness status[/bold]\n"
            f"{len(detections)} harnesses • {total_artifacts} artifacts • {attention_count} need attention",
            border_style="cyan",
        )
    )
    console.print(view._build_harness_table(detections))
    for detection in detections:
        view._render_harness_detail(console, detection)
    if attention_count > 0:
        console.print(
            "[yellow]Run `hol-guard doctor <harness>` for harness-specific drift and runtime diagnostics.[/yellow]"
        )


def _render_start(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    harnesses = view._coerce_dict_list(payload.get("harnesses"))
    console.print(
        view.Panel.fit(
            f"[bold]HOL Guard first run[/bold]\n"
            f"{len(harnesses)} harnesses detected • {payload.get('receipt_count', 0)} receipts recorded • "
            f"{payload.get('pending_approvals', 0)} approvals waiting",
            border_style="cyan",
        )
    )
    console.print(view._build_cloud_summary_panel(payload))
    console.print(view._build_product_table(harnesses))
    if payload.get("approval_center_url"):
        console.print(f"Approval center: [bold]{payload.get('approval_center_url')}[/bold]")
    console.print(view._build_steps_panel(view._coerce_dict_list(payload.get("next_steps"))))


def _render_init(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    plan = view._coerce_dict_list(payload.get("plan"))
    if plan:
        console.print(view._init_plan_panel(plan, str(payload.get("status") or "initialized")))
    dashboard = payload.get("dashboard")
    apps = payload.get("apps")
    cloud = payload.get("cloud")
    notifications = payload.get("desktop_notifications")
    dashboard_payload = view._coerce_object_dict(dashboard)
    apps_payload = view._coerce_object_dict(apps)
    cloud_payload = view._coerce_object_dict(cloud)
    notification_payload = view._coerce_object_dict(notifications)
    managed_installs = view._coerce_dict_list(apps_payload.get("managed_installs"))
    summary = view.Table.grid(padding=(0, 1))
    summary.add_row("Dashboard", view._init_dashboard_summary(dashboard_payload))
    summary.add_row("Apps", view._init_apps_summary(apps_payload, len(managed_installs)))
    summary.add_row("Cloud", view._init_cloud_summary(cloud_payload))
    summary.add_row("Notifications", view._init_notification_summary(notification_payload))
    status = str(payload.get("status") or "initialized")
    title = view._init_panel_title(status)
    border_style = "red" if status == "needs_attention" else "cyan"
    console.print(view.Panel(summary, title=title, border_style=border_style))
    if managed_installs:
        console.print(view._managed_install_batch_table(managed_installs))
    guidance = notification_payload.get("guidance")
    if isinstance(guidance, str) and guidance:
        console.print(view.Panel(guidance, title="Notification setup", border_style="blue"))
    console.print(view._build_steps_panel(view._coerce_dict_list(payload.get("next_steps"))))


def _init_plan_panel(view: RenderContext, plan: list[dict[str, object]], status: str) -> Panel:
    table = view.Table.grid(padding=(0, 1))
    for step in plan:
        decision = str(step.get("decision") or "pending").replace("_", " ")
        title = str(step.get("title") or step.get("id") or "Step")
        command = str(step.get("command") or "")
        table.add_row(view._init_decision_label(decision), f"[bold]{title}[/bold]", command)
        detail = step.get("detail")
        if isinstance(detail, str) and detail:
            table.add_row("", f"[dim]{detail}[/dim]", "")
    border = "red" if status == "needs_attention" else ("yellow" if status == "approval_required" else "cyan")
    return view.Panel(table, title="Progressive init plan", border_style=border)


def _init_decision_label(view: RenderContext, decision: str) -> str:
    if decision == "approved":
        return "[green]approved[/green]"
    if decision == "skipped":
        return "[yellow]skipped[/yellow]"
    return "[blue]pending[/blue]"


def _init_panel_title(view: RenderContext, status: str) -> str:
    if status == "approval_required":
        return "HOL Guard init needs approval"
    if status == "needs_attention":
        return "HOL Guard init needs attention"
    return "HOL Guard initialized"


def _init_skip_reason(view: RenderContext, payload: dict[str, object]) -> str:
    return str(payload.get("reason") or "not approved").replace("_", " ")


def _init_dashboard_summary(view: RenderContext, payload: dict[str, object]) -> str:
    if bool(payload.get("skipped")):
        return f"skipped ({view._init_skip_reason(payload)})"
    if payload.get("error"):
        return f"not opened ({payload.get('error')})"
    opened = "opened" if bool(payload.get("opened")) else "ready"
    url = payload.get("browser_url") or payload.get("approval_center_url") or "local approval center"
    return f"{opened}: {url}"


def _init_apps_summary(view: RenderContext, payload: dict[str, object], count: int) -> str:
    if bool(payload.get("skipped")):
        return f"skipped ({view._init_skip_reason(payload)})"
    if payload.get("error"):
        return f"needs attention ({payload.get('error')})"
    return f"{count} app install{'s' if count != 1 else ''} checked"


def _init_cloud_summary(view: RenderContext, payload: dict[str, object]) -> str:
    if bool(payload.get("skipped")):
        return f"skipped ({view._init_skip_reason(payload)})"
    if payload.get("error"):
        return f"needs attention ({payload.get('error')})"
    if bool(payload.get("connected")):
        return "connected"
    status = payload.get("status") or payload.get("state") or "waiting"
    return str(status).replace("_", " ")


def _init_notification_summary(view: RenderContext, payload: dict[str, object]) -> str:
    if bool(payload.get("skipped")):
        return f"skipped ({view._init_skip_reason(payload)})"
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


def _protection_display_name(view: RenderContext, payload: dict[str, object], fallback: str) -> str:
    for key in ("runtime_protection_label", "protection_label"):
        label = payload.get(key)
        if isinstance(label, str) and label.strip():
            return label.strip()
    return fallback


def _protection_status_copy(view: RenderContext, payload: dict[str, object], fallback: str) -> tuple[str, bool]:
    protection = str(payload.get("protection") or payload.get("protection_posture") or fallback)
    return (
        view._protection_display_name(payload, protection),
        bool(payload.get("protection_off")) or protection == "watch",
    )


def _render_status(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    harnesses = view._coerce_dict_list(payload.get("harnesses"))
    name, protection_off = view._protection_status_copy(payload, "protected")
    protection_line = f"[bold red]protection: {name} (off)[/bold red]" if protection_off else f"protection: {name}"
    console.print(
        view.Panel.fit(
            f"[bold]HOL Guard status[/bold]\n"
            f"{protection_line}\n"
            f"{payload.get('managed_harnesses', 0)} managed harnesses • "
            f"{payload.get('receipt_count', 0)} receipts • "
            f"{payload.get('pending_approvals', 0)} approvals • "
            f"sync {'connected' if payload.get('sync_configured') else 'local only'}",
            border_style="red" if protection_off else "cyan",
        )
    )
    console.print(view._build_cloud_summary_panel(payload))
    console.print(view._build_product_table(harnesses))
    if payload.get("approval_center_url"):
        console.print(f"Approval center: [bold]{payload.get('approval_center_url')}[/bold]")
    review_items = [item for item in harnesses if view._coerce_int(item.get("review_count")) > 0]
    if review_items:
        console.print(
            view.Panel(
                "\n".join(
                    f"• {item.get('harness')}: run [bold]{item.get('review_command')}[/bold]" for item in review_items
                ),
                title="Needs review",
                border_style="yellow",
            )
        )


def _render_bootstrap(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    harness = payload.get("recommended_harness") or "none"
    bootstrap_install = payload.get("bootstrap_install")
    install_summary = view._bootstrap_install_summary(bootstrap_install, fallback_harness=str(harness))
    body = view.Table.grid(padding=(0, 1))
    body.add_row("Recommended harness", str(harness))
    body.add_row("Approval center", str(payload.get("approval_center_url") or "not running"))
    body.add_row("Daemon ready", view._bool_label(bool(payload.get("approval_center_reachable"))))
    body.add_row("Install", install_summary)
    alias = payload.get("shell_alias")
    if isinstance(alias, dict):
        body.add_row("Protect alias", str(alias.get("snippet") or "not configured"))
    console.print(view.Panel(body, title="Guard bootstrap", border_style="cyan"))
    console.print(view._build_steps_panel(view._coerce_dict_list(payload.get("next_steps"))))


def _bootstrap_install_summary(view: RenderContext, bootstrap_install: object, *, fallback_harness: str) -> str:
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


def _build_harness_table(view: RenderContext, detections: list[dict[str, object]]) -> Table:
    table = view.Table(box=view.box.SIMPLE_HEAVY, show_header=True)
    table.add_column("Harness", style="bold")
    table.add_column("Status")
    table.add_column("Command")
    table.add_column("Artifacts", justify="right")
    table.add_column("Warnings", justify="right")
    for detection in detections:
        table.add_row(
            str(detection.get("harness", "unknown")),
            view._status_text(detection),
            view._bool_label(bool(detection.get("command_available"))),
            str(len(view._coerce_dict_list(detection.get("artifacts")))),
            str(view._warning_count(detection)),
        )
    return table


def _build_product_table(view: RenderContext, harnesses: list[dict[str, object]]) -> Table:
    table = view.Table(box=view.box.SIMPLE_HEAVY, show_header=True)
    table.add_column("Harness", style="bold")
    table.add_column("Managed")
    table.add_column("Artifacts", justify="right")
    table.add_column("Review", justify="right")
    table.add_column("Recommended action")
    for harness in harnesses:
        table.add_row(
            str(harness.get("harness", "unknown")),
            view._bool_label(bool(harness.get("managed"))),
            str(harness.get("artifact_count", 0)),
            str(harness.get("review_count", 0)),
            view._next_action_label(harness),
        )
    return table


def _next_action_label(view: RenderContext, harness: dict[str, object]) -> str:
    next_action = str(harness.get("next_action") or "install")
    review_count = view._coerce_int(harness.get("review_count"))
    if next_action == "install-harness":
        return "Install harness first"
    if next_action == "install":
        return "Install Guard"
    if next_action == "review":
        return f"Review {review_count} change{'s' if review_count != 1 else ''}"
    if next_action == "run":
        return "Run through Guard"
    return next_action.replace("-", " ").strip() or "Check status"


def _build_steps_panel(view: RenderContext, steps: Sequence[PayloadMapping]) -> Panel:
    lines = []
    for step in steps:
        title = str(step.get("title", "Next step"))
        command = str(step.get("command", ""))
        detail = str(step.get("detail", ""))
        lines.append(f"[bold]{title}[/bold]\n  {command}\n  {detail}")
    return view.Panel("\n\n".join(lines), title="Next steps", border_style="green")


def _build_diagnostic_command_panel(
    view: RenderContext,
) -> Panel:
    return view.Panel(
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


def _render_harness_detail(view: RenderContext, console: Console, detection: dict[str, object]) -> None:
    artifacts = view._coerce_dict_list(detection.get("artifacts"))
    warnings = view._coerce_string_list(detection.get("warnings"))
    if not artifacts and not warnings:
        return
    body = view.Table.grid(padding=(0, 1))
    body.add_row("Status", view._status_text(detection))
    config_paths = view._coerce_string_list(detection.get("config_paths"))
    body.add_row("Config", "\n".join(view._short_path(path) for path in config_paths) or "none")
    if warnings:
        body.add_row("Warnings", "\n".join(f"• {warning}" for warning in warnings))
    console.print(view.Panel(body, title=str(detection.get("harness", "unknown")), border_style="blue"))
    if artifacts:
        console.print(view._build_artifact_table(artifacts))
