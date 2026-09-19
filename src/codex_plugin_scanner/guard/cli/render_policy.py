"""policy presentation for Guard CLI output."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .render import Console, Table
    from .render_context import RenderContext


def _render_receipts(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    receipts = view._coerce_dict_list(payload.get("items"))
    console.print(
        view.Panel.fit(
            f"[bold]Recent Guard receipts[/bold]\n{len(receipts)} local decisions recorded",
            border_style="cyan",
        )
    )
    table = view.Table(box=view.box.SIMPLE_HEAVY, show_header=True)
    table.add_column("Date", style="dim", no_wrap=True)
    table.add_column("Time", style="dim", no_wrap=True)
    table.add_column("Harness", style="cyan")
    table.add_column("Artifact", style="bold")
    table.add_column("Decision")
    table.add_column("Capabilities", style="blue")
    table.add_column("Changed fields", style="magenta")
    for receipt in receipts:
        date_text, time_text = view._timestamp_parts(receipt.get("timestamp"))
        table.add_row(
            date_text,
            time_text,
            str(receipt.get("harness", "unknown")),
            str(receipt.get("artifact_name") or receipt.get("artifact_id") or "unknown"),
            view._action_text(str(receipt.get("policy_decision", "warn"))),
            str(receipt.get("capabilities_summary") or "unknown"),
            ", ".join(view._coerce_string_list(receipt.get("changed_capabilities"))) or "none",
        )
    console.print(table)


def _render_inventory(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    items = view._coerce_dict_list(payload.get("items"))
    console.print(
        view.Panel.fit(
            f"[bold]Local Guard inventory[/bold]\n{len(items)} tracked artifact{'s' if len(items) != 1 else ''}",
            border_style="cyan",
        )
    )
    table = view.Table(box=view.box.SIMPLE_HEAVY, show_header=True)
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
            view._action_text(str(item.get("last_policy_action") or "warn")),
            view._bool_label(bool(item.get("present"))),
        )
    console.print(table)


def _render_policies(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    if "counts" in payload or payload.get("operation") == "migrate-local-integrity":
        counts = view._coerce_object_dict(payload.get("counts"))
        degraded_reasons = view._coerce_string_list(payload.get("degraded_reasons"))
        body = view.Table.grid(padding=(0, 1))
        body.add_row("Mode", str(payload.get("mode") or "unknown"))
        body.add_row("Enforcement", str(payload.get("enforcement") or "unknown"))
        body.add_row("Backend", str(payload.get("backend") or "unknown"))
        body.add_row("Local rows", str(view._coerce_int(payload.get("local_rows_scanned"))))
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
            body.add_row("Cleared", str(view._coerce_int(payload.get("cleared"))))
        for label, key in (
            ("Valid", "valid"),
            ("Unsigned", "missing_integrity"),
            ("Tampered", "tampered"),
            ("Unknown key", "unknown_key"),
            ("Rolled back", "rollback_detected"),
            ("Degraded", "degraded_mode"),
        ):
            body.add_row(label, str(view._coerce_int(counts.get(key))))
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
        console.print(view.Panel(body, title=title, border_style=border_style))
        if payload.get("error"):
            console.print(str(payload.get("error")))
            return
        invalid_items = view._coerce_dict_list(payload.get("items"))
        if not invalid_items:
            return
        table = view.Table(box=view.box.SIMPLE_HEAVY, show_header=True)
        table.add_column("Harness", style="cyan")
        table.add_column("Action")
        table.add_column("Artifact", style="bold")
        table.add_column("Integrity")
        table.add_column("Updated")
        for item in invalid_items:
            table.add_row(
                str(item.get("harness") or "unknown"),
                view._action_text(str(item.get("action") or "warn")),
                str(item.get("artifact_id") or "all artifacts"),
                str(item.get("integrity_status") or "unknown"),
                str(item.get("updated_at") or "unknown"),
            )
        console.print(table)
        return
    if "cleared" in payload or "error" in payload:
        error = payload.get("error")
        cleared = view._coerce_int(payload.get("cleared"))
        scope = str(payload.get("harness") or "all harnesses")
        source = payload.get("source")
        body = view.Table.grid(padding=(0, 1))
        body.add_row("Outcome", str(error) if error else f"cleared {cleared} decision{'s' if cleared != 1 else ''}")
        body.add_row("Harness", scope)
        if source:
            body.add_row("Source", str(source))
        console.print(
            view.Panel(
                body,
                title="Guard rules clear",
                border_style="red" if error else "green",
            )
        )
        return
    items = view._coerce_dict_list(payload.get("items"))
    console.print(
        view.Panel.fit(
            f"[bold]Guard remembered rules and Cloud policies[/bold]\n"
            f"{len(items)} active rule{'s' if len(items) != 1 else ''}",
            border_style="cyan",
        )
    )
    table = view.Table(box=view.box.SIMPLE_HEAVY, show_header=True)
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
            view._action_text(str(item.get("action") or "warn")),
            str(item.get("integrity_status") or "remote"),
            str(item.get("artifact_id") or "all artifacts"),
            str(item.get("publisher") or "—"),
            str(item.get("owner") or "—"),
            str(item.get("expires_at") or "never"),
        )
    console.print(table)


def _render_advisories(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    items = view._coerce_dict_list(payload.get("items"))
    console.print(
        view.Panel.fit(
            f"[bold]Guard advisories[/bold]\n{len(items)} cached advisory{'s' if len(items) != 1 else ''}",
            border_style="cyan",
        )
    )
    console.print(view._build_advisory_table(items))


def _build_advisory_table(view: RenderContext, items: list[dict[str, object]], *, title: str | None = None) -> Table:
    table = view.Table(title=title, box=view.box.SIMPLE_HEAVY, show_header=True)
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


def _render_events(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    items = view._coerce_dict_list(payload.get("items"))
    console.print(
        view.Panel.fit(
            f"[bold]Guard lifecycle events[/bold]\n{len(items)} local event{'s' if len(items) != 1 else ''}",
            border_style="cyan",
        )
    )
    table = view.Table(box=view.box.SIMPLE_HEAVY, show_header=True)
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


def _render_approvals(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    approval_url = payload.get("approval_url")
    if isinstance(approval_url, str) and approval_url:
        body = view.Table.grid(padding=(0, 1))
        body.add_row("Request", str(payload.get("request_id", "")))
        body.add_row("URL", f"[bold]{approval_url}[/bold]")
        console.print(view.Panel(body, title="Open approval", border_style="cyan"))
        return
    if "title" in payload and "body" in payload:
        body = view.Table.grid(padding=(0, 1))
        body.add_row("Status", str(payload["title"]))
        body.add_row("Next step", str(payload["body"]))
        console.print(view.Panel(body, title="Approval resolved", border_style="green"))
        return
    if payload.get("error"):
        console.print(view.Panel(str(payload.get("error")), title="Approval error", border_style="red"))
        return
    if "history_cleared" in payload or "cleared_policies" in payload:
        error = payload.get("error")
        body = view.Table.grid(padding=(0, 1))
        body.add_row(
            "Outcome",
            str(error) if error else "approval history reset",
        )
        body.add_row("Harness", str(payload.get("harness") or "all harnesses"))
        source = payload.get("source")
        if source:
            body.add_row("Source", str(source))
        body.add_row("Policy decisions", str(view._coerce_int(payload.get("cleared_policies"))))
        body.add_row("Resolved requests", str(view._coerce_int(payload.get("cleared_resolved_requests"))))
        console.print(
            view.Panel(
                body,
                title="Approval history",
                border_style="red" if error else "green",
            )
        )
        return
    if payload.get("resolved"):
        item = payload.get("item")
        if isinstance(item, dict):
            body = view.Table.grid(padding=(0, 1))
            body.add_row("Artifact", str(item.get("artifact_name") or item.get("artifact_id") or "unknown"))
            body.add_row("Harness", str(item.get("harness") or "unknown"))
            body.add_row("Action", view._action_text(str(item.get("resolution_action") or "warn")))
            body.add_row("Scope", str(item.get("resolution_scope") or "artifact"))
            console.print(view.Panel(body, title="Approval resolved", border_style="green"))
            return
    items = view._coerce_dict_list(payload.get("items"))
    console.print(
        view.Panel.fit(
            f"[bold]Pending Guard approvals[/bold]\n{len(items)} item{'s' if len(items) != 1 else ''} waiting",
            border_style="yellow" if items else "green",
        )
    )
    if payload.get("approval_center_url"):
        console.print(f"Approval center: [bold]{payload.get('approval_center_url')}[/bold]")
    console.print(view._build_approval_table(items, title=None))


def _build_approval_table(view: RenderContext, items: list[dict[str, object]], *, title: str | None) -> Table:
    table = view.Table(title=title, box=view.box.SIMPLE_HEAVY, show_header=True)
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
            ", ".join(view._coerce_string_list(item.get("changed_fields"))) or "none",
            str(item.get("risk_summary") or "no obvious secret/network signal"),
            view._action_text(str(item.get("policy_action") or "warn")),
            resolve_text,
        )
    return table
