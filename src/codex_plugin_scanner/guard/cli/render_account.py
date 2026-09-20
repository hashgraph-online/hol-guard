"""account presentation for Guard CLI output."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .render import Console, Table
    from .render_context import RenderContext


def _render_login(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    console.print(
        view.Panel.fit(
            f"[bold]Guard sync endpoint saved[/bold]\nEndpoint: {payload.get('sync_url', 'unknown')}",
            border_style="green",
        )
    )


def _render_connect(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    if "connected" in payload or "browser_opened" in payload or "status" in payload:
        body = view.Table.grid(padding=(0, 1))
        milestone = str(payload.get("milestone") or "")
        body.add_row("Browser opened", view._bool_label(bool(payload.get("browser_opened"))))
        body.add_row(
            "Browser paired",
            view._bool_label(bool(payload.get("completed_at")) or str(payload.get("status") or "") == "connected"),
        )
        body.add_row("Connection", view._connect_status_text(payload))
        if milestone:
            body.add_row("Next step", view._connect_milestone_text(payload))
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
            receipts_stored = view._coerce_int(sync_payload.get("receipts_stored"))
            inventory_value = sync_payload.get("inventory_tracked", sync_payload.get("inventory"))
            inventory_tracked = view._coerce_int(inventory_value)
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
        sync_message = view._connect_sync_note_text(payload)
        if sync_message is not None:
            body.add_row("Sync note", sync_message)
        console.print(view.Panel(body, title="Guard connect", border_style="green"))
        return

    border_style = view._cloud_border_style(str(payload.get("cloud_state") or "local_only"))
    console.print(
        view.Panel.fit(
            f"[bold]HOL Guard connect[/bold]\n"
            f"{payload.get('cloud_state_label', 'Local only')} • "
            f"{payload.get('receipt_count', 0)} receipts • "
            f"{payload.get('pending_approvals', 0)} approvals",
            border_style=border_style,
        )
    )
    console.print(view._build_cloud_summary_panel(payload))
    sync_result = payload.get("sync_result")
    if isinstance(sync_result, dict):
        body = view.Table.grid(padding=(0, 1))
        body.add_row("Synced at", str(sync_result.get("synced_at") or "unknown"))
        body.add_row("Receipts stored", str(sync_result.get("receipts_stored") or 0))
        body.add_row("Advisories stored", str(sync_result.get("advisories_stored") or 0))
        body.add_row("Remote policies", str(sync_result.get("remote_policies_stored") or 0))
        console.print(view.Panel(body, title="Connect sync", border_style="green"))
    if payload.get("sync_error"):
        console.print(view.Panel(str(payload.get("sync_error")), title="Connect failed", border_style="red"))
    if payload.get("approval_center_url"):
        console.print(f"Approval center: [bold]{payload.get('approval_center_url')}[/bold]")
    console.print(view._build_product_table(view._coerce_dict_list(payload.get("harnesses"))))
    console.print(view._build_steps_panel(view._coerce_dict_list(payload.get("next_steps"))))


def _render_dashboard(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    body = view.Table.grid(padding=(0, 1))
    body.add_row("Dashboard", str(payload.get("approval_center_url") or "unknown"))
    if payload.get("opened") is not None:
        body.add_row("Browser opened", view._bool_label(bool(payload.get("opened"))))
    console.print(view.Panel(body, title="HOL Guard dashboard", border_style="cyan"))


def _render_sync(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    view.render_sync_summary(console, payload)
    ecosystem_support = view._coerce_dict_list(payload.get("ecosystem_support"))
    if ecosystem_support:
        console.print(view._build_ecosystem_support_table(ecosystem_support))


def _add_update_version_rows(view: RenderContext, body: Table, version_check: object) -> None:
    if not isinstance(version_check, dict):
        return
    latest_version = version_check.get("latest_version")
    if isinstance(latest_version, str) and latest_version.strip():
        body.add_row("Latest PyPI version", latest_version.strip())
    reserved_alpha = version_check.get("reserved_alpha_version")
    if isinstance(reserved_alpha, str) and reserved_alpha.strip():
        body.add_row("Reserved GitHub alpha", reserved_alpha.strip())


def _render_update(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    body = view.Table.grid(padding=(0, 1))
    body.add_row("Current version", str(payload.get("current_version") or "unknown"))
    body.add_row("Installer", str(payload.get("installer") or "unknown"))
    command = payload.get("command")
    if isinstance(command, list) and command:
        body.add_row("Command", " ".join(str(part) for part in command))
    body.add_row("Dry run", view._bool_label(bool(payload.get("dry_run"))))
    view._add_update_version_rows(body, payload.get("version_check"))
    if payload.get("resulting_version"):
        body.add_row("Resulting version", str(payload.get("resulting_version")))
    if payload.get("editable_install") is not None:
        body.add_row("Editable install", view._bool_label(bool(payload.get("editable_install"))))
    if payload.get("changed") is not None:
        body.add_row("Changed", view._bool_label(bool(payload.get("changed"))))
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
        "deferred": "yellow",
        "failed": "red",
    }.get(status, "red")
    console.print(view.Panel(body, title=f"Guard update: {status}", border_style=border_style))
    notes = view._coerce_string_list(payload.get("notes"))
    stdout = str(payload.get("stdout") or "").strip()
    stderr = str(payload.get("stderr") or "").strip()
    error = str(payload.get("error") or "").strip()
    if notes:
        console.print(view.Panel("\n".join(f"• {note}" for note in notes), title="Notes", border_style="blue"))
    if status in {"updated", "failed"} and stdout and stdout != str(payload.get("message") or "").strip():
        console.print(view.Panel(stdout, title="stdout", border_style="green"))
    if status == "failed" and stderr:
        console.print(view.Panel(stderr, title="stderr", border_style="yellow"))
    if error:
        console.print(view.Panel(error, title="error", border_style="red"))
    if payload.get("managed_install") or payload.get("managed_installs"):
        view._render_managed_install(console, payload)


def _connect_status_text(view: RenderContext, payload: dict[str, object]) -> str:
    status = str(payload.get("status") or "unknown")
    milestone = str(payload.get("milestone") or "")
    if status == "connected" and milestone == "sync_not_available":
        return "Guard is running locally"
    if status == "connected" and milestone == "first_sync_pending":
        reason = view._connect_reason_text(payload)
        if view._connect_reason_requires_login(reason) or view._connect_reason_requires_paid_plan(reason):
            return "Guard is running locally"
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


def _connect_milestone_text(view: RenderContext, payload: dict[str, object]) -> str:
    milestone = str(payload.get("milestone") or "")
    if milestone == "waiting_for_browser":
        return "Waiting for browser approval"
    if milestone == "sync_not_available":
        return "Upgrade to sync this device to Guard Cloud"
    if milestone == "first_sync_pending":
        reason = view._connect_reason_text(payload)
        if view._connect_reason_requires_login(reason):
            return "Sign in to finish Guard Cloud setup"
        if view._connect_reason_requires_paid_plan(reason):
            return "Upgrade to sync this device to Guard Cloud"
        return "First Guard Cloud proof is on the way"
    if milestone == "first_sync_succeeded":
        return "Guard Cloud is tracking this device"
    if milestone == "first_sync_failed":
        return "First shared proof needs another try"
    if milestone == "expired":
        return "The request expired before pairing finished"
    return milestone.replace("_", " ")


def _connect_reason_text(view: RenderContext, payload: dict[str, object]) -> str:
    return str(payload.get("reason") or payload.get("sync_message") or "").strip().lower()


def _connect_reason_requires_login(view: RenderContext, reason: str) -> bool:
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


def _connect_reason_requires_paid_plan(view: RenderContext, reason: str) -> bool:
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


def _connect_sync_note_text(view: RenderContext, payload: dict[str, object]) -> str | None:
    message = str(payload.get("sync_message") or "").strip()
    if not message:
        return None
    reason = message.lower()
    if view._connect_reason_requires_login(reason):
        return "Local Guard is available. Sign in on the Guard connect page to finish Guard Cloud setup."
    if view._connect_reason_requires_paid_plan(reason):
        return (
            "Local Guard is available. Upgrade your Guard plan to sync shared "
            "proof, receipts, and Fleet history to Guard Cloud."
        )
    return message
