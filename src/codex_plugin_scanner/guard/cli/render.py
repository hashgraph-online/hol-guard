"""Rich renderers for Guard CLI output."""

from __future__ import annotations

import json
import re
import sys
import textwrap
from pathlib import Path
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text


def emit_guard_payload(command: str, payload: dict[str, object], as_json: bool) -> None:
    """Render Guard payloads as JSON or human-friendly rich output."""

    if as_json:
        print(json.dumps(payload, indent=2))
        return

    console = Console(file=sys.stdout, soft_wrap=True)
    renderer = _RENDERERS.get(command, _render_fallback)
    renderer(console, payload)


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
    console.print(_build_product_table(harnesses))
    if payload.get("approval_center_url"):
        console.print(f"Approval center: [bold]{payload.get('approval_center_url')}[/bold]")
    console.print(_build_steps_panel(_coerce_dict_list(payload.get("next_steps"))))


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
    console.print(_build_product_table(harnesses))
    if payload.get("approval_center_url"):
        console.print(f"Approval center: [bold]{payload.get('approval_center_url')}[/bold]")
    review_items = [item for item in harnesses if int(item.get("review_count", 0)) > 0]
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
    install_summary = "not changed"
    if isinstance(bootstrap_install, dict):
        if bool(bootstrap_install.get("installed")):
            install_summary = f"installed for {bootstrap_install.get('harness', harness)}"
        elif bootstrap_install.get("reason") == "already_managed":
            install_summary = f"already managing {bootstrap_install.get('harness', harness)}"
        else:
            install_summary = str(bootstrap_install.get("reason") or install_summary)
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


def _render_doctor(console: Console, payload: dict[str, object]) -> None:
    if "adapters" in payload:
        tables = _coerce_string_list(payload.get("tables"))
        console.print(
            Panel.fit(
                f"[bold]HOL Guard doctor[/bold]\n{len(tables)} local tables checked",
                border_style="cyan",
            )
        )
        adapters = _coerce_dict_list(payload.get("adapters"))
        console.print(_build_harness_table(adapters))
        return

    warnings = _coerce_string_list(payload.get("warnings"))
    summary = Table.grid(padding=(0, 1))
    summary.add_row("Harness", f"[bold]{payload.get('harness', 'unknown')}[/bold]")
    summary.add_row("Installed", _bool_label(bool(payload.get("installed"))))
    summary.add_row("Command", _bool_label(bool(payload.get("command_available"))))
    summary.add_row("Artifacts", str(len(_coerce_dict_list(payload.get("artifacts")))))
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


def _render_run(console: Console, payload: dict[str, object]) -> None:
    blocked = bool(payload.get("blocked"))
    launched = bool(payload.get("launched"))
    title = "Blocked before launch" if blocked else "Launch allowed"
    border_style = "red" if blocked else "green"
    body = Table.grid(padding=(0, 1))
    body.add_row("Harness", f"[bold]{payload.get('harness', 'unknown')}[/bold]")
    body.add_row("Receipts", str(payload.get("receipts_recorded", 0)))
    body.add_row("Launched", _bool_label(launched))
    if payload.get("approval_center_url"):
        body.add_row("Approval center", str(payload.get("approval_center_url")))
    if payload.get("review_hint"):
        body.add_row("Review", str(payload.get("review_hint")))
    if launched:
        body.add_row("Command", _command_text(payload.get("launch_command")))
    console.print(Panel(body, title=title, border_style=border_style))
    console.print(_build_artifact_result_table(_coerce_dict_list(payload.get("artifacts"))))
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
    items = _coerce_dict_list(payload.get("items"))
    console.print(
        Panel.fit(
            f"[bold]Guard policy decisions[/bold]\n{len(items)} active rule{'s' if len(items) != 1 else ''}",
            border_style="cyan",
        )
    )
    table = Table(box=box.SIMPLE_HEAVY, show_header=True)
    table.add_column("Harness", style="cyan")
    table.add_column("Scope")
    table.add_column("Action")
    table.add_column("Artifact", style="bold")
    table.add_column("Publisher")
    table.add_column("Owner")
    table.add_column("Expires")
    for item in items:
        table.add_row(
            str(item.get("harness") or "unknown"),
            str(item.get("scope") or "harness"),
            _action_text(str(item.get("action") or "warn")),
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
    table = Table(box=box.SIMPLE_HEAVY, show_header=True)
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
    console.print(table)


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
    managed_install = payload.get("managed_install")
    if isinstance(managed_install, dict):
        _render_single_managed_install(console, managed_install)
        return
    managed_installs = _coerce_dict_list(payload.get("managed_installs"))
    if not managed_installs:
        _render_fallback(console, payload)
        return
    summary = Table(title="Guard managed harnesses")
    summary.add_column("Harness", style="bold")
    summary.add_column("Active")
    summary.add_column("Workspace")
    summary.add_column("Config")
    for item in managed_installs:
        manifest = item.get("manifest")
        config_path = manifest.get("config_path") if isinstance(manifest, dict) else None
        summary.add_row(
            str(item.get("harness") or "unknown"),
            _bool_label(bool(item.get("active"))),
            str(item.get("workspace") or "current shell"),
            str(config_path or "no config changed"),
        )
    console.print(summary)


def _render_single_managed_install(console: Console, managed_install: dict[str, object]) -> None:
    manifest = managed_install.get("manifest")
    notes = _coerce_string_list(manifest.get("notes")) if isinstance(manifest, dict) else []
    body = Table.grid(padding=(0, 1))
    body.add_row("Harness", f"[bold]{managed_install.get('harness', 'unknown')}[/bold]")
    body.add_row("Active", _bool_label(bool(managed_install.get("active"))))
    body.add_row("Workspace", str(managed_install.get("workspace") or "current shell"))
    if isinstance(manifest, dict):
        body.add_row("Config", str(manifest.get("config_path") or "no config changed"))
        if manifest.get("shim_command"):
            body.add_row("Launcher", str(manifest.get("shim_command")))
    console.print(Panel(body, title="Guard install state", border_style="cyan"))
    if notes:
        console.print(Panel("\n".join(f"• {note}" for note in notes), title="Notes", border_style="blue"))


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


def _render_sync(console: Console, payload: dict[str, object]) -> None:
    body = Table.grid(padding=(0, 1))
    body.add_row("Synced at", str(payload.get("synced_at") or "unknown"))
    body.add_row("Receipts sent", str(payload.get("receipts") or 0))
    body.add_row("Inventory sent", str(payload.get("inventory") or 0))
    body.add_row("Receipts stored", str(payload.get("receipts_stored") or 0))
    body.add_row("Advisories stored", str(payload.get("advisories_stored") or 0))
    console.print(Panel(body, title="Guard sync complete", border_style="green"))


def _render_hook(console: Console, payload: dict[str, object]) -> None:
    body = Table.grid(padding=(0, 1))
    body.add_row("Recorded", _bool_label(bool(payload.get("recorded"))))
    body.add_row("Artifact", str(payload.get("artifact_name") or payload.get("artifact_id") or "unknown"))
    body.add_row("Decision", _action_text(str(payload.get("policy_action", "warn"))))
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


def _render_scan(console: Console, payload: dict[str, object]) -> None:
    recommendation = payload.get("policy_recommendation")
    ecosystems = []
    if isinstance(payload.get("capability_manifest"), dict):
        ecosystems = _coerce_string_list(payload["capability_manifest"].get("ecosystems"))
    artifact_snapshot = payload.get("artifact_snapshot")
    artifact_path = "."
    if isinstance(artifact_snapshot, dict):
        artifact_path = str(artifact_snapshot.get("path") or artifact_snapshot.get("artifact_path") or ".")
    body = Table.grid(padding=(0, 1))
    body.add_row("Artifact", artifact_path)
    body.add_row("Ecosystems", ", ".join(ecosystems) or "unknown")
    if isinstance(recommendation, dict):
        body.add_row("Recommended action", _action_text(str(recommendation.get("action", "review"))))
    console.print(Panel(body, title="Consumer scan", border_style="cyan"))
    _render_cisco_evidence(console, payload)
    console.print(
        Syntax(
            json.dumps(payload, indent=2),
            "json",
            theme="ansi_dark",
            word_wrap=True,
        )
    )


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
    _render_scan(console, payload)


def _render_protect(console: Console, payload: dict[str, object]) -> None:
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
            json.dumps(payload, indent=2),
            "json",
            theme="ansi_dark",
            word_wrap=True,
        )
    )


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
    table.add_column("Next step")
    for harness in harnesses:
        table.add_row(
            str(harness.get("harness", "unknown")),
            _bool_label(bool(harness.get("managed"))),
            str(harness.get("artifact_count", 0)),
            str(harness.get("review_count", 0)),
            str(harness.get("next_action", "install")),
        )
    return table


def _build_steps_panel(steps: list[dict[str, object]]) -> Panel:
    lines = []
    for step in steps:
        title = str(step.get("title", "Next step"))
        command = str(step.get("command", ""))
        detail = str(step.get("detail", ""))
        lines.append(f"[bold]{title}[/bold]\n  {command}\n  {detail}")
    return Panel("\n\n".join(lines), title="Next steps", border_style="green")


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
        table.add_row(
            str(item.get("request_id") or "unknown"),
            str(item.get("harness") or "unknown"),
            str(item.get("artifact_name") or item.get("artifact_id") or "unknown"),
            ", ".join(_coerce_string_list(item.get("changed_fields"))) or "none",
            str(item.get("risk_summary") or "no obvious secret/network signal"),
            _action_text(str(item.get("policy_action") or "warn")),
            str(item.get("review_command") or "hol-guard approvals"),
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


def _coerce_dict_list(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _coerce_string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if isinstance(item, str) and item]


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


_RENDERERS: dict[str, Any] = {
    "approvals": _render_approvals,
    "start": _render_start,
    "status": _render_status,
    "bootstrap": _render_bootstrap,
    "detect": _render_detect,
    "doctor": _render_doctor,
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
    "allow": _render_decision,
    "deny": _render_decision,
    "login": _render_login,
    "sync": _render_sync,
    "hook": _render_hook,
    "protect": _render_protect,
    "preflight": _render_preflight,
    "scan": _render_scan,
    "explain": _render_scan,
}
