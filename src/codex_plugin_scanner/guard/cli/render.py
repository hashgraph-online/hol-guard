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
    console.print(_build_cloud_summary_panel(payload))
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
    console.print(_build_cloud_summary_panel(payload))
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
    dry_run = bool(payload.get("dry_run"))
    artifacts = _coerce_dict_list(payload.get("artifacts"))
    visible_artifacts = [artifact for artifact in artifacts if _run_artifact_should_be_visible(artifact)]
    summarized_artifacts = _summarize_run_artifacts(visible_artifacts)
    title = _run_title(blocked=blocked, dry_run=dry_run)
    border_style = "red" if blocked else "green"
    body = Table.grid(padding=(0, 1))
    approval_delivery = payload.get("approval_delivery")
    body.add_row("Harness", f"[bold]{payload.get('harness', 'unknown')}[/bold]")
    body.add_row("Mode", "dry run" if dry_run else "launch")
    body.add_row("Outcome", _run_outcome_text(blocked=blocked, dry_run=dry_run, launched=launched))
    body.add_row("Artifacts", str(len(summarized_artifacts)))
    if blocked:
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


def _render_connect(console: Console, payload: dict[str, object]) -> None:
    if "connected" in payload or "browser_opened" in payload or "status" in payload:
        body = Table.grid(padding=(0, 1))
        body.add_row("Connected", _bool_label(bool(payload.get("connected"))))
        body.add_row("Browser opened", _bool_label(bool(payload.get("browser_opened"))))
        body.add_row("Status", str(payload.get("status") or "unknown"))
        body.add_row("Connect URL", str(payload.get("connect_url") or "unknown"))
        body.add_row("Sync endpoint", str(payload.get("sync_url") or "unknown"))
        sync_payload = payload.get("sync")
        if isinstance(sync_payload, dict):
            body.add_row("Receipts stored", str(sync_payload.get("receipts_stored") or 0))
            body.add_row("Inventory sent", str(sync_payload.get("inventory") or 0))
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
    approval_center_url = payload.get("approval_center_url")
    review_hint = payload.get("review_hint")
    rerun_command = payload.get("rerun_command")
    diff_command = payload.get("diff_command")
    approvals_command = payload.get("approvals_command")
    if blocked and dry_run:
        review_command = (
            str(approvals_command)
            if approval_center_url and isinstance(approvals_command, str) and approvals_command
            else "hol-guard approvals"
            if approval_center_url
            else str(rerun_command)
            if isinstance(rerun_command, str) and rerun_command
            else f"hol-guard run {harness}"
        )
        inspect_command = (
            str(diff_command) if isinstance(diff_command, str) and diff_command else f"hol-guard diff {harness}"
        )
        review_detail = (
            str(review_hint)
            if isinstance(review_hint, str) and review_hint
            else "Rerun without --dry-run to review the full blocker set and continue into the harness launch."
        )
        return [
            {
                "title": "Resolve the blocked launch",
                "command": review_command,
                "detail": review_detail,
            },
            {
                "title": "Inspect only the changed config entries (optional)",
                "command": inspect_command,
                "detail": (
                    "See the config-level diff only. This view can omit policy-only blockers "
                    "Guard still needs you to review."
                ),
            },
        ]
    if blocked and isinstance(review_hint, str) and review_hint:
        command = (
            str(approvals_command)
            if approval_center_url and isinstance(approvals_command, str) and approvals_command
            else "hol-guard approvals"
            if approval_center_url
            else str(rerun_command)
            if isinstance(rerun_command, str) and rerun_command
            else f"hol-guard run {harness}"
        )
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
    return str(artifact.get("policy_action") or "allow") in {"block", "sandbox-required", "require-reapproval"}


def _artifact_needs_review(artifact: dict[str, object]) -> bool:
    return str(artifact.get("policy_action") or "allow") in {"block", "sandbox-required", "require-reapproval"}


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


def _build_cloud_summary_panel(payload: dict[str, object]) -> Panel:
    cloud_state = str(payload.get("cloud_state") or "local_only")
    body = Table.grid(padding=(0, 1))
    body.add_row("State", f"[bold]{payload.get('cloud_state_label', 'Local only')}[/bold]")
    body.add_row("Summary", str(payload.get("cloud_state_detail") or "Guard is protecting this machine locally."))
    body.add_row("Dashboard", str(payload.get("dashboard_url") or "https://hol.org/guard"))
    body.add_row("Connect guide", str(payload.get("connect_url") or "https://hol.org/guard/connect"))
    if payload.get("sync_url"):
        body.add_row("Sync endpoint", str(payload.get("sync_url")))
    if payload.get("last_sync_at"):
        body.add_row("Last sync", str(payload.get("last_sync_at")))
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
    "connect": _render_connect,
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
