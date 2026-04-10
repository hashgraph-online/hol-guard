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
            "[yellow]Run `codex-plugin-scanner guard doctor <harness>` "
            "for harness-specific drift and runtime diagnostics.[/yellow]"
        )


def _render_start(console: Console, payload: dict[str, object]) -> None:
    harnesses = _coerce_dict_list(payload.get("harnesses"))
    console.print(
        Panel.fit(
            f"[bold]HOL Guard first run[/bold]\n"
            f"{len(harnesses)} harnesses detected • {payload.get('receipt_count', 0)} receipts recorded",
            border_style="cyan",
        )
    )
    console.print(_build_product_table(harnesses))
    console.print(_build_steps_panel(_coerce_dict_list(payload.get("next_steps"))))


def _render_status(console: Console, payload: dict[str, object]) -> None:
    harnesses = _coerce_dict_list(payload.get("harnesses"))
    console.print(
        Panel.fit(
            f"[bold]HOL Guard status[/bold]\n"
            f"{payload.get('managed_harnesses', 0)} managed harnesses • "
            f"{payload.get('receipt_count', 0)} receipts • "
            f"sync {'connected' if payload.get('sync_configured') else 'local only'}",
            border_style="cyan",
        )
    )
    console.print(_build_product_table(harnesses))
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
    if payload.get("review_hint"):
        body.add_row("Review", str(payload.get("review_hint")))
    if launched:
        body.add_row("Command", _command_text(payload.get("launch_command")))
    console.print(Panel(body, title=title, border_style=border_style))
    console.print(_build_artifact_result_table(_coerce_dict_list(payload.get("artifacts"))))


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
    table.add_column("Changed fields", style="magenta")
    for receipt in receipts:
        date_text, time_text = _timestamp_parts(receipt.get("timestamp"))
        table.add_row(
            date_text,
            time_text,
            str(receipt.get("harness", "unknown")),
            str(receipt.get("artifact_name") or receipt.get("artifact_id") or "unknown"),
            _action_text(str(receipt.get("policy_decision", "warn"))),
            ", ".join(_coerce_string_list(receipt.get("changed_capabilities"))) or "none",
        )
    console.print(table)


def _render_managed_install(console: Console, payload: dict[str, object]) -> None:
    managed_install = payload.get("managed_install")
    if not isinstance(managed_install, dict):
        _render_fallback(console, payload)
        return
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
    body.add_row("Receipts stored", str(payload.get("receipts_stored") or 0))
    console.print(Panel(body, title="Guard sync complete", border_style="green"))


def _render_hook(console: Console, payload: dict[str, object]) -> None:
    body = Table.grid(padding=(0, 1))
    body.add_row("Recorded", _bool_label(bool(payload.get("recorded"))))
    body.add_row("Artifact", str(payload.get("artifact_name") or payload.get("artifact_id") or "unknown"))
    body.add_row("Decision", _action_text(str(payload.get("policy_action", "warn"))))
    console.print(Panel(body, title="Guard hook event", border_style="cyan"))


def _render_scan(console: Console, payload: dict[str, object]) -> None:
    recommendation = payload.get("policy_recommendation")
    ecosystems = []
    if isinstance(payload.get("capability_manifest"), dict):
        ecosystems = _coerce_string_list(payload["capability_manifest"].get("ecosystems"))
    artifact_snapshot = payload.get("artifact_snapshot")
    body = Table.grid(padding=(0, 1))
    body.add_row(
        "Artifact",
        str(artifact_snapshot.get("artifact_path", ".")) if isinstance(artifact_snapshot, dict) else ".",
    )
    body.add_row("Ecosystems", ", ".join(ecosystems) or "unknown")
    if isinstance(recommendation, dict):
        body.add_row("Recommended action", _action_text(str(recommendation.get("action", "review"))))
    console.print(Panel(body, title="Consumer scan", border_style="cyan"))
    console.print(
        Syntax(
            json.dumps(payload, indent=2),
            "json",
            theme="ansi_dark",
            word_wrap=True,
        )
    )


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
    for artifact in artifacts:
        table.add_row(
            str(artifact.get("artifact_name") or artifact.get("artifact_id") or "unknown"),
            _bool_label(bool(artifact.get("changed"))),
            _action_text(str(artifact.get("policy_action", "warn"))),
            ", ".join(_coerce_string_list(artifact.get("changed_fields"))) or "none",
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
    "start": _render_start,
    "status": _render_status,
    "detect": _render_detect,
    "doctor": _render_doctor,
    "run": _render_run,
    "diff": _render_diff,
    "receipts": _render_receipts,
    "install": _render_managed_install,
    "uninstall": _render_managed_install,
    "allow": _render_decision,
    "deny": _render_decision,
    "login": _render_login,
    "sync": _render_sync,
    "hook": _render_hook,
    "scan": _render_scan,
    "explain": _render_scan,
}
