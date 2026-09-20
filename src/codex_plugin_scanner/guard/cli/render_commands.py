"""commands presentation for Guard CLI output."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .render import Console, PayloadDict
    from .render_context import RenderContext


def _render_command_inspection(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    status = str(payload.get("status") or "invalid")
    classification = view._coerce_object_dict(payload.get("classification"))
    extensions = view._coerce_dict_list(payload.get("extensions"))
    rules = view._coerce_dict_list(payload.get("rules"))
    risk_classes = view._coerce_string_list(payload.get("risk_classes"))
    border_style = "yellow" if status == "review" else "cyan"
    summary = view.Table.grid(padding=(0, 1))
    summary.add_row("Result", view.Text(status.upper(), style=f"bold {border_style}"))
    action_class = classification.get("action_class")
    summary.add_row("Action class", view.Text(str(action_class or "No sensitive action matched")))
    if extensions:
        summary.add_row("Extension", view.Text(str(extensions[0].get("extension_id") or "unknown"), style="cyan"))
    if rules:
        summary.add_row("Rule", view.Text(str(rules[0].get("rule_id") or "unknown"), style="cyan"))
    if risk_classes:
        summary.add_row("Risk classes", view.Text(", ".join(risk_classes)))
    summary.add_row("Policy", view.Text("Not evaluated; this inspection creates no approvals or receipts", style="dim"))
    console.print(view.Panel(summary, title="HOL Guard command inspection", border_style=border_style))
    console.print(view.Panel(view.Syntax(str(payload.get("command") or ""), "bash", word_wrap=True), title="Command"))
    reason = classification.get("reason")
    if isinstance(reason, str) and reason:
        console.print(view.Panel(view.Text(reason), title="Why", border_style=border_style))
    if extensions:
        alternatives = view._coerce_string_list(extensions[0].get("safer_alternatives"))
        if alternatives:
            console.print(view.Panel("\n".join(f"• {item}" for item in alternatives), title="Safer approaches"))
    if str(payload.get("mode") or "") == "explain":
        trace = view._coerce_dict_list(payload.get("trace"))
        trace_table = view.Table(title="Evaluation trace", box=view.box.SIMPLE_HEAD, show_lines=False)
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


def _render_command_extensions(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    extensions = view._coerce_dict_list(payload.get("extensions"))
    table = view.Table(title="Built-in command safety extensions", box=view.box.SIMPLE_HEAD, show_lines=False)
    table.add_column("Extension", style="bold cyan", no_wrap=True)
    table.add_column("Version", no_wrap=True)
    table.add_column("Coverage")
    table.add_column("Rules")
    table.add_column("Purpose")
    for extension in extensions:
        table.add_row(
            str(extension.get("extension_id") or ""),
            str(extension.get("version") or ""),
            str(len(view._coerce_string_list(extension.get("action_classes")))),
            str(extension.get("rule_count") or 0),
            str(extension.get("description") or ""),
        )
    console.print(table)


def _render_command_setup(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    detections = view._coerce_dict_list(payload.get("detections"))
    table = view.Table(title="Command ecosystem setup", box=view.box.SIMPLE_HEAD, show_lines=False)
    table.add_column("Ecosystem", style="bold cyan", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Detected from")
    table.add_column("Protection")
    for detection in detections:
        marker_names = view._coerce_string_list(detection.get("project_markers"))
        executables = view._coerce_string_list(detection.get("available_executables"))
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


def _plain_text_command_inspection(view: RenderContext, payload: PayloadDict) -> str:
    classification = view._coerce_object_dict(payload.get("classification"))
    extensions = view._coerce_dict_list(payload.get("extensions"))
    rules = view._coerce_dict_list(payload.get("rules"))
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


def _plain_text_command_extensions(view: RenderContext, payload: PayloadDict) -> str:
    extensions = view._coerce_dict_list(payload.get("extensions"))
    lines = [f"Built-in command safety extensions ({len(extensions)})"]
    lines.extend(f"{item.get('extension_id')} {item.get('version')} - {item.get('description')}" for item in extensions)
    return "\n".join(lines)


def _plain_text_command_setup(view: RenderContext, payload: PayloadDict) -> str:
    detections = view._coerce_dict_list(payload.get("detections"))
    lines = [f"Recommended command ecosystems ({payload.get('recommended_count') or 0})"]
    for item in detections:
        if not item.get("recommended"):
            continue
        lines.append(f"{item.get('extension_id')} - recommended")
    lines.append("Detection is read-only. No Guard settings were changed.")
    return "\n".join(lines)


def _render_decision(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    decision = payload.get("decision")
    if not isinstance(decision, dict):
        view._render_fallback(console, payload)
        return
    body = view.Table.grid(padding=(0, 1))
    body.add_row("Harness", f"[bold]{decision.get('harness', 'unknown')}[/bold]")
    body.add_row("Scope", str(decision.get("scope", "harness")))
    body.add_row("Action", view._action_text(str(decision.get("action", "warn"))))
    body.add_row("Artifact", str(decision.get("artifact_id") or "all artifacts"))
    if decision.get("publisher"):
        body.add_row("Publisher", str(decision.get("publisher")))
    if decision.get("reason"):
        body.add_row("Reason", str(decision.get("reason")))
    console.print(view.Panel(body, title="Policy updated", border_style="green"))


def _render_hook(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    body = view.Table.grid(padding=(0, 1))
    body.add_row("Recorded", view._bool_label(bool(payload.get("recorded"))))
    body.add_row("Artifact", str(payload.get("artifact_name") or payload.get("artifact_id") or "unknown"))
    body.add_row("Decision", view._action_text(str(payload.get("policy_action", "warn"))))
    if payload.get("risk_summary"):
        body.add_row("Why", str(payload.get("risk_summary")))
    if payload.get("path_summary"):
        body.add_row("Path", str(payload.get("path_summary")))
    if payload.get("approval_center_url"):
        body.add_row("Approval center", str(payload.get("approval_center_url")))
    if payload.get("review_hint"):
        body.add_row("Review", str(payload.get("review_hint")))
    console.print(view.Panel(body, title="Guard hook event", border_style="cyan"))


def _render_explain(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    advisories = view._coerce_dict_list(payload.get("advisories"))
    if "artifact_snapshot" in payload:
        console.print(
            view.Panel(view._build_consumer_summary_table(payload), title="Path evidence", border_style="cyan")
        )
        view._render_consumer_evidence_panels(console, payload)
        view._render_cisco_evidence(console, payload)
        if advisories:
            console.print(view._build_advisory_table(advisories, title="Matching advisories"))
        return
    artifact = payload.get("artifact")
    if not isinstance(artifact, dict):
        view._render_fallback(console, payload)
        return
    latest_receipt = payload.get("latest_receipt")
    latest_diff = payload.get("latest_diff")
    body = view.Table.grid(padding=(0, 1))
    body.add_row("Artifact", str(artifact.get("artifact_name") or artifact.get("artifact_id") or "unknown"))
    body.add_row("Harness", str(artifact.get("harness") or "unknown"))
    body.add_row("Type", str(artifact.get("artifact_type") or "artifact"))
    body.add_row("Scope", str(artifact.get("source_scope") or "unknown"))
    body.add_row("Present", view._bool_label(bool(artifact.get("present"))))
    if isinstance(latest_receipt, dict):
        body.add_row("Latest decision", view._action_text(str(latest_receipt.get("policy_decision") or "warn")))
        body.add_row("Receipt time", str(latest_receipt.get("timestamp") or "unknown"))
    if isinstance(latest_diff, dict):
        changed_fields = ", ".join(view._coerce_string_list(latest_diff.get("changed_fields"))) or "no field changes"
        body.add_row("Latest diff", changed_fields)
        body.add_row("Current hash", str(latest_diff.get("current_hash") or "unknown"))
    body.add_row("Advisories", str(len(advisories)))
    console.print(view.Panel(body, title="Guard artifact evidence", border_style="cyan"))
    if advisories:
        console.print(view._build_advisory_table(advisories, title="Matching advisories"))


def _render_preflight(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    install_verdict = payload.get("install_verdict")
    install_target = payload.get("install_target")
    body = view.Table.grid(padding=(0, 1))
    if isinstance(install_target, dict):
        body.add_row("Target", str(install_target.get("path") or "."))
        body.add_row("Harness", str(install_target.get("intended_harness") or "not specified"))
    if isinstance(install_verdict, dict):
        body.add_row("Install verdict", view._action_text(str(install_verdict.get("action") or "review")))
        body.add_row("Can install", view._bool_label(bool(install_verdict.get("can_install"))))
        body.add_row("Reason", str(install_verdict.get("reason") or "unknown"))
    threat_intelligence = payload.get("threat_intelligence")
    if isinstance(threat_intelligence, dict):
        body.add_row("Verdict source", str(threat_intelligence.get("verdict_source") or "local-scan"))
        body.add_row("Highest severity", str(threat_intelligence.get("highest_severity") or "info"))
        body.add_row("Findings", str(threat_intelligence.get("finding_count") or 0))
    console.print(view.Panel(body, title="Install-time preflight", border_style="cyan"))
    console.print(view.Panel(view._build_consumer_summary_table(payload), title="Artifact scan", border_style="blue"))
    view._render_consumer_evidence_panels(console, payload)
    view._render_cisco_evidence(console, payload)
