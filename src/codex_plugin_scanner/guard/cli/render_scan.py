"""scan presentation for Guard CLI output."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .render import Console, Table, Text
    from .render_context import RenderContext


def _render_supply_chain_risk_results(
    view: RenderContext,
    console: Console,
    supply_chain_risks: list[dict[str, object]],
) -> None:
    table = view.Table(box=view.box.SIMPLE_HEAVY, show_header=True, expand=True)
    table.add_column("Signal", overflow="fold")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Confidence", no_wrap=True)
    table.add_column("Explanation", overflow="fold")
    for entry in supply_chain_risks:
        severity = str(entry.get("severity", "medium")).lower()
        severity_color = view._SEVERITY_COLORS.get(severity, "white")
        table.add_row(
            str(entry.get("signal_id", "?")),
            f"[{severity_color}]{severity}[/{severity_color}]",
            str(entry.get("confidence", "?")),
            str(entry.get("plain_reason", "")),
        )
    console.print(
        view.Panel(
            table,
            title=f"[bold yellow]Supply chain risks — {len(supply_chain_risks)} signal(s)[/bold yellow]",
            border_style="yellow",
        )
    )


def _render_safe_decode_results(
    view: RenderContext,
    console: Console,
    safe_decode_risks: list[dict[str, object]],
) -> None:
    table = view.Table(box=view.box.SIMPLE_HEAVY, show_header=True, expand=True)
    table.add_column("Signal", overflow="fold")
    table.add_column("Layers", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Explanation", overflow="fold")
    for entry in safe_decode_risks:
        severity = str(entry.get("severity", "medium")).lower()
        severity_color = view._SEVERITY_COLORS.get(severity, "white")
        layers = str(entry.get("technical_detail") or "")
        table.add_row(
            str(entry.get("signal_id", "?")),
            layers[:60] if layers else "-",
            f"[{severity_color}]{severity}[/{severity_color}]",
            str(entry.get("plain_reason", "")),
        )
    console.print(
        view.Panel(
            table,
            title=f"[bold magenta]Encoded payload risks — {len(safe_decode_risks)} signal(s)[/bold magenta]",
            border_style="magenta",
        )
    )


def _render_sandbox_results(view: RenderContext, console: Console, sandbox_analysis: list[dict[str, object]]) -> None:
    table = view.Table(box=view.box.SIMPLE_HEAVY, show_header=True, expand=True)
    table.add_column("Signal", overflow="fold")
    table.add_column("Writes", justify="right", no_wrap=True)
    table.add_column("Network", justify="right", no_wrap=True)
    table.add_column("Processes", justify="right", no_wrap=True)
    table.add_column("Timed out", no_wrap=True)
    table.add_column("Exit code", no_wrap=True)
    for entry in sandbox_analysis:
        signals = view._coerce_string_list(entry.get("signals_detected"))
        signal_text = ", ".join(signals) if signals else "—"
        writes = view._coerce_string_list(entry.get("writes"))
        network = view._coerce_string_list(entry.get("network_attempts"))
        processes = view._coerce_string_list(entry.get("process_attempts"))
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
        view.Panel(
            table,
            title=f"[bold magenta]Sandbox analysis — {len(sandbox_analysis)} result(s)[/bold magenta]",
            border_style="magenta",
        )
    )


def _render_skill_scan_results(view: RenderContext, console: Console, skill_scan: list[dict[str, object]]) -> None:
    table = view.Table(box=view.box.SIMPLE_HEAVY, show_header=True, expand=True)
    table.add_column("Skill file", overflow="fold")
    table.add_column("Risks", justify="right", no_wrap=True)
    table.add_column("Severities", no_wrap=True)
    table.add_column("Signals", overflow="fold")
    for entry in skill_scan:
        severity_text = ", ".join(view._coerce_string_list(entry.get("severities")))
        signal_text = " ".join(view._coerce_string_list(entry.get("signal_ids")))
        risk_count = str(entry.get("risk_count", 0))
        table.add_row(str(entry.get("skill_path", "?")), risk_count, severity_text, signal_text)
    console.print(
        view.Panel(
            table,
            title=f"[bold red]Skill security scan — {len(skill_scan)} file(s) with risks[/bold red]",
            border_style="red",
        )
    )


def _cisco_status_text(view: RenderContext, status: str) -> Text:
    styles = {
        "enabled": "green",
        "skipped": "yellow",
        "unavailable": "yellow",
        "failed": "red",
    }
    return view.Text(status, style=styles.get(status, "white"))


def _render_cisco_evidence(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    cisco_evidence = payload.get("cisco_evidence")
    if not isinstance(cisco_evidence, dict):
        return
    body = view.Table.grid(padding=(0, 1))
    body.add_row("Mode", str(cisco_evidence.get("mode", "offline-only")).replace("-", " "))
    body.add_row("Status", view._cisco_status_text(str(cisco_evidence.get("status", "skipped"))))
    body.add_row("Findings", str(cisco_evidence.get("finding_count", 0)))
    body.add_row("Targets", str(cisco_evidence.get("target_count", 0)))
    body.add_row("Summary", str(cisco_evidence.get("summary", "No Cisco MCP evidence collected.")))
    for integration in view._coerce_dict_list(cisco_evidence.get("integrations")):
        body.add_row(
            str(integration.get("name", "cisco-mcp-scanner")),
            str(integration.get("message", "No Cisco MCP detail available.")),
        )
    console.print(view.Panel(body, title="Cisco static scan evidence", border_style="blue"))


def _build_consumer_summary_table(view: RenderContext, payload: dict[str, object]) -> Table:
    recommendation = payload.get("policy_recommendation")
    manifest = payload.get("capability_manifest")
    threat_intelligence = payload.get("threat_intelligence")
    evidence_bundle = payload.get("trust_evidence_bundle")
    provenance_record = payload.get("provenance_record")
    artifact_snapshot = payload.get("artifact_snapshot")
    artifact_path = "."
    if isinstance(artifact_snapshot, dict):
        artifact_path = str(artifact_snapshot.get("path") or artifact_snapshot.get("artifact_path") or ".")
    artifact_name = view.Path(artifact_path).name or artifact_path
    ecosystems = view._coerce_string_list(manifest.get("ecosystems")) if isinstance(manifest, dict) else []
    categories = view._coerce_string_list(manifest.get("category_names")) if isinstance(manifest, dict) else []
    packages = view._coerce_dict_list(manifest.get("packages")) if isinstance(manifest, dict) else []
    severity_counts = (
        evidence_bundle.get("severity_counts")
        if isinstance(evidence_bundle, dict) and isinstance(evidence_bundle.get("severity_counts"), dict)
        else {}
    )
    body = view.Table.grid(padding=(0, 1))
    body.add_row("Name", artifact_name)
    body.add_row("Artifact", artifact_path)
    body.add_row("Ecosystems", ", ".join(ecosystems) or "unknown")
    if categories:
        body.add_row("Categories", ", ".join(categories))
    if packages:
        body.add_row("Packages", str(len(packages)))
    if isinstance(recommendation, dict):
        body.add_row("Recommended action", view._action_text(str(recommendation.get("action", "review"))))
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


def _render_consumer_evidence_panels(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    evidence_bundle = payload.get("trust_evidence_bundle")
    if isinstance(evidence_bundle, dict):
        severity_counts = evidence_bundle.get("severity_counts")
        integrations = view._coerce_dict_list(evidence_bundle.get("integrations"))
        summary = view.Table.grid(padding=(0, 1))
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
            console.print(view.Panel(summary, title="Evidence summary", border_style="yellow"))
        findings = view._coerce_string_list(evidence_bundle.get("findings"))
        if findings:
            console.print(
                view.Panel(
                    "\n".join(f"• {item}" for item in findings[:5]),
                    title="Evidence highlights",
                    border_style="yellow",
                )
            )


def _render_scan(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    console.print(view.Panel(view._build_consumer_summary_table(payload), title="Consumer scan", border_style="cyan"))
    view._render_consumer_evidence_panels(console, payload)
    view._render_cisco_evidence(console, payload)


def _render_deep_scan(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    scan_type = str(payload.get("scan_type") or "unknown")
    status = str(payload.get("status") or "unknown")
    body = view.Table.grid(padding=(0, 1))
    body.add_row("Type", scan_type)
    body.add_row("Status", view._cisco_status_text(status))
    body.add_row("Mode", str(payload.get("mode") or "auto"))
    body.add_row("Findings", str(payload.get("finding_count") or 0))
    body.add_row("Targets", str(payload.get("targets_scanned") or 0))
    body.add_row("Analyzers", str(payload.get("analyzers_used") or 0))
    if payload.get("message"):
        body.add_row("Message", str(payload["message"]))
    console.print(view.Panel(body, title=f"Deep scan — {scan_type}", border_style="cyan"))
    findings = view._coerce_dict_list(payload.get("scanner_evidence") or payload.get("findings"))
    if findings:
        table = view.Table(box=view.box.SIMPLE_HEAVY, show_header=True)
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


def _render_protect(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    if str(payload.get("mode") or "") == "status":
        body = view.Table.grid(padding=(0, 1))
        body.add_row("Mode", "status")
        console.print(view.Panel(body, title="Install protection", border_style="cyan"))
        supply_chain = payload.get("supply_chain")
        if isinstance(supply_chain, dict):
            console.print(view._build_supply_chain_posture_panel(supply_chain))
        return
    verdict = payload.get("verdict")
    request = payload.get("request")
    body = view.Table.grid(padding=(0, 1))
    if isinstance(request, dict):
        body.add_row("Command", view._command_text(request.get("command")))
        body.add_row("Kind", str(request.get("install_kind") or "unknown"))
    if isinstance(verdict, dict):
        action = str(verdict.get("action") or "review")
        body.add_row("Action", view._action_text(action))
        body.add_row("Executed", view._bool_label(bool(payload.get("executed"))))
        body.add_row("Reason", str(verdict.get("reason") or "unknown"))
    console.print(view.Panel(body, title="Install protection", border_style="cyan"))
    supply_chain_evaluation = payload.get("supply_chain_evaluation")
    if isinstance(supply_chain_evaluation, dict):
        user_copy = supply_chain_evaluation.get("user_copy")
        if isinstance(user_copy, dict):
            harness_message = str(user_copy.get("harness_message") or "").strip()
            if harness_message:
                console.print(
                    view.Panel(
                        view.Text(harness_message, no_wrap=False, overflow="fold"),
                        title="Guard guidance",
                        border_style="magenta",
                    )
                )
    supply_chain = payload.get("supply_chain")
    if isinstance(supply_chain, dict):
        console.print(view._build_supply_chain_posture_panel(supply_chain))
    risk_signals = view._coerce_string_list(verdict.get("risk_signals")) if isinstance(verdict, dict) else []
    if risk_signals:
        console.print(
            view.Panel(
                "\n".join(f"• {item}" for item in risk_signals),
                title="Risk signals",
                border_style="yellow",
            )
        )
    targets = view._coerce_dict_list(payload.get("targets"))
    if targets:
        table = view.Table(box=view.box.SIMPLE_HEAVY, show_header=True)
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
