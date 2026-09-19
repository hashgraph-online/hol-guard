"""health presentation for Guard CLI output."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .render import Console, Panel
    from .render_context import RenderContext


def _render_doctor(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    if "desktop_notifications" in payload:
        desktop = payload.get("desktop_notifications")
        if not isinstance(desktop, dict):
            desktop = {}
        summary = view.Table.grid(padding=(0, 1))
        summary.add_row("Platform", f"[bold]{desktop.get('platform', 'unknown')}[/bold]")
        summary.add_row("Supported", view._bool_label(bool(desktop.get("supported"))))
        summary.add_row("Preview sent", view._bool_label(bool(desktop.get("preview_sent"))))
        summary.add_row("Settings opened", view._bool_label(bool(desktop.get("settings_opened"))))
        summary.add_row("Already prompted", view._bool_label(bool(desktop.get("already_prompted"))))
        notifier_path = desktop.get("notifier_path")
        if notifier_path:
            summary.add_row("Notifier", str(notifier_path))
        settings_url = desktop.get("settings_url")
        if settings_url:
            summary.add_row("Settings URL", str(settings_url))
        console.print(view.Panel(summary, title="Guard notification setup", border_style="cyan"))
    elif "adapters" in payload:
        tables = view._coerce_string_list(payload.get("tables"))
        name, protection_off = view._protection_status_copy(payload, "protected")
        protection_line = f"[bold red]protection: {name} (off)[/bold red]" if protection_off else f"protection: {name}"
        console.print(
            view.Panel.fit(
                f"[bold]HOL Guard doctor[/bold]\n{protection_line}\n{len(tables)} local tables checked",
                border_style="red" if protection_off else "cyan",
            )
        )
        adapters = view._coerce_dict_list(payload.get("adapters"))
        console.print(view._build_harness_table(adapters))
    elif "harnesses" in payload and all(
        "install_aliases" in h for h in view._coerce_dict_list(payload.get("harnesses"))
    ):
        contracts = view._coerce_dict_list(payload.get("harnesses"))
        table = view.Table(title="HOL Guard supported harnesses", box=view.box.SIMPLE_HEAD, show_lines=False)
        table.add_column("Harness", style="bold cyan", no_wrap=True)
        table.add_column("Install alias", style="dim")
        table.add_column("Events")
        table.add_column("Native approval")
        table.add_column("Known blind spots")
        for contract in contracts:
            aliases = ", ".join(view._coerce_string_list(contract.get("install_aliases")))
            events = ", ".join(view._coerce_string_list(contract.get("event_surfaces")))
            native = "\u2713" if bool(contract.get("native_approval")) else "-"
            blind_spots = str(contract.get("known_blind_spots") or "")
            table.add_row(
                str(contract.get("harness", "")),
                aliases,
                events,
                native,
                view.textwrap.shorten(blind_spots, width=60),
            )
        console.print(table)
    else:
        warnings = view._coerce_string_list(payload.get("warnings"))
        summary = view.Table.grid(padding=(0, 1))
        summary.add_row("Harness", f"[bold]{payload.get('harness', 'unknown')}[/bold]")
        summary.add_row("Installed", view._bool_label(bool(payload.get("installed"))))
        summary.add_row("Command", view._bool_label(bool(payload.get("command_available"))))
        summary.add_row("Artifacts", str(len(view._coerce_dict_list(payload.get("artifacts")))))
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
        name, protection_off = view._protection_status_copy(payload, "")
        if name:
            value = f"[bold red]{name} (off)[/bold red]" if protection_off else name
            summary.add_row("Protection", value)
        console.print(view.Panel(summary, title="Guard doctor", border_style="cyan"))
        if warnings:
            warning_text = "\n".join(
                view.textwrap.fill(
                    f"• {warning}",
                    width=72,
                    subsequent_indent="  ",
                )
                for warning in warnings
            )
            console.print(view.Panel(view.Text(warning_text), title="Attention", border_style="yellow"))
        runtime_probe = payload.get("runtime_probe")
        if isinstance(runtime_probe, dict):
            console.print(view._build_runtime_probe_panel(runtime_probe))
        artifacts = view._coerce_dict_list(payload.get("artifacts"))
        if artifacts:
            console.print(view._build_artifact_table(artifacts))
        supply_chain = payload.get("supply_chain")
        if isinstance(supply_chain, dict):
            console.print(view._build_supply_chain_posture_panel(supply_chain))
    trust = payload.get("trust")
    if isinstance(trust, dict):
        console.print(view._build_trust_doctor_panel(trust))
    perf_items = payload.get("detector_perf")
    if isinstance(perf_items, list) and perf_items:
        perf_table = view.Table(title="Detector performance", box=view.box.SIMPLE_HEAVY, show_header=True)
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
    console.print(view._build_diagnostic_command_panel())


def _build_trust_doctor_panel(view: RenderContext, trust: dict[str, object]) -> Panel:
    body = view.Table.grid(padding=(0, 1))
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
        body.add_row("Local rules protected", view._bool_label(bool(checks.get("local_rules_protected"))))
        body.add_row("Passive no-UI check", view._bool_label(bool(checks.get("passive_no_ui"))))
    approval_center = trust.get("approval_center")
    if isinstance(approval_center, dict):
        body.add_row("Approval center", str(approval_center.get("approval_url_base") or "inactive"))
        if approval_center.get("port") is not None:
            body.add_row("Approval port", str(approval_center.get("port")))
        detail = approval_center.get("detail")
        if isinstance(detail, str) and detail.strip():
            body.add_row("Approval route", view.textwrap.fill(detail.strip(), width=72))
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
        body.add_row("Summary", view.textwrap.fill(summary.strip(), width=72))
    actions = view._coerce_string_list(trust.get("recommended_actions"))
    if actions:
        body.add_row("Next", "\n".join(view.textwrap.fill(f"* {action}", width=72) for action in actions))
    border_style = "green" if str(trust.get("remembered_rules") or "") == "enforced" else "yellow"
    return view.Panel(body, title="Local trust", border_style=border_style)


def _render_trust_doctor(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    console.print(view._build_trust_doctor_panel(payload))
    console.print(view._build_diagnostic_command_panel())


def _render_trust_explain(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    rule = payload.get("rule")
    if not isinstance(rule, dict):
        view._render_fallback(console, payload)
        return
    body = view.Table.grid(padding=(0, 1))
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
        body.add_row("Why", view.textwrap.fill(rule_status_reason.strip(), width=72))
    trust_status = payload.get("trust_status")
    if isinstance(trust_status, dict):
        body.add_row("Runtime", str(trust_status.get("runtime_protection") or "unknown"))
        body.add_row("Local trust", str(trust_status.get("remembered_rules") or "unknown"))
        body.add_row("Cloud", str(trust_status.get("cloud_policies") or "unknown"))
    console.print(view.Panel(body, title="Remembered rule authority", border_style="cyan"))


def _build_supply_chain_posture_panel(view: RenderContext, supply_chain: dict[str, object]) -> Panel:
    body = view.Table.grid(padding=(0, 1))
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
    ecosystems = view._coerce_dict_list(supply_chain.get("supported_ecosystems"))
    if ecosystems:
        support_summary = ", ".join(
            f"{item.get('display_name') or item.get('ecosystem')}: {item.get('support_label') or item.get('label')}"
            for item in ecosystems[:5]
        )
        if len(ecosystems) > 5:
            support_summary = f"{support_summary}, +{len(ecosystems) - 5} more"
        body.add_row("Coverage", support_summary)
    return view.Panel(body, title="Supply-chain firewall", border_style="cyan")


def _build_runtime_probe_panel(view: RenderContext, runtime_probe: dict[str, object]) -> Panel:
    body = view.Table.grid(padding=(0, 1))
    body.add_row("Command", view._command_text(runtime_probe.get("command")))
    body.add_row("Succeeded", view._bool_label(bool(runtime_probe.get("ok"))))
    if runtime_probe.get("return_code") is not None:
        body.add_row("Return code", str(runtime_probe.get("return_code")))
    if runtime_probe.get("reported_artifacts") is not None:
        body.add_row("CLI artifacts", str(runtime_probe.get("reported_artifacts")))
    if runtime_probe.get("stderr"):
        body.add_row("stderr", str(runtime_probe.get("stderr")))
    if runtime_probe.get("stdout"):
        stdout = view._clean_terminal_output(str(runtime_probe.get("stdout")))
        preview = "\n".join(stdout.splitlines()[:6])
        body.add_row("stdout", preview)
    return view.Panel(body, title="Runtime probe", border_style="magenta")


def _build_cloud_summary_panel(view: RenderContext, payload: dict[str, object]) -> Panel:
    cloud_state = str(payload.get("cloud_state") or "local_only")
    body = view.Table.grid(padding=(0, 1))
    body.add_row("State", f"[bold]{payload.get('cloud_state_label', 'Local only')}[/bold]")
    body.add_row("Summary", str(payload.get("cloud_state_detail") or "Guard is running on this machine."))
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
    return view.Panel(body, title="Local to cloud", border_style=view._cloud_border_style(cloud_state))


def _cloud_border_style(view: RenderContext, cloud_state: str) -> str:
    if cloud_state == "paired_active":
        return "green"
    if cloud_state == "paired_waiting":
        return "yellow"
    return "cyan"
