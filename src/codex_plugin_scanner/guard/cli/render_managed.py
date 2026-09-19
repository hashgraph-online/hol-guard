"""managed presentation for Guard CLI output."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .render import Console, Panel, Table
    from .render_context import RenderContext


def _render_managed_install(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    skill_scan = view._coerce_dict_list(payload.get("skill_scan"))
    supply_chain_risks = view._coerce_dict_list(payload.get("supply_chain_risks"))
    safe_decode_risks = view._coerce_dict_list(payload.get("safe_decode_risks"))
    sandbox_analysis = view._coerce_dict_list(payload.get("sandbox_analysis"))
    if bool(payload.get("self_uninstall")):
        view.render_self_uninstall(console, payload)
    managed_install = payload.get("managed_install")
    if isinstance(managed_install, dict):
        view._render_single_managed_install(console, managed_install)
    else:
        managed_installs = view._coerce_dict_list(payload.get("managed_installs"))
        if not managed_installs:
            if (
                not bool(payload.get("self_uninstall"))
                and not skill_scan
                and not supply_chain_risks
                and not safe_decode_risks
                and not sandbox_analysis
            ):
                view._render_fallback(console, payload)
                return
        else:
            console.print(
                view.Panel(
                    view._managed_install_batch_summary(payload, managed_installs),
                    title="Guard managed harnesses",
                    border_style="cyan",
                )
            )
            console.print(view._managed_install_batch_table(managed_installs))
            notes = view._managed_install_batch_notes(managed_installs)
            if notes:
                console.print(view._notes_panel(notes))
    if skill_scan:
        view._render_skill_scan_results(console, skill_scan)
    if supply_chain_risks:
        view._render_supply_chain_risk_results(console, supply_chain_risks)
    if safe_decode_risks:
        view._render_safe_decode_results(console, safe_decode_risks)
    if sandbox_analysis:
        view._render_sandbox_results(console, sandbox_analysis)


def _render_apps(view: RenderContext, console: Console, payload: dict[str, object]) -> None:
    if payload.get("managed_install") or payload.get("managed_installs"):
        view._render_managed_install(console, payload)
    else:
        view._render_fallback(console, payload)
    dry_run_effect = payload.get("dry_run_effect")
    if isinstance(dry_run_effect, str) and dry_run_effect:
        console.print(view.Panel(dry_run_effect, title="Dry run", border_style="yellow"))
    cloud_app = payload.get("cloud_app")
    if not isinstance(cloud_app, dict):
        return
    body = view.Table.grid(padding=(0, 1))
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
        view.Panel(
            body,
            title="Guard Cloud app connect",
            border_style="green" if browser_opened else "yellow",
        )
    )


def _managed_install_workspace_label(view: RenderContext, workspace: object) -> str:
    if isinstance(workspace, str) and workspace.strip():
        return workspace.strip()
    return "global (~/.cursor)"


def _managed_install_config_label(view: RenderContext, manifest: dict[str, object]) -> str:
    for key in ("config_path", "managed_config_path"):
        value = manifest.get(key)
        if isinstance(value, str) and value.strip():
            return view._short_path(value.strip())
    hooks_path = manifest.get("managed_hooks_path")
    if isinstance(hooks_path, str) and hooks_path.strip():
        return f"hooks updated ({view._short_path(hooks_path.strip())})"
    return "no config changed"


def _render_single_managed_install(view: RenderContext, console: Console, managed_install: dict[str, object]) -> None:
    manifest = managed_install.get("manifest")
    notes = view._managed_install_notes(managed_install, manifest)
    body = view.Table.grid(padding=(0, 1))
    body.add_row("Harness", f"[bold]{managed_install.get('harness', 'unknown')}[/bold]")
    body.add_row("Protection", view._managed_install_state_text(managed_install))
    body.add_row("Workspace", view._managed_install_workspace_label(managed_install.get("workspace")))
    if isinstance(manifest, dict):
        mode = view._managed_install_mode_text(manifest.get("mode"))
        if mode is not None:
            body.add_row("Mode", mode)
        body.add_row("Config", view._managed_install_config_label(manifest))
        managed_servers = view._coerce_string_list(manifest.get("managed_servers"))
        if managed_servers:
            body.add_row("Managed servers", str(len(managed_servers)))
        skipped_servers = view._coerce_string_list(manifest.get("skipped_servers"))
        if skipped_servers:
            body.add_row("Skipped servers", str(len(skipped_servers)))
        if manifest.get("shim_command"):
            body.add_row("Launcher", str(manifest.get("shim_command")))
    console.print(view.Panel(body, title="Guard install state", border_style="cyan"))
    if notes:
        console.print(view._notes_panel(notes))


def _managed_install_batch_summary(
    view: RenderContext,
    payload: dict[str, object],
    managed_installs: list[dict[str, object]],
) -> Table:
    installed_count = sum(1 for item in managed_installs if bool(item.get("active")))
    removed_count = len(managed_installs) - installed_count
    body = view.Table.grid(padding=(0, 1))
    body.add_row("Harnesses", str(len(managed_installs)))
    if payload.get("auto_detected") is not None:
        body.add_row("Selection", "Auto-detected" if bool(payload.get("auto_detected")) else "Requested")
    body.add_row("Protection", f"{installed_count} installed • {removed_count} removed")
    return body


def _managed_install_batch_table(view: RenderContext, managed_installs: list[dict[str, object]]) -> Table:
    table = view.Table(box=view.box.SIMPLE_HEAVY, show_header=True, expand=True)
    table.add_column("Harness", style="bold", no_wrap=True)
    table.add_column("State", no_wrap=True)
    table.add_column("Mode", overflow="fold")
    table.add_column("Servers", justify="right", no_wrap=True)
    table.add_column("Config", overflow="fold")
    for item in managed_installs:
        manifest = item.get("manifest")
        mode = view._managed_install_mode_text(manifest.get("mode")) if isinstance(manifest, dict) else None
        managed_servers = (
            view._coerce_string_list(manifest.get("managed_servers")) if isinstance(manifest, dict) else []
        )
        config_path = manifest.get("config_path") if isinstance(manifest, dict) else None
        table.add_row(
            str(item.get("harness") or "unknown"),
            view._managed_install_state_text(item),
            mode or "—",
            str(len(managed_servers)) if managed_servers else "—",
            view._short_path(config_path) if config_path else "no config changed",
        )
    return table


def _managed_install_batch_notes(view: RenderContext, managed_installs: list[dict[str, object]]) -> list[str]:
    notes: list[str] = []
    for item in managed_installs:
        harness = str(item.get("harness") or "unknown")
        manifest = item.get("manifest")
        for note in view._managed_install_notes(item, manifest):
            notes.append(f"{harness}: {note}")
    return notes


def _notes_panel(view: RenderContext, notes: list[str]) -> Panel:
    return view.Panel(
        view.Text("\n".join(f"• {note}" for note in notes), overflow="fold", no_wrap=False),
        title="Notes",
        border_style="blue",
    )


def _managed_install_state_text(view: RenderContext, managed_install: dict[str, object]) -> str:
    return "Installed" if bool(managed_install.get("active")) else "Removed"


def _build_ecosystem_support_table(view: RenderContext, items: list[dict[str, object]]) -> Table:
    table = view.Table(title="Ecosystem support", box=view.box.SIMPLE_HEAVY, show_header=True)
    table.add_column("Ecosystem", style="bold")
    table.add_column("Coverage")
    for item in items:
        table.add_row(
            str(item.get("display_name") or item.get("ecosystem") or "unknown"),
            str(item.get("support_label") or "Monitor-only"),
        )
    return table


def _managed_install_mode_text(view: RenderContext, mode: object) -> str | None:
    if not isinstance(mode, str) or not mode.strip():
        return None
    normalized = mode.strip().lower()
    if normalized in view._KNOWN_MANAGED_INSTALL_MODES:
        return view._KNOWN_MANAGED_INSTALL_MODES[normalized]
    words = []
    for part in normalized.split("-"):
        lowered = part.lower()
        if lowered in view._MODE_ACRONYMS:
            words.append(lowered.upper())
        else:
            words.append(lowered.capitalize())
    return " ".join(words)


def _managed_install_notes(view: RenderContext, managed_install: dict[str, object], manifest: object) -> list[str]:
    if not isinstance(manifest, dict):
        if not bool(managed_install.get("active")):
            return ["Guard removed the managed wrapper configuration for this harness."]
        return []
    notes = view._coerce_string_list(manifest.get("notes"))
    skipped_servers = view._coerce_string_list(manifest.get("skipped_servers"))
    if skipped_servers:
        notes.append(f"Skipped existing server entries: {', '.join(skipped_servers)}")
    source_config_paths = view._coerce_string_list(manifest.get("source_config_paths"))
    if source_config_paths:
        notes.append(f"Source configs: {', '.join(source_config_paths)}")
    if not notes and not bool(managed_install.get("active")):
        notes.append("Guard removed the managed wrapper configuration for this harness.")
    return notes
