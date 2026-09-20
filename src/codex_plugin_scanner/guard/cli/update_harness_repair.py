"""Managed harness repairs through the existing update facade."""

from __future__ import annotations

from ..adapters.base import HarnessContext
from ..store import GuardStore
from .update_subprocess import TrustedUpdateContext


def _repair_supported_harnesses(
    *,
    context: HarnessContext | None,
    store: GuardStore | None,
    workspace: str | None,
    now: str | None,
    dry_run: bool,
    update_context: TrustedUpdateContext,
) -> tuple[list[dict[str, object]], list[str]]:
    """Repair managed harnesses in the updater's already-bound interpreter."""

    if dry_run or context is None or store is None or now is None:
        return [], []
    repair_payload = {
        "home_dir": str(context.home_dir),
        "workspace_dir": str(context.workspace_dir) if context.workspace_dir is not None else workspace,
        "guard_home": str(context.guard_home),
        "home_override_explicit": context.home_override_explicit,
        "now": now,
    }
    try:
        result = update_context.run(
            update_context.python_command(_update._HARNESS_REPAIR_SCRIPT),
            input_text=_update.json.dumps(repair_payload),
            timeout_seconds=_update._HARNESS_REPAIR_TIMEOUT_SECONDS,
        )
    except _update.UpdateSubprocessError as error:
        return [], [f"Could not repair supported harnesses during update: {error.reason_code}"]
    if result.output_limited:
        return [], ["Could not repair supported harnesses during update: update_installer_output_limit"]
    if result.returncode != 0:
        return [], ["Could not repair supported harnesses during update: update_repair_failed"]
    try:
        repair_result = _update.json.loads(result.stdout)
    except _update.json.JSONDecodeError:
        return [], ["Could not repair supported harnesses during update: update_repair_output_invalid"]
    if not isinstance(repair_result, dict) or set(repair_result) != {"managed_installs", "notes"}:
        return [], ["Could not repair supported harnesses during update: update_repair_output_invalid"]
    raw_installs = repair_result.get("managed_installs")
    raw_notes = repair_result.get("notes")
    if not isinstance(raw_installs, list) or not isinstance(raw_notes, list):
        return [], ["Could not repair supported harnesses during update: update_repair_output_invalid"]
    if not all(isinstance(item, dict) for item in raw_installs) or not all(isinstance(item, str) for item in raw_notes):
        return [], ["Could not repair supported harnesses during update: update_repair_output_invalid"]
    return [dict(item) for item in raw_installs], [str(item) for item in raw_notes]


def _repair_supported_harnesses_in_process(
    *,
    context: HarnessContext,
    store: GuardStore,
    workspace: str | None,
    now: str,
    dry_run: bool,
) -> tuple[list[dict[str, object]], list[str]]:
    """Perform repair after the trusted subprocess boundary has been crossed."""

    if dry_run:
        return [], []
    repaired_codex, codex_warning = _update._repair_codex_install(
        context=context,
        store=store,
        workspace=workspace,
        now=now,
    )
    repaired_installs = [repaired_codex] if repaired_codex is not None else []
    repair_notes = [codex_warning] if codex_warning is not None else []
    repaired_cursor, cursor_warning = _update._repair_cursor_install(
        context=context,
        store=store,
        workspace=workspace,
        now=now,
    )
    if repaired_cursor is not None:
        repaired_installs.append(repaired_cursor)
    if cursor_warning is not None:
        repair_notes.append(cursor_warning)
    _update.append_grok_repair(
        repaired_installs, repair_notes, context=context, store=store, workspace=workspace, now=now
    )
    for harness, display_name in (("pi", "Pi"), ("omp", "Oh My Pi")):
        repaired_pi_family, pi_family_warning = _update._repair_pi_family_install(
            harness=harness,
            display_name=display_name,
            context=context,
            store=store,
            workspace=workspace,
            now=now,
        )
        if repaired_pi_family is not None:
            repaired_installs.append(repaired_pi_family)
        if pi_family_warning is not None:
            repair_notes.append(pi_family_warning)
    opencode_note = _update._refresh_opencode_pretool_plugin(context=context, store=store)
    if opencode_note is not None:
        repair_notes.append(opencode_note)
    return repaired_installs, repair_notes


def _repair_pi_family_install(
    *,
    harness: str,
    display_name: str,
    context: HarnessContext,
    store: GuardStore,
    workspace: str | None,
    now: str,
) -> tuple[dict[str, object] | None, str | None]:
    """Rewrite one managed Pi-family extension after package updates."""

    try:
        managed_install = store.get_managed_install(harness)
    except (_update.json.JSONDecodeError, _update.sqlite3.Error):
        return None, None
    if managed_install is None or not bool(managed_install.get("active")):
        return None, None
    try:
        repair_context, repair_workspace = _update._repair_context_from_managed_install(context, managed_install)
        if _update._pi_family_extension_is_current(harness=harness, context=repair_context):
            return None, None
        payload = _update.apply_managed_install(
            "install",
            harness,
            False,
            repair_context,
            store,
            repair_workspace or workspace,
            now,
        )
    except (OSError, RuntimeError, ValueError, _update.json.JSONDecodeError, _update.sqlite3.Error) as error:
        return None, f"Could not refresh {display_name} protection during update: {error}"
    repaired = payload.get("managed_install")
    if not isinstance(repaired, dict):
        return None, f"Could not refresh {display_name} protection during update: managed install was not recorded"
    return repaired, None


def _pi_family_extension_is_current(*, harness: str, context: HarnessContext) -> bool:
    """Return whether the managed Pi/OMP extension already matches this package."""

    adapter: _update.PiHarnessAdapter | _update.OmpHarnessAdapter
    if harness == "pi":
        adapter = _update.PiHarnessAdapter()
    elif harness == "omp":
        adapter = _update.OmpHarnessAdapter()
    else:
        return False
    extension_path = adapter._managed_extension_path(context)
    settings_path = adapter._managed_settings_path(context)
    if not extension_path.is_file():
        return False
    expected_source = _update.managed_extension_source(
        guard_home=context.guard_home,
        home_dir=context.home_dir,
        settings_path=settings_path,
        harness=adapter.harness,
        display_name=adapter.display_name,
    )
    try:
        current_source = extension_path.read_text(encoding="utf-8")
    except OSError:
        return False
    if current_source != expected_source:
        return False
    settings = _update.json_payload(settings_path) if settings_path.is_file() else {}
    raw_extensions = settings.get("extensions")
    if not isinstance(raw_extensions, list):
        return False
    extension_value = str(extension_path)
    return any(isinstance(item, str) and item == extension_value for item in raw_extensions)


def _repair_cursor_install(
    *,
    context: HarnessContext,
    store: GuardStore,
    workspace: str | None,
    now: str,
) -> tuple[dict[str, object] | None, str | None]:
    try:
        managed_install = store.get_managed_install("cursor")
    except (_update.json.JSONDecodeError, _update.sqlite3.Error):
        return None, None
    if managed_install is None or not bool(managed_install.get("active")):
        return None, None
    manifest = managed_install.get("manifest")
    if not isinstance(manifest, dict):
        return None, "Could not inspect Cursor protection during update: managed manifest is invalid"
    surface_value = manifest.get("surface")
    surface: str | None = (
        surface_value if isinstance(surface_value, str) and surface_value in {"editor", "all"} else None
    )
    if surface is None:
        return None, None
    try:
        repair_context, repair_workspace = _update._repair_context_from_managed_install(context, managed_install)
        hook_state = _update.cursor_native_hook_state(repair_context)
    except (OSError, RuntimeError, ValueError, _update.json.JSONDecodeError, _update.sqlite3.Error) as error:
        return None, f"Could not inspect Cursor protection during update: {error}"
    if hook_state["protection_active"] is True:
        return None, None
    try:
        repair_surface = None if surface == "all" else surface
        payload = _update.apply_managed_install(
            "install",
            "cursor",
            False,
            repair_context,
            store,
            repair_workspace or workspace,
            now,
            surface=repair_surface,
        )
    except (OSError, RuntimeError, ValueError, _update.json.JSONDecodeError, _update.sqlite3.Error) as error:
        return None, f"Could not repair Cursor protection during update: {error}"
    repaired = payload.get("managed_install")
    if not isinstance(repaired, dict):
        return None, "Could not repair Cursor protection during update: managed install was not recorded"
    return repaired, None


def _refresh_opencode_pretool_plugin(
    *,
    context: HarnessContext,
    store: GuardStore,
) -> str | None:
    try:
        managed_install = store.get_managed_install("opencode")
    except (_update.json.JSONDecodeError, _update.sqlite3.Error):
        return None
    if managed_install is None or not bool(managed_install.get("active")):
        return None
    try:
        repair_context, _ = _update._repair_context_from_managed_install(context, managed_install)
    except ValueError as error:
        return f"Could not inspect OpenCode pretool plugin during update: {error}"
    global_path = _update.global_plugin_path(repair_context)
    managed_path = _update.managed_plugin_path(repair_context)
    try:
        expected_source = _update.pretool_plugin_source(repair_context)
    except (OSError, RuntimeError) as error:
        return f"Could not inspect OpenCode pretool plugin during update: {error}"
    try:
        global_source = global_path.read_text(encoding="utf-8") if global_path.is_file() else ""
        managed_source = managed_path.read_text(encoding="utf-8") if managed_path.is_file() else ""
    except OSError as error:
        return f"Could not inspect OpenCode pretool plugin during update: {error}"
    if global_source == expected_source and managed_source == expected_source:
        return None
    try:
        _update.install_pretool_plugin(repair_context)
    except (OSError, RuntimeError) as error:
        return f"Could not refresh OpenCode pretool plugin during update: {error}"
    return "Refreshed the OpenCode pretool plugin during update. Restart OpenCode to load it."


def _repair_codex_install(
    *,
    context: HarnessContext,
    store: GuardStore,
    workspace: str | None,
    now: str,
) -> tuple[dict[str, object] | None, str | None]:
    try:
        repair_target = _update._codex_repair_target(context, store)
    except ValueError as error:
        return None, f"Could not inspect Codex protection during update: {error}"
    if repair_target is None:
        return None, None
    repair_context, repair_workspace = repair_target
    try:
        hook_state = _update.codex_native_hook_state(repair_context)
    except (OSError, RuntimeError) as error:
        return None, f"Could not inspect Codex protection during update: {error}"
    if (
        bool(hook_state["protection_active"])
        and hook_state.get("integrity_status") == "valid"
        and bool(hook_state["shell_protection_active"])
    ):
        return None, None
    try:
        payload = _update.apply_managed_install(
            "install",
            "codex",
            False,
            repair_context,
            store,
            repair_workspace,
            now,
        )
    except (OSError, RuntimeError, ValueError, _update.json.JSONDecodeError, _update.sqlite3.Error) as error:
        return None, f"Could not repair Codex protection during update: {error}"
    try:
        repaired_state = _update.codex_native_hook_state(repair_context)
    except (OSError, RuntimeError) as error:
        return None, f"Could not verify repaired Codex protection during update: {error}"
    if not bool(repaired_state.get("protection_active")) or repaired_state.get("integrity_status") != "valid":
        reason = str(repaired_state.get("integrity_reason") or "codex_hook_integrity_readback_failed")
        return None, f"Could not verify repaired Codex protection during update: {reason}"
    managed_install = payload.get("managed_install")
    return (managed_install if isinstance(managed_install, dict) else None), None


def _codex_repair_target(context: HarnessContext, store: GuardStore) -> tuple[HarnessContext, str | None] | None:
    try:
        managed_install = store.get_managed_install("codex")
    except (_update.json.JSONDecodeError, _update.sqlite3.Error):
        return _update._codex_backup_repair_target(context)
    if managed_install is not None and bool(managed_install.get("active")):
        return _update._repair_context_from_managed_install(context, managed_install)
    return _update._codex_backup_repair_target(context)


def _codex_backup_repair_target(context: HarnessContext) -> tuple[HarnessContext, str | None] | None:
    for repair_context in _update._codex_backup_repair_contexts(context):
        if not _update.CodexHarnessAdapter._backup_path(repair_context).is_file():
            continue
        repair_workspace = str(repair_context.workspace_dir) if repair_context.workspace_dir is not None else None
        return repair_context, repair_workspace
    return None


def _codex_backup_repair_contexts(context: HarnessContext) -> tuple[HarnessContext, ...]:
    return (context,)


# Bind the facade after definitions so either module can be imported first.
from . import update_commands as _update  # noqa: E402
