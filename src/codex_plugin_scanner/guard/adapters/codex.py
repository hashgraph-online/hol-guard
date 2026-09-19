"""Codex harness adapter."""

from __future__ import annotations

# Keep facade dependencies available to the live helper lookups.
import hashlib
import json
import shlex  # noqa: F401
import sys
from collections.abc import Mapping, Sequence
from copy import deepcopy  # noqa: F401
from pathlib import Path
from urllib.parse import urlencode  # noqa: F401

from ...version import __version__  # noqa: F401
from ..aibom_detection import (
    enrich_mcp_server_metadata,  # noqa: F401
    extend_codex_runtime_inventory,  # noqa: F401
    extend_detection_with_workspace_aibom,  # noqa: F401
)
from ..codex_config import dump_toml, read_toml_payload, write_toml_payload  # noqa: F401
from ..codex_hook_file_integrity import validate_regular_file  # noqa: F401
from ..codex_hook_integrity import (
    atomic_write_text,  # noqa: F401
    hook_manifest_path,  # noqa: F401
    hook_secret_path,  # noqa: F401
    remove_hook_manifest,  # noqa: F401
    remove_hook_secret_if_unused,  # noqa: F401
    restore_private_file,  # noqa: F401
    snapshot_regular_file,  # noqa: F401
    write_hook_manifest,  # noqa: F401
)
from ..codex_hook_inventory import (
    CODEX_HOOK_IDENTITY_SCHEMA,  # noqa: F401
    CODEX_HOOK_INVENTORY_UNMANAGED_EXECUTABLE,  # noqa: F401
    CodexHookInventory,  # noqa: F401
    CodexHookInventoryRecord,  # noqa: F401
    canonical_codex_hook_conflict_keys,  # noqa: F401
    canonical_codex_hook_group_identity,  # noqa: F401
    enumerate_codex_hooks,  # noqa: F401
)
from ..codex_hook_launch_runtime import isolated_daemon_start_command, isolated_guard_cli_command  # noqa: F401
from ..codex_hook_manifest import (
    CodexHookManifestSpec,  # noqa: F401
    build_authenticated_hook_manifest,  # noqa: F401
    load_hook_manifest_baseline,  # noqa: F401
    verify_live_hook_manifest,  # noqa: F401
)
from ..codex_hook_manifest import (
    assert_package_reauthentication_is_safe as _assert_package_reauthentication_is_safe,  # noqa: F401
)
from ..codex_hook_manifest import (
    manifest_bindings as _manifest_bindings,  # noqa: F401
)
from ..codex_hook_registration import (
    exact_legacy_hook_bindings,  # noqa: F401
    finalize_codex_doctor_setup_status,
    finalize_codex_doctor_warnings,
    install_managed_codex_hook_groups,  # noqa: F401
    overlay_live_owned_event_matches,  # noqa: F401
)
from ..codex_hook_registration import (
    remove_manifest_bound_hook_events as _remove_manifest_bound_hook_events,  # noqa: F401
)
from ..codex_hook_sources import (
    require_hook_inventory_sources_unchanged as _require_hook_inventory_sources_unchanged,  # noqa: F401
)
from ..codex_hook_sources import strict_json_object as _strict_json_object  # noqa: F401
from ..codex_hook_sources import strict_toml_object as _strict_toml_object  # noqa: F401
from ..config import MAX_APPROVAL_WAIT_TIMEOUT_SECONDS, load_guard_config, resolve_guard_home  # noqa: F401
from ..launcher import merge_guard_launcher_env
from ..models import GuardArtifact, HarnessDetection  # noqa: F401
from ..shims import install_guard_shim, remove_guard_shim  # noqa: F401
from ..stable_guard_cli import resolve_frozen_guard_cli  # noqa: F401
from .base import HarnessAdapter, HarnessContext, _command_available  # noqa: F401
from .codex_remote_control import (
    codex_remote_launch_environment,
    guarded_codex_launch_command,
    guarded_codex_launch_command_candidates,
    guarded_codex_launch_command_from_prefix,
)
from .mcp_servers import (
    ManagedMcpServer,
    is_guard_proxy_command,  # noqa: F401
    managed_stdio_servers,  # noqa: F401
    proxy_launcher_entry,
    skipped_stdio_server_names,  # noqa: F401
)
from .workspace_overrides import should_skip_workspace_override

_read_toml = read_toml_payload


from . import codex_adapter_inventory as _codex_inventory  # noqa: E402

_artifact_from_guard_proxy_args = _codex_inventory._artifact_from_guard_proxy_args


_parse_guard_proxy_args = _codex_inventory._parse_guard_proxy_args


_MANAGED_HOOK_STATUS_MESSAGE = "HOL Guard checking tool action"
_MANAGED_PROMPT_HOOK_STATUS_MESSAGE = "HOL Guard checking prompt"
_MANAGED_PERMISSION_HOOK_STATUS_MESSAGE = "HOL Guard checking Codex approval request"
_MANAGED_POST_TOOL_HOOK_STATUS_MESSAGE = "HOL Guard checking tool result"
_LEGACY_MANAGED_HOOK_STATUS_MESSAGES = {
    "HOL Guard checking Bash command",
    _MANAGED_HOOK_STATUS_MESSAGE,
    _MANAGED_PROMPT_HOOK_STATUS_MESSAGE,
    _MANAGED_PERMISSION_HOOK_STATUS_MESSAGE,
    _MANAGED_POST_TOOL_HOOK_STATUS_MESSAGE,
}
_MANAGED_HOOK_TIMEOUT_SECONDS = 30
_MANAGED_HOOK_TIMEOUT_GRACE_SECONDS = 5
_CODEX_GUARD_TOOL_MATCHER = "Bash|Read|Write|Edit|MultiEdit|^apply_patch$|mcp__.*"
_CODEX_GUARD_PERMISSION_MATCHER = "Bash|Read|Write|Edit|MultiEdit|^apply_patch$|mcp__.*"
_CODEX_GUARD_POST_TOOL_MATCHER = "Bash|Read|mcp__.*"
_SHELL_GUARD_BEGIN = "# >>> HOL Guard Codex shell guard >>>"
_SHELL_GUARD_END = "# <<< HOL Guard Codex shell guard <<<"
_AUTHORITATIVE_ENFORCEMENT_BOUNDARY = "codex-native-hooks"
_AUTHORITATIVE_HOOK_UNAVAILABLE_REASON = "codex_authoritative_hook_unavailable"


from . import codex_adapter_commands as _codex_commands  # noqa: E402

_hook_workspace_dir = _codex_commands._hook_workspace_dir


_json_object = _codex_inventory._json_object


_local_hook_command_parts_for_home_mode = _codex_commands._local_hook_command_parts_for_home_mode


_guard_python_executable = _codex_commands._guard_python_executable


_home_is_current = _codex_commands._home_is_current


_runtime_guard_home = _codex_commands._runtime_guard_home


_local_hook_command_parts = _codex_commands._local_hook_command_parts


def _daemon_start_command(
    guard_home: Path,
    home_dir: Path,
    *,
    python_executable: str = sys.executable,
) -> tuple[str, ...]:
    package_root = Path(__file__).resolve().parents[3]
    return isolated_daemon_start_command(
        python_executable,
        package_root,
        guard_home.resolve(strict=False),
        home_dir.resolve(strict=False),
    )


_hook_command_parts_for_home_mode = _codex_commands._hook_command_parts_for_home_mode


_hook_command_parts = _codex_commands._hook_command_parts


_hook_command = _codex_commands._hook_command


def _managed_hook_entry(
    context: HarnessContext,
    status_message: str,
    *,
    timeout_seconds: int = _MANAGED_HOOK_TIMEOUT_SECONDS,
) -> dict[str, object]:
    environment = merge_guard_launcher_env(pin_package=True)
    environment.update(codex_remote_launch_environment(context.home_dir))
    return {
        "type": "command",
        "command": _hook_command(context),
        "timeout": timeout_seconds,
        "statusMessage": status_message,
        "env": environment,
    }


_pre_tool_hook_group = _codex_commands._pre_tool_hook_group


_prompt_hook_group = _codex_commands._prompt_hook_group


_permission_request_hook_group = _codex_commands._permission_request_hook_group


_post_tool_hook_timeout_seconds = _codex_commands._post_tool_hook_timeout_seconds


_post_tool_hook_group = _codex_commands._post_tool_hook_group


_managed_hook_groups = _codex_commands._managed_hook_groups


from . import codex_adapter_manifest as _codex_manifest  # noqa: E402

_manifest_event_bindings = _codex_manifest._manifest_event_bindings


_hook_packaged_file_paths = _codex_manifest._hook_packaged_file_paths


_hook_manifest_spec = _codex_manifest._hook_manifest_spec


_current_install_legacy_bindings = _codex_manifest._current_install_legacy_bindings


_CODEX_HOOK_MIGRATION_CONFLICT = "codex_hook_migration_conflict"
_CODEX_HOOK_MIGRATION_READBACK_MISMATCH = "codex_hook_migration_readback_mismatch"


from . import codex_adapter_config_migration as _codex_config_migration  # noqa: E402

_append_unique_hook_groups = _codex_config_migration._append_unique_hook_groups


_migrate_hooks_json_into_config = _codex_config_migration._migrate_hooks_json_into_config


from . import codex_adapter_migration as _codex_migration  # noqa: E402

_canonical_hook_semantics = _codex_migration._canonical_hook_semantics


_require_hook_semantics_readback = _codex_migration._require_hook_semantics_readback


_migration_group_identities = _codex_migration._migration_group_identities


_unmanaged_migration_payload = _codex_migration._unmanaged_migration_payload


_write_hook_migration_backup = _codex_migration._write_hook_migration_backup


_codex_hook_inventory = _codex_inventory._codex_hook_inventory


_require_complete_preactivation_inventory = _codex_inventory._require_complete_preactivation_inventory


_codex_hook_artifacts = _codex_inventory._codex_hook_artifacts


_payload_has_hooks_feature_enabled = _codex_config_migration._payload_has_hooks_feature_enabled


from . import codex_adapter_hook_writes as _codex_hook_writes  # noqa: E402

_line_marker_at = _codex_hook_writes._line_marker_at


_find_line_marker = _codex_hook_writes._find_line_marker


_trailing_line_break_length = _codex_hook_writes._trailing_line_break_length


_remove_managed_shell_guard_blocks = _codex_hook_writes._remove_managed_shell_guard_blocks


_hooks_have_registered_entries = _codex_inventory._hooks_have_registered_entries


_verify_live_hook_manifest = _codex_manifest._verify_live_hook_manifest


codex_native_hook_state = _codex_manifest.codex_native_hook_state


_require_codex_authoritative_shell_hook = _codex_manifest._require_codex_authoritative_shell_hook


from . import codex_adapter_installation as _codex_installation  # noqa: E402


class CodexHarnessAdapter(HarnessAdapter):
    """Discover Codex MCP servers and wrapper surfaces."""

    harness = "codex"
    executable = "codex"
    approval_tier = "native-or-center"
    approval_summary = (
        "Guard uses native Codex PreToolUse hooks as the authoritative complete-command boundary, "
        "PermissionRequest hooks for Codex approval prompts, prompt hooks for sensitive file-read requests, "
        "keeps same-chat approvals for managed MCP tool calls, and falls back to the local approval center when "
        "Codex cannot answer."
    )
    fallback_hint = (
        "If Codex cannot render or return the inline approval request, or the native PreToolUse hook blocks a "
        "sensitive complete command, Guard will queue it in the local approval center."
    )
    approval_prompt_channel = "native"
    approval_auto_open_browser = False

    def launch_command(self, context: HarnessContext, passthrough_args: list[str]) -> list[str]:
        _require_codex_authoritative_shell_hook(context)
        return guarded_codex_launch_command(
            executable=self.resolved_executable(context) or self.executable,
            home_dir=context.home_dir,
            passthrough_args=passthrough_args,
        )

    def preview_launch_commands(
        self,
        context: HarnessContext,
        passthrough_args: list[str],
    ) -> tuple[list[str], ...]:
        _require_codex_authoritative_shell_hook(context)
        return guarded_codex_launch_command_candidates(
            executable=self.resolved_executable(context) or self.executable,
            home_dir=context.home_dir,
            passthrough_args=passthrough_args,
        )

    def launch_command_from_authorized_plan(
        self,
        context: HarnessContext,
        passthrough_args: list[str],
        *,
        authorized_executable_prefixes: Sequence[Sequence[str]],
        launch_environment: Mapping[str, str],
    ) -> list[str]:
        _require_codex_authoritative_shell_hook(context)
        prefixes = {tuple(prefix) for prefix in authorized_executable_prefixes if prefix}
        if len(prefixes) != 1:
            raise ValueError("Codex launch candidates do not share one authorized executable prefix.")
        return guarded_codex_launch_command_from_prefix(
            executable_prefix=prefixes.pop(),
            home_dir=context.home_dir,
            passthrough_args=passthrough_args,
            environ=launch_environment,
        )

    def launch_environment(self, context: HarnessContext) -> dict[str, str]:
        return codex_remote_launch_environment(context.home_dir)

    @staticmethod
    def _scope_for(context: HarnessContext, path: Path) -> str:
        if context.workspace_dir is not None and path.is_relative_to(context.workspace_dir):
            return "project"
        return "global"

    def policy_path(self, context: HarnessContext) -> Path:
        return context.home_dir / ".codex" / "config.toml"

    @staticmethod
    def _hooks_path(context: HarnessContext) -> Path:
        return context.home_dir / ".codex" / "hooks.json"

    @staticmethod
    def _all_hook_paths(context: HarnessContext) -> tuple[Path, ...]:
        paths = [context.home_dir / ".codex" / "hooks.json"]
        if context.workspace_dir is not None:
            paths.append(context.workspace_dir / ".codex" / "hooks.json")
        return tuple(paths)

    @staticmethod
    def _config_hook_pairs(context: HarnessContext) -> tuple[tuple[Path, Path], ...]:
        pairs = [(context.home_dir / ".codex" / "config.toml", context.home_dir / ".codex" / "hooks.json")]
        if context.workspace_dir is not None:
            pairs.append(
                (context.workspace_dir / ".codex" / "config.toml", context.workspace_dir / ".codex" / "hooks.json")
            )
        return tuple(pairs)

    detect = _codex_inventory.detect

    install = _codex_installation.install

    uninstall = _codex_installation.uninstall

    def diagnostics(self, context: HarnessContext) -> dict[str, object]:
        payload = super().diagnostics(context)
        hook_state = codex_native_hook_state(context)
        warning_items = payload.get("warnings")
        items = warning_items if isinstance(warning_items, list) else []
        warnings = finalize_codex_doctor_warnings([str(item) for item in items if isinstance(item, str)], hook_state)
        payload["warnings"] = warnings
        payload["setup_status"] = finalize_codex_doctor_setup_status(payload.get("setup_status"), hook_state, warnings)
        payload["native_hook_state"] = hook_state
        return payload

    @staticmethod
    def _target_config_path(context: HarnessContext) -> Path:
        return context.home_dir / ".codex" / "config.toml"

    @staticmethod
    def _hook_config_path(context: HarnessContext) -> Path:
        return context.home_dir / ".codex" / "config.toml"

    @staticmethod
    def _backup_path(context: HarnessContext) -> Path:
        target_path = str(CodexHarnessAdapter._target_config_path(context).resolve())
        digest = hashlib.sha256(target_path.encode("utf-8")).hexdigest()[:12]
        return context.guard_home / "managed" / "codex" / f"{digest}.backup.toml"

    def _proxy_server_entry(self, context: HarnessContext, server: ManagedMcpServer) -> dict[str, object]:
        return proxy_launcher_entry(
            proxy_command="codex-mcp-proxy",
            context=context,
            server=server,
        )

    _refresh_managed_proxy_interpreters = staticmethod(_codex_config_migration._refresh_managed_proxy_interpreters)

    _should_skip_workspace_override = staticmethod(should_skip_workspace_override)

    _load_hook_payloads = _codex_migration._load_hook_payloads

    _migrate_alternate_hook_configs = _codex_migration._migrate_alternate_hook_configs

    _remove_managed_hooks_from_alternate_configs = _codex_config_migration._remove_managed_hooks_from_alternate_configs

    _remove_managed_mcp_servers_from_alternate_configs = (
        _codex_config_migration._remove_managed_mcp_servers_from_alternate_configs
    )

    _verify_json_hook_migrations = _codex_migration._verify_json_hook_migrations

    _remove_json_hook_files = _codex_migration._remove_json_hook_files

    _install_hooks = _codex_hook_writes._install_hooks

    _install_config_hooks = staticmethod(_codex_hook_writes._install_config_hooks)

    _write_authenticated_hook_config = staticmethod(_codex_hook_writes._write_authenticated_hook_config)

    _uninstall_shell_guard = staticmethod(_codex_hook_writes._uninstall_shell_guard)

    _remove_shell_guard_block = staticmethod(_codex_hook_writes._remove_shell_guard_block)

    def _remove_hooks(self, context: HarnessContext, *, payloads: dict[Path, dict[str, object]] | None = None) -> Path:
        target_hooks_path = self._hooks_path(context)
        # JSON hook files created after install are foreign to the authenticated
        # TOML registration and must be preserved byte-for-byte on uninstall.
        del payloads
        return target_hooks_path

    @staticmethod
    def _write_hooks_payload(
        hooks_path: Path,
        payload: dict[str, object],
        *,
        original_payload: dict[str, object] | None = None,
    ) -> None:
        if original_payload is not None and payload == original_payload:
            return
        if payload:
            hooks_path.parent.mkdir(parents=True, exist_ok=True)
            hooks_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        elif hooks_path.exists():
            hooks_path.unlink()
