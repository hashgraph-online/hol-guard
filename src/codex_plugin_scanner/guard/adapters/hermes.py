"""Hermes harness adapter.

Discovers Hermes skills (SKILL.md + subdirectory files) and MCP servers
configured in the Hermes config directory (default ~/.hermes, or $HERMES_HOME).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import yaml as _yaml  # type: ignore[import-untyped]

from ...safe_output import write_text_atomic_no_follow
from ..aibom_detection import native_adapter_detection_with_warnings
from ..models import HarnessDetection
from ..native_path_anchor import anchor_to_process_directory
from ..shims import install_guard_shim, remove_guard_shim
from ..skill_directory_identity import (
    inspect_skill_directory,
    skill_directory_identity_metadata,
)
from . import hermes_runtime_hooks
from .adapter_safe_output import write_text_at_authorized_path
from .adapter_state_integrity import authenticate_adapter_state
from .base import HarnessAdapter, HarnessContext, _command_available, _json_payload, _run_command_probe
from .bounded_cli_hook_bridge import bounded_cli_hook_command
from .cloud_identity import cloud_agent_identity_environment, cloud_agent_identity_hints
from .hermes_file_inspection import (
    HermesConfigInspection,
    inspect_hermes_config,
)
from .hermes_state_paths import (
    hermes_cleanup_values,
    hermes_install_config_path,
    hermes_install_paths,
    hermes_manifest,
    hermes_previous_guard_for_install,
    hermes_uninstall_state,
    remove_hermes_managed_files,
    validated_hermes_managed_paths,
)

_HERMES_MANAGED_APPROVAL_TIER = "native-or-center"
_HERMES_MANAGED_PROMPT_CHANNEL = "native"
_GUARD_PRETOOL_INTERNAL_TIMEOUT_SECONDS = 3
_GUARD_PRETOOL_HOST_TIMEOUT_SECONDS = 5


def _hermes_home(context: HarnessContext) -> Path:
    """Resolve the Hermes home directory.

    Hermes reads its config from ``get_hermes_home()`` which checks the
    ``HERMES_HOME`` env var first, falling back to ``~/.hermes``.  Guard must
    use the same resolution so config.yaml is written where Hermes expects it.
    """
    env_home = os.environ.get("HERMES_HOME")
    if env_home and env_home.strip():
        return Path(env_home.strip())
    return context.home_dir / ".hermes"


def _hermes_host_home(context: HarnessContext) -> Path | None:
    """Resolve the host's real Hermes home when running inside a container.

    Hermes agents often run inside Docker containers with a minimal sandbox
    config (``mcp_servers: {}``) and an empty skills directory.  The host's
    real Hermes installation — with the full config.yaml and 200+ skills — is
    not mounted into the container.

    When the operator sets ``HERMES_HOST_HOME``, ``detect()`` can fall back to
    scanning the mounted host installation even from inside the container.
    A persisted ``~/hermes-host-home`` mirror is also recognized because
    Hermes sandbox launchers may not preserve custom environment variables.

    Returns ``None`` when neither location exists.
    """
    env_host = os.environ.get("HERMES_HOST_HOME")
    if env_host and env_host.strip():
        host_path = Path(env_host.strip())
        return host_path if host_path.is_dir() else None

    fallback_path = context.home_dir / "hermes-host-home"
    return fallback_path if fallback_path.is_dir() else None


def _hermes_home_has_artifacts(hermes_home: Path) -> bool:
    """Check whether a Hermes home directory has any discoverable artifacts.

    Returns True when config.yaml or config.toml exists and is non-trivial
    (>300 bytes), when config.yaml contains mcp_servers entries, when
    mcp_servers.json contains configured servers, or when the skills
    directory has at least one SKILL.md file.
    """
    for config_name in ("config.yaml", "config.toml"):
        config_path = hermes_home / config_name
        if config_path.is_file():
            try:
                if config_path.stat().st_size > 300:
                    return True
            except OSError:
                pass
    # Check if config.yaml has mcp_servers entries (even if small).
    yaml_path = hermes_home / "config.yaml"
    if yaml_path.is_file():
        try:
            if _parse_mcp_from_yaml(yaml_path):
                return True
        except (ValueError, OSError):
            # An unreadable or malformed primary config is still an artifact.
            # Treat it as populated so an incomplete sandbox cannot inherit
            # unrelated MCP configuration from a host-home mirror.
            return True
    json_path = hermes_home / "mcp_servers.json"
    if json_path.is_file():
        try:
            servers = _parse_mcp_from_json(json_path)
            if servers:
                return True
        except (ValueError, OSError):
            return True
    skills_dir = hermes_home / "skills"
    if skills_dir.is_dir():
        try:
            for category_dir in skills_dir.iterdir():
                if not category_dir.is_dir():
                    continue
                for skill_dir in category_dir.iterdir():
                    if skill_dir.is_dir() and (skill_dir / "SKILL.md").is_file():
                        return True
        except (PermissionError, OSError):
            pass
    return False


def _manifest_notes(payload: dict[str, object]) -> list[str]:
    notes = payload.get("notes")
    if not isinstance(notes, list):
        return []
    return [str(note) for note in notes]


class HermesHarnessAdapter(HarnessAdapter):
    """Discover Hermes skills and MCP servers."""

    harness = "hermes"
    executable = "hermes"
    approval_tier = "approval-center"
    approval_summary = (
        "Guard can scan Hermes skills before execution and hand blocked artifacts to the local approval center."
    )
    fallback_hint = "Configure Hermes to use Guard-launched sessions for skill execution."

    def install(self, context: HarnessContext) -> dict[str, object]:
        hermes_home = _hermes_home(context)
        source_configs = _load_mcp_server_sources(hermes_home)
        # Only consult the mirror for a minimal sandbox, matching detect().
        host_home = _hermes_host_home(context)
        if host_home and host_home.resolve() != hermes_home.resolve() and not _hermes_home_has_artifacts(hermes_home):
            for key, config in _load_mcp_server_sources(host_home).items():
                source_configs.setdefault(key, config)

        # Parse every source completely before making any installation change.
        shim_manifest = install_guard_shim(self.harness, context)
        managed_root = _managed_root(context)
        manifest_path, overlay_path, pretool_path = hermes_install_paths(context, managed_root)
        managed_root.mkdir(parents=True, exist_ok=True)
        existing_manifest = _json_payload(manifest_path)
        install_state = _install_state(
            existing_manifest=existing_manifest,
            overlay_path=overlay_path,
            pretool_path=pretool_path,
        )
        overlay_servers = _overlay_servers(context=context, source_configs=source_configs)
        cloud_identity = cloud_agent_identity_hints(context, runtime=self.harness)
        write_text_atomic_no_follow(overlay_path, json.dumps(overlay_servers, indent=2) + "\n")
        write_text_atomic_no_follow(
            pretool_path,
            json.dumps(_pretool_payload(context=context), indent=2) + "\n",
        )
        config_yaml_path = hermes_install_config_path(context, _hermes_home(context))
        previous_managed_names = _read_managed_server_names(context)
        new_managed_names, previous_guard_section, config_written = _write_guard_to_hermes_config_yaml(
            context=context,
            config_yaml_path=config_yaml_path,
            overlay_servers=overlay_servers,
            managed_names=previous_managed_names,
        )
        if config_written:
            _write_managed_server_names(context, new_managed_names)
            existing_previous_guard = _previous_guard_section_path(context)
            if not existing_previous_guard.exists():
                _write_previous_guard_section(context, previous_guard_section)
        authenticated_previous_guard = hermes_previous_guard_for_install(
            context,
            existing_manifest,
            previous_guard_section,
        )
        manifest = {
            "harness": self.harness,
            "active": True,
            "config_path": str(overlay_path),
            "hermes_config_yaml_path": str(config_yaml_path),
            "hermes_config_yaml_resolved_path": str(config_yaml_path.resolve()),
            **shim_manifest,
            "install_state": install_state,
            "managed_root": str(managed_root),
            "managed_manifest_path": str(manifest_path),
            "mcp_overlay_path": str(overlay_path),
            "pretool_hook_path": str(pretool_path),
            "managed_server_names": new_managed_names if config_written else [],
            "previous_guard_section": authenticated_previous_guard,
            "capabilities": {
                "same_channel": True,
                "pretool": True,
                "mcp_proxy": True,
            },
            "servers": _manifest_servers(source_configs),
            "notes": [
                "Guard generated a Hermes MCP overlay, fail-closed hooks.pre_tool_call entry, and MCP proxy bundle.",
                *_manifest_notes(shim_manifest),
            ],
        }
        if cloud_identity is not None:
            manifest["cloud_agent_identity"] = cloud_identity
        manifest = authenticate_adapter_state(context.guard_home, harness=self.harness, payload=manifest)
        write_text_atomic_no_follow(manifest_path, json.dumps(manifest, indent=2) + "\n")
        return manifest

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = remove_guard_shim(self.harness, context)
        managed_root = _managed_root(context)
        _manifest, config_yaml_path = hermes_uninstall_state(context, managed_root, _hermes_home(context))
        removed_paths = remove_hermes_managed_files(context, managed_root)
        managed_names, previous_guard = (
            hermes_cleanup_values(context, _manifest, config_yaml_path) if config_yaml_path else ([], None)
        )
        if config_yaml_path is not None:
            _remove_guard_from_hermes_config_yaml(
                config_yaml_path=config_yaml_path,
                managed_names=managed_names,
                previous_guard=previous_guard,
            )
        managed_servers_manifest = _managed_servers_manifest_path(context)
        if managed_servers_manifest.exists():
            managed_servers_manifest.unlink()
            removed_paths.append(str(managed_servers_manifest))
        previous_guard_manifest = _previous_guard_section_path(context)
        if previous_guard_manifest.exists():
            previous_guard_manifest.unlink()
            removed_paths.append(str(previous_guard_manifest))
        return {
            "harness": self.harness,
            "active": False,
            "config_path": str(managed_root / "mcp-overlay.json"),
            **shim_manifest,
            "removed_paths": removed_paths,
            "notes": [
                "Guard removed the managed Hermes overlay bundle and cleaned Guard-managed entries from config.yaml.",
                *_manifest_notes(shim_manifest),
            ],
        }

    def launch_environment(self, context: HarnessContext) -> dict[str, str]:
        managed_root = _managed_root(context)
        manifest = hermes_manifest(context, managed_root)
        managed_paths = validated_hermes_managed_paths(context, manifest, managed_root)
        if managed_paths is None:
            return {}
        overlay_path, pretool_path = managed_paths
        environment = {
            "HERMES_GUARD_MCP_OVERLAY_PATH": str(overlay_path),
            "HERMES_GUARD_PRETOOL_PATH": str(pretool_path),
        }
        environment.update(
            cloud_agent_identity_environment(
                cloud_agent_identity_hints(context, runtime=self.harness),
                prefix="HERMES",
            )
        )
        return environment

    def runtime_probe(self, context: HarnessContext) -> dict[str, object] | None:
        managed_root = _managed_root(context)
        manifest = hermes_manifest(context, managed_root)
        managed_paths = validated_hermes_managed_paths(context, manifest, managed_root)
        overlay_path, pretool_path = managed_paths or (None, None)
        hook_registered = hermes_runtime_hooks.hermes_runtime_hook_registered(_hermes_home(context) / "config.yaml")
        return {
            "command": _run_command_probe([self.executable, "--help"]) if _command_available(self.executable) else None,
            "managed_install_present": bool(manifest),
            "runtime_hook_registered": hook_registered,
            "managed_install_ready": (
                overlay_path is not None
                and overlay_path.exists()
                and pretool_path is not None
                and pretool_path.exists()
                and hook_registered
            ),
            "cloud_agent_identity_configured": bool(cloud_agent_identity_hints(context, runtime=self.harness)),
        }

    def diagnostic_warnings(self, detection: HarnessDetection, runtime_probe: dict[str, object] | None) -> list[str]:
        warnings = super().diagnostic_warnings(detection, runtime_probe)
        warning = hermes_runtime_hooks.hermes_runtime_hook_warning(runtime_probe)
        if warning is not None:
            warnings.append(warning)
        return warnings

    def diagnostics(self, context: HarnessContext) -> dict[str, object]:
        payload = super().diagnostics(context)
        hermes_runtime_hooks.apply_hermes_doctor_protection_label(payload)
        return payload

    def approval_flow(self, *, managed_install: dict[str, object] | None = None) -> dict[str, object]:
        manifest = managed_install.get("manifest") if isinstance(managed_install, dict) else None
        capabilities = manifest.get("capabilities") if isinstance(manifest, dict) else None
        same_channel = isinstance(capabilities, dict) and bool(capabilities.get("same_channel"))
        if same_channel:
            return {
                "tier": _HERMES_MANAGED_APPROVAL_TIER,
                "summary": (
                    "Guard uses the managed Hermes same-channel seam first and falls back to the approval center."
                ),
                "fallback_hint": "Use the Guard approval center if Hermes does not surface the pending request inline.",
                "prompt_channel": _HERMES_MANAGED_PROMPT_CHANNEL,
                "auto_open_browser": False,
            }
        return {
            "tier": "approval-center",
            "summary": "Guard keeps Hermes approvals in the local approval center without forcing a browser open.",
            "fallback_hint": "Resolve pending Hermes requests from the Guard approval center.",
            "prompt_channel": "native-fallback",
            "auto_open_browser": False,
        }

    def detect(self, context: HarnessContext) -> HarnessDetection:
        # The native resident owns skill, MCP and config discovery, the host-home
        # mirror fallback and the manifest fallback. Python resolves the homes and
        # the managed server names and fails closed without the resident.
        hermes_home = anchor_to_process_directory(_hermes_home(context))
        host_home = _hermes_host_home(context)
        request: dict[str, object] = {
            "harness": self.harness,
            "hermes_home": hermes_home,
            "host_home": None if host_home is None else anchor_to_process_directory(host_home),
            "managed_names": _read_managed_server_names(context),
            "manifest_path": anchor_to_process_directory(_managed_root(context) / "manifest.json"),
        }
        if _native_cannot_walk_skills():
            roots = [hermes_home] if host_home is None else [hermes_home, anchor_to_process_directory(host_home)]
            request["skill_identities"] = _portable_skill_identities(roots)
        artifacts, found_paths, warnings = native_adapter_detection_with_warnings("hermes_detect", request)
        command_available = _command_available(self.executable)
        return HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or command_available,
            command_available=command_available,
            artifacts=artifacts,
            config_paths=found_paths,
            warnings=warnings,
        )


# ------------------------------------------------------------------
# Module-level helpers (no dependency on adapter instance)
# ------------------------------------------------------------------


def _native_cannot_walk_skills() -> bool:
    """Whether the resident's unix file-descriptor skill walk cannot serve this host."""

    return os.name == "nt"


def _sorted_children(directory: Path) -> list[Path]:
    try:
        return sorted(directory.iterdir())
    except OSError:
        return []


def _portable_skill_identities(homes: list[str]) -> dict[str, dict[str, object]]:
    """Finished skill directory identities, keyed by SKILL.md path, for hosts the resident cannot walk."""

    identities: dict[str, dict[str, object]] = {}
    for home in homes:
        skills_dir = Path(home) / "skills"
        if not skills_dir.is_dir():
            continue
        for category_dir in _sorted_children(skills_dir):
            if not category_dir.is_dir():
                continue
            for skill_dir in _sorted_children(category_dir):
                skill_md = skill_dir / "SKILL.md"
                if not (skill_dir.is_dir() and skill_md.is_file()):
                    continue
                identity = inspect_skill_directory(skill_md, scope_root=skills_dir)
                identities[str(skill_md)] = {
                    "metadata": skill_directory_identity_metadata(
                        identity, version_label=f"{category_dir.name}/{skill_dir.name}"
                    ),
                    "complete": identity.status == "complete",
                    "failure_reason": identity.failure_reason,
                }
    return identities


class _HermesConfigInspectionError(ValueError):
    def __init__(self, path: Path, inspection: HermesConfigInspection) -> None:
        reason = inspection.reason or "config_parse_error"
        super().__init__(f"Hermes config inspection failed for {path}: {reason}")
        self.inspection = inspection


def _mcp_servers_from_payload(payload: dict[str, object]) -> dict[str, dict[str, object]]:
    mcp = payload.get("mcp_servers")
    if not isinstance(mcp, dict):
        return {}
    return {name: config for name, config in mcp.items() if isinstance(name, str) and isinstance(config, dict)}


def _parse_mcp_from_yaml(yaml_path: Path) -> dict[str, dict[str, object]]:
    """Extract MCP entries only from a complete, bounded YAML mapping."""

    inspection = inspect_hermes_config(yaml_path, syntax="yaml")
    if not inspection.complete or inspection.payload is None:
        raise _HermesConfigInspectionError(yaml_path, inspection)
    return _mcp_servers_from_payload(inspection.payload)


def _parse_mcp_from_json(json_path: Path) -> dict[str, dict[str, object]]:
    """Parse MCP servers only from a complete, bounded JSON mapping."""

    inspection = inspect_hermes_config(json_path, syntax="json")
    if not inspection.complete or inspection.payload is None:
        raise _HermesConfigInspectionError(json_path, inspection)
    return {name: config for name, config in inspection.payload.items() if isinstance(config, dict)}


def _managed_root(context: HarnessContext) -> Path:
    return context.guard_home / "hermes"


def _load_mcp_server_sources(hermes_home: Path) -> dict[str, dict[str, object]]:
    sources: dict[str, dict[str, object]] = {}
    yaml_path = hermes_home / "config.yaml"
    if yaml_path.is_file():
        for name, config in _parse_mcp_from_yaml(yaml_path).items():
            if config.get("enabled", True) is False:
                continue
            if name.startswith(_GUARD_MCP_SERVER_PREFIX):
                continue
            sources[f"yaml:{name}"] = {
                "name": name,
                "source": "yaml",
                "config_path": str(yaml_path),
                **config,
            }
    json_path = hermes_home / "mcp_servers.json"
    if json_path.is_file():
        for name, config in _parse_mcp_from_json(json_path).items():
            if config.get("enabled", True) is False:
                continue
            if name.startswith(_GUARD_MCP_SERVER_PREFIX):
                continue
            sources[f"json:{name}"] = {
                "name": name,
                "source": "json",
                "config_path": str(json_path),
                **config,
            }
    return sources


def _overlay_servers(
    *,
    context: HarnessContext,
    source_configs: dict[str, dict[str, object]],
) -> dict[str, dict[str, object]]:
    overlay: dict[str, dict[str, object]] = {}
    names_in_use: set[str] = set()
    for server_key, server in source_configs.items():
        overlay_name = _overlay_name(server_key, server, names_in_use)
        overlay[overlay_name] = {
            "command": str(Path(sys.executable)),
            "args": _mcp_proxy_command(context=context, server_key=server_key),
            "transport": "stdio",
            "metadata": {
                "guard_server_key": server_key,
                "guard_transport": "remote" if isinstance(server.get("url"), str) else "stdio",
                "guard_config_path": str(server.get("config_path") or ""),
            },
        }
    return overlay


def _overlay_name(server_key: str, server: dict[str, object], names_in_use: set[str]) -> str:
    raw_name = server.get("name")
    candidate = str(raw_name) if isinstance(raw_name, str) and raw_name else server_key
    if candidate not in names_in_use:
        names_in_use.add(candidate)
        return candidate
    base_candidate = server_key.replace(":", "-")
    scoped_candidate = base_candidate
    suffix = 2
    while scoped_candidate in names_in_use:
        scoped_candidate = f"{base_candidate}-{suffix}"
        suffix += 1
    names_in_use.add(scoped_candidate)
    return scoped_candidate


def _mcp_proxy_command(*, context: HarnessContext, server_key: str) -> list[str]:
    command = [
        "-m",
        "codex_plugin_scanner.cli",
        "hermes",
        "mcp-proxy",
        "--guard-home",
        str(context.guard_home),
    ]
    if context.home_dir.resolve() != Path.home().resolve():
        command.extend(["--home", str(context.home_dir)])
    if context.workspace_dir is not None:
        command.extend(["--workspace", str(context.workspace_dir)])
    command.extend(["--server", server_key, "--stdio"])
    return command


def _pretool_payload(*, context: HarnessContext) -> dict[str, object]:
    cli_args = [
        "guard",
        "hook",
        "--guard-home",
        str(context.guard_home),
        "--harness",
        "hermes",
    ]
    if context.home_dir.resolve() != Path.home().resolve():
        cli_args.extend(["--home", str(context.home_dir)])
    cli_args.append("--json")
    return {
        "command": list(
            bounded_cli_hook_command(
                python_executable=sys.executable,
                package_root=Path(__file__).resolve().parents[3],
                guard_home=context.guard_home,
                cli_args=cli_args,
                harness="hermes",
                timeout_seconds=_GUARD_PRETOOL_INTERNAL_TIMEOUT_SECONDS,
            )
        ),
        "harness": "hermes",
        "timeout_seconds": _GUARD_PRETOOL_HOST_TIMEOUT_SECONDS,
        "fail_open": False,
    }


def _manifest_servers(source_configs: dict[str, dict[str, object]]) -> dict[str, dict[str, object]]:
    servers: dict[str, dict[str, object]] = {}
    for server_key, server in source_configs.items():
        args = server.get("args")
        env = server.get("env")
        headers = server.get("headers")
        servers[server_key] = {
            "name": str(server.get("name") or server_key),
            "source": str(server.get("source") or "unknown"),
            "config_path": str(server.get("config_path") or ""),
            "transport": "http" if isinstance(server.get("url"), str) else "stdio",
            "command": server.get("command") if isinstance(server.get("command"), str) else None,
            "args": _manifest_args(args),
            "url": server.get("url") if isinstance(server.get("url"), str) else None,
            "env": _manifest_env(env),
            "headers": (
                {str(key): value for key, value in headers.items() if isinstance(key, str) and isinstance(value, str)}
                if isinstance(headers, dict)
                else {}
            ),
        }
    return servers


def _manifest_args(args: object) -> list[str]:
    if not isinstance(args, list):
        return []
    return [str(value) for value in args if isinstance(value, (str, int, float, bool))]


def _manifest_env(env: object) -> dict[str, str]:
    if not isinstance(env, dict):
        return {}
    return {
        str(key): str(value)
        for key, value in env.items()
        if isinstance(key, str) and isinstance(value, (str, int, float, bool))
    }


# Marker prefix for Guard-managed MCP server names in Hermes config.yaml.
# Using a prefix makes it easy to identify Guard entries while remaining
# distinct from user-configured servers that might coincidentally start with
# the same prefix.  The manifest file is the source of truth for which
# entries Guard owns — the prefix alone is not sufficient because a user
# may have pre-existing servers named ``guard-*``.
_GUARD_MCP_SERVER_PREFIX = "guard-"

# Key used for the Guard section in Hermes config.yaml.
_GUARD_CONFIG_KEY = "guard"

# Default Guard Cloud consumer API base URL.  Used when the issuer cannot be
# resolved from the local Guard store (e.g. not yet connected).
_DEFAULT_GUARD_CONSUMER_BASE_URL = "https://hol.org/api/v1/consumer"

# State key used by the Guard store for the OAuth local credentials payload.
_OAUTH_LOCAL_CREDENTIALS_STATE_KEY = "oauth_local_credentials"


def _resolve_guard_consumer_base_url(context: HarnessContext) -> str:
    """Resolve the Guard Cloud consumer API base URL from the local Guard store.

    Reads the OAuth issuer from ``guard.db`` and derives the consumer API URL.
    Falls back to the default ``hol.org`` endpoint when the issuer cannot be
    resolved (e.g. not yet connected).
    """
    db_path = context.guard_home / "guard.db"
    if not db_path.exists():
        return _DEFAULT_GUARD_CONSUMER_BASE_URL
    try:
        import sqlite3

        db_uri = f"{db_path.resolve().as_uri()}?mode=ro"
        connection = sqlite3.connect(db_uri, uri=True)
        try:
            row = connection.execute(
                "select payload_json from sync_state where state_key = ?",
                (_OAUTH_LOCAL_CREDENTIALS_STATE_KEY,),
            ).fetchone()
        finally:
            connection.close()
    except Exception:
        return _DEFAULT_GUARD_CONSUMER_BASE_URL
    if row is None:
        return _DEFAULT_GUARD_CONSUMER_BASE_URL
    try:
        payload = json.loads(str(row[0]))
    except (json.JSONDecodeError, TypeError):
        return _DEFAULT_GUARD_CONSUMER_BASE_URL
    issuer = payload.get("issuer") if isinstance(payload, dict) else None
    if not isinstance(issuer, str) or not issuer.strip():
        return _DEFAULT_GUARD_CONSUMER_BASE_URL
    # Derive the consumer API base URL from the issuer origin.
    # The issuer is a full URL like https://hol.org — the consumer API is at
    # {origin}/api/v1/consumer.
    from urllib.parse import urlsplit

    parsed = urlsplit(issuer.strip())
    if not parsed.scheme or not parsed.netloc:
        return _DEFAULT_GUARD_CONSUMER_BASE_URL
    return f"{parsed.scheme}://{parsed.netloc}/api/v1/consumer"


# Filename under the managed root that records which config.yaml mcp_servers
# entries were created by Guard.  This avoids deleting user-owned servers that
# happen to share the ``guard-`` prefix.
_GUARD_MANAGED_SERVERS_MANIFEST = "managed-servers.json"

# Filename under the managed root that records the user's existing guard
# section so it can be restored on uninstall.
_GUARD_PREVIOUS_SECTION_MANIFEST = "previous-guard-section.json"


def _managed_servers_manifest_path(context: HarnessContext) -> Path:
    return _managed_root(context) / _GUARD_MANAGED_SERVERS_MANIFEST


def _read_managed_server_names(context: HarnessContext) -> list[str]:
    path = _managed_servers_manifest_path(context)
    data = _json_payload(path)
    names = data.get("servers")
    if not isinstance(names, list):
        return []
    return [str(n) for n in names if isinstance(n, str)]


def _write_managed_server_names(context: HarnessContext, names: list[str]) -> None:
    path = _managed_servers_manifest_path(context)
    path.parent.mkdir(parents=True, exist_ok=True)
    write_text_atomic_no_follow(path, json.dumps({"servers": names}, indent=2) + "\n")


def _previous_guard_section_path(context: HarnessContext) -> Path:
    return _managed_root(context) / _GUARD_PREVIOUS_SECTION_MANIFEST


def _write_previous_guard_section(context: HarnessContext, section: dict[str, object] | None) -> None:
    path = _previous_guard_section_path(context)
    path.parent.mkdir(parents=True, exist_ok=True)
    write_text_atomic_no_follow(path, json.dumps({"guard": section}, indent=2) + "\n")


def _write_guard_to_hermes_config_yaml(
    *,
    context: HarnessContext,
    config_yaml_path: Path,
    overlay_servers: dict[str, dict[str, object]],
    managed_names: list[str],
) -> tuple[list[str], dict[str, object] | None, bool]:
    """Write Guard-managed MCP proxy entries, guard section, and runtime hooks."""
    config_yaml_path.parent.mkdir(parents=True, exist_ok=True)

    # Load existing config.
    existing: dict[str, Any] = {}
    if config_yaml_path.exists():
        inspection = inspect_hermes_config(config_yaml_path, syntax="yaml")
        if not inspection.complete or inspection.payload is None:
            return [], None, False
        existing = inspection.payload

    # Capture the user's existing guard section so uninstall can restore it.
    previous_guard = existing.get(_GUARD_CONFIG_KEY)
    if not isinstance(previous_guard, dict):
        previous_guard = None

    # Build the new mcp_servers dict: keep user servers, remove old Guard entries
    # (identified by the manifest, not by prefix — avoids deleting user servers
    # that happen to start with the same prefix).
    managed_set = set(managed_names)
    mcp_servers = existing.get("mcp_servers")
    if not isinstance(mcp_servers, dict):
        mcp_servers = {}
    cleaned: dict[str, Any] = {
        name: cfg for name, cfg in mcp_servers.items() if isinstance(name, str) and name not in managed_set
    }
    # Add current overlay servers with Guard prefix.
    new_managed: list[str] = []
    for overlay_name, overlay_config in overlay_servers.items():
        key = f"{_GUARD_MCP_SERVER_PREFIX}{overlay_name}"
        cleaned[key] = overlay_config
        new_managed.append(key)
    existing["mcp_servers"] = cleaned

    # Write the guard section so Hermes's guard_runtime_policy.py activates.
    existing[_GUARD_CONFIG_KEY] = {
        "enabled": True,
        "base_url": _resolve_guard_consumer_base_url(context),
        "timeout_seconds": _GUARD_PRETOOL_HOST_TIMEOUT_SECONDS,
        "cache_ttl_seconds": 60,
        "fail_open": False,
        "token_env_var": "HERMES_GUARD_TOKEN",
        "enforce_mcp_tools": True,
        "pain_signals_enabled": True,
    }

    hermes_runtime_hooks.sync_guard_runtime_hooks(
        existing,
        command=_pretool_payload(context=context)["command"],
        timeout_seconds=_GUARD_PRETOOL_HOST_TIMEOUT_SECONDS,
        hermes_home=config_yaml_path.parent,
    )

    write_text_at_authorized_path(config_yaml_path, _yaml.dump(existing, default_flow_style=False, sort_keys=False))
    return new_managed, previous_guard, True


def _remove_guard_from_hermes_config_yaml(
    *,
    config_yaml_path: Path,
    managed_names: list[str],
    previous_guard: dict[str, object] | None = None,
) -> None:
    """Remove Guard-managed MCP, guard section, and runtime hook entries."""
    if not config_yaml_path.exists():
        return
    inspection = inspect_hermes_config(config_yaml_path, syntax="yaml")
    if not inspection.complete or inspection.payload is None:
        return
    raw = inspection.payload

    managed_set = set(managed_names)
    mcp_servers = raw.get("mcp_servers")
    if isinstance(mcp_servers, dict):
        cleaned = {name: cfg for name, cfg in mcp_servers.items() if isinstance(name, str) and name not in managed_set}
        raw["mcp_servers"] = cleaned

    hermes_runtime_hooks.unsync_guard_runtime_hooks(raw, hermes_home=config_yaml_path.parent)

    # Restore the user's previous guard section, or remove it if there wasn't one.
    if previous_guard is not None:
        raw[_GUARD_CONFIG_KEY] = previous_guard
    else:
        raw.pop(_GUARD_CONFIG_KEY, None)

    write_text_at_authorized_path(config_yaml_path, _yaml.dump(raw, default_flow_style=False, sort_keys=False))


def _install_state(
    *,
    existing_manifest: dict[str, object],
    overlay_path: Path,
    pretool_path: Path,
) -> str:
    if len(existing_manifest) == 0:
        return "installed"
    overlay_exists = overlay_path.exists()
    pretool_exists = pretool_path.exists()
    if overlay_exists and pretool_exists:
        return "already_managed"
    return "repaired_managed_install"
