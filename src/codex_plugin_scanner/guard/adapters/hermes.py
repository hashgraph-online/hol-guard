"""Hermes harness adapter.

Discovers Hermes skills (SKILL.md + subdirectory files) and MCP servers
configured in the Hermes config directory (default ~/.hermes, or $HERMES_HOME).
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import yaml as _yaml  # type: ignore[import-untyped]

from ..aibom_detection import enrich_mcp_server_metadata
from ..inventory_cisco import run_cisco_inventory_scans
from ..inventory_contract import GuardAgentInventorySnapshot, inventory_snapshot_from_detection
from ..models import GuardArtifact, HarnessDetection
from ..shims import install_guard_shim, remove_guard_shim
from ..skill_directory_identity import (
    inspect_skill_directory,
    skill_directory_identity_metadata,
)
from .base import HarnessAdapter, HarnessContext, _command_available, _json_payload, _run_command_probe
from .cloud_identity import cloud_agent_identity_environment, cloud_agent_identity_hints
from .hermes_file_inspection import (
    HermesConfigInspection,
    HermesFileInspection,
    file_inspection_metadata,
    inspect_hermes_config,
    inspect_hermes_text_file,
    parse_hermes_yaml_mapping,
)

# Subdirectories within a skill that may contain executable or injectable content.
_SKILL_SUBDIRS = ("references", "templates", "scripts", "assets")

# File extensions whose content is scanned for risk signals.
_SCANNABLE_EXTENSIONS = {
    ".md",
    ".txt",
    ".py",
    ".sh",
    ".bash",
    ".js",
    ".ts",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
    ".cfg",
    ".ini",
    ".env",
}

# Filenames (no extension) that should be scanned in skill subdirectories.
_SCANNABLE_NAMES = {".env", "Makefile", "Dockerfile", "Procfile"}

_HERMES_MANAGED_APPROVAL_TIER = "native-or-center"
_HERMES_MANAGED_PROMPT_CHANNEL = "native"


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
        manifest_path = managed_root / "manifest.json"
        overlay_path = managed_root / "mcp-overlay.json"
        pretool_path = managed_root / "pretool-hook.json"
        managed_root.mkdir(parents=True, exist_ok=True)
        existing_manifest = _json_payload(manifest_path)
        install_state = _install_state(
            existing_manifest=existing_manifest,
            overlay_path=overlay_path,
            pretool_path=pretool_path,
        )
        overlay_servers = _overlay_servers(context=context, source_configs=source_configs)
        cloud_identity = cloud_agent_identity_hints(context, runtime=self.harness)
        overlay_path.write_text(json.dumps(overlay_servers, indent=2) + "\n", encoding="utf-8")
        pretool_path.write_text(
            json.dumps(_pretool_payload(context=context), indent=2) + "\n",
            encoding="utf-8",
        )
        config_yaml_path = _hermes_home(context) / "config.yaml"
        previous_managed_names = _read_managed_server_names(context)
        new_managed_names, previous_guard_section, config_written = _write_guard_to_hermes_config_yaml(
            context=context,
            config_yaml_path=config_yaml_path,
            overlay_servers=overlay_servers,
            managed_names=previous_managed_names,
        )
        # Update manifests if config.yaml was actually written (not bailed out).
        # We always write both manifests — even if new_managed_names is empty
        # (no MCP servers to proxy) or previous_guard_section is None (no
        # existing guard section), because the guard section was still written
        # and uninstall needs to know to remove it.
        if config_written:
            # Always write the manifest — even an empty list clears stale
            # entries from a prior install that had more servers.
            _write_managed_server_names(context, new_managed_names)
            # On reinstall, don't overwrite the saved previous guard section —
            # the one from the first install captured the user's original. If
            # we overwrote it with the Guard-managed section, uninstall would
            # restore Guard's defaults instead of removing the section.
            existing_previous_guard = _previous_guard_section_path(context)
            if not existing_previous_guard.exists():
                _write_previous_guard_section(context, previous_guard_section)
        manifest = {
            "harness": self.harness,
            "active": True,
            "config_path": str(overlay_path),
            "hermes_config_yaml_path": str(config_yaml_path),
            **shim_manifest,
            "install_state": install_state,
            "managed_root": str(managed_root),
            "managed_manifest_path": str(manifest_path),
            "mcp_overlay_path": str(overlay_path),
            "pretool_hook_path": str(pretool_path),
            "capabilities": {
                "same_channel": True,
                "pretool": True,
                "mcp_proxy": True,
            },
            "servers": _manifest_servers(source_configs),
            "notes": [
                "Guard generated a Hermes MCP overlay and pre-tool hook bundle.",
                "Guard wrote Guard-managed MCP proxy entries into the Hermes config.yaml.",
                *_manifest_notes(shim_manifest),
            ],
        }
        if cloud_identity is not None:
            manifest["cloud_agent_identity"] = cloud_identity
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        return manifest

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = remove_guard_shim(self.harness, context)
        managed_root = _managed_root(context)
        manifest_path = managed_root / "manifest.json"
        manifest = _json_payload(manifest_path)
        removed_paths: list[str] = []
        for key in ("managed_manifest_path", "mcp_overlay_path", "pretool_hook_path"):
            value = manifest.get(key)
            if not isinstance(value, str) or not value:
                continue
            path = Path(value)
            if path.exists():
                path.unlink()
                removed_paths.append(str(path))
        config_yaml_path_str = manifest.get("hermes_config_yaml_path")
        config_yaml_path = (
            Path(config_yaml_path_str)
            if isinstance(config_yaml_path_str, str) and config_yaml_path_str
            else _hermes_home(context) / "config.yaml"
        )
        managed_names = _read_managed_server_names(context)
        previous_guard = _read_previous_guard_section(context)
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
        manifest = _json_payload(_managed_root(context) / "manifest.json")
        overlay_path = manifest.get("mcp_overlay_path")
        pretool_path = manifest.get("pretool_hook_path")
        if not isinstance(overlay_path, str) or not isinstance(pretool_path, str):
            return {}
        environment = {
            "HERMES_GUARD_MCP_OVERLAY_PATH": overlay_path,
            "HERMES_GUARD_PRETOOL_PATH": pretool_path,
        }
        environment.update(
            cloud_agent_identity_environment(
                cloud_agent_identity_hints(context, runtime=self.harness),
                prefix="HERMES",
            )
        )
        return environment

    def runtime_probe(self, context: HarnessContext) -> dict[str, object] | None:
        manifest = _json_payload(_managed_root(context) / "manifest.json")
        overlay_path = manifest.get("mcp_overlay_path")
        pretool_path = manifest.get("pretool_hook_path")
        return {
            "command": _run_command_probe([self.executable, "--help"]) if _command_available(self.executable) else None,
            "managed_install_present": bool(manifest),
            "managed_install_ready": (
                isinstance(overlay_path, str)
                and Path(overlay_path).exists()
                and isinstance(pretool_path, str)
                and Path(pretool_path).exists()
            ),
            "cloud_agent_identity_configured": bool(cloud_agent_identity_hints(context, runtime=self.harness)),
        }

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
        hermes_home = _hermes_home(context)
        artifacts: list[GuardArtifact] = []
        found_paths: list[str] = []
        warnings: list[str] = []

        # Detect Hermes installation signals.
        for config_name in ("config.yaml", "config.toml"):
            config_path = hermes_home / config_name
            if config_path.is_file():
                found_paths.append(str(config_path))

        # Discover skills in ~/.hermes/skills/<category>/<skill>/
        skills_dir = hermes_home / "skills"
        if skills_dir.is_dir():
            try:
                category_dirs = sorted(skills_dir.iterdir())
            except (PermissionError, OSError):
                category_dirs = []
            for category_dir in category_dirs:
                if not category_dir.is_dir():
                    continue
                try:
                    skill_dirs = sorted(category_dir.iterdir())
                except (PermissionError, OSError):
                    continue
                for skill_dir in skill_dirs:
                    if not skill_dir.is_dir():
                        continue
                    skill_md = skill_dir / "SKILL.md"
                    if not skill_md.is_file():
                        continue
                    found_paths.append(str(skill_md))
                    artifacts.extend(
                        self._scan_skill(
                            category_dir,
                            skill_dir,
                            skill_md,
                            identity_scope_root=skills_dir,
                            warnings=warnings,
                        )
                    )

        # Discover MCP servers from both config.yaml and mcp_servers.json.
        artifacts.extend(self._scan_mcp_servers(hermes_home, found_paths, warnings))

        # Container fallback: use an explicit or persisted host-home mirror
        # when the sandbox has only empty skills and trivial config.
        host_home = _hermes_host_home(context)
        if host_home and host_home.resolve() != hermes_home.resolve() and not _hermes_home_has_artifacts(hermes_home):
            artifacts.extend(self._scan_host_home(host_home, found_paths, warnings))

        # Manifest fallback: when no MCP servers were discovered from config
        # files, fall back to the Guard-managed manifest.json.  This covers
        # containers where install() ran on the host and wrote the manifest,
        # but the container's config.yaml has no mcp_servers.
        if not any(a.artifact_type == "mcp_server" for a in artifacts):
            artifacts.extend(self._scan_manifest_mcp_servers(context, found_paths))

        return HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or _command_available(self.executable),
            command_available=_command_available(self.executable),
            artifacts=tuple(artifacts),
            config_paths=tuple(found_paths),
            warnings=tuple(dict.fromkeys(warnings)),
        )

    def inventory_snapshot(
        self,
        context: HarnessContext,
        *,
        generated_at: str,
        cisco_mcp_scan: str = "off",
        cisco_skill_scan: str = "off",
        cisco_timeout_seconds: float | None = None,
    ) -> GuardAgentInventorySnapshot:
        detection = self.detect(context)
        return inventory_snapshot_from_detection(
            detection,
            generated_at=generated_at,
            home_dir=context.home_dir,
            workspace_dir=context.workspace_dir,
            cisco_runs=run_cisco_inventory_scans(
                harness=self.harness,
                context=context,
                detection=detection,
                mcp_mode=cisco_mcp_scan,
                skill_mode=cisco_skill_scan,
                timeout_seconds=cisco_timeout_seconds,
            ),
        )

    # ------------------------------------------------------------------
    # Skill scanning
    # ------------------------------------------------------------------

    def _scan_skill(
        self,
        category_dir: Path,
        skill_dir: Path,
        skill_md: Path,
        *,
        identity_scope_root: Path,
        warnings: list[str],
    ) -> list[GuardArtifact]:
        """Produce artifacts for SKILL.md and any scannable subdirectory files."""
        artifacts: list[GuardArtifact] = []

        inspection = inspect_hermes_text_file(skill_md, scope_root=skill_dir)
        content = inspection.preview
        frontmatter = _parse_frontmatter(content)
        code_blocks = _extract_code_blocks(content)

        skill_name_value = frontmatter.get("name")
        skill_name = skill_name_value if isinstance(skill_name_value, str) and skill_name_value else skill_dir.name
        description_value = frontmatter.get("description")
        description = description_value if isinstance(description_value, str) else ""
        # related_skills may be top-level or nested under metadata.hermes
        related_value = frontmatter.get("related_skills")
        related = related_value if isinstance(related_value, str) else ""
        if not related:
            meta = frontmatter.get("metadata", {})
            if isinstance(meta, str):
                # Fallback parser returns strings; try to extract from it
                pass
            elif isinstance(meta, dict):
                hermes_meta = meta.get("hermes", {})
                if isinstance(hermes_meta, dict):
                    hermes_related = hermes_meta.get("related_skills")
                    if isinstance(hermes_related, str):
                        related = hermes_related

        env_mentions = _extract_env_mentions(content)
        identity = inspect_skill_directory(skill_md, scope_root=identity_scope_root)
        metadata = skill_directory_identity_metadata(
            identity,
            version_label=f"{category_dir.name}/{skill_dir.name}",
        )
        metadata.update(
            {
                "category": category_dir.name,
                "description": description[:200] if description else "",
                "has_code_blocks": bool(code_blocks),
                "related_skills": related,
                "env_mentions": sorted(env_mentions),
                **file_inspection_metadata(inspection),
            }
        )
        signals = _inspection_signals(inspection, label="Hermes skill")
        if identity.status != "complete":
            signals.append("Hermes skill directory identity is incomplete; review is required.")
            warnings.append(
                f"Hermes skill directory identity is incomplete ({identity.failure_reason or 'unknown'}); "
                "approval reuse is disabled."
            )
        if signals:
            metadata["runtime_request_signals"] = signals

        # Include both fenced code blocks AND non-fenced plain text for risk
        # analysis.  Mixed files may have a benign fenced snippet plus malicious
        # plain-markdown instructions; dropping either would miss signals.
        risk_args: tuple[str, ...] = tuple(code_blocks)
        plain_text = _extract_plain_markdown(content)
        if plain_text:
            risk_args = (*risk_args, plain_text)

        artifacts.append(
            GuardArtifact(
                artifact_id=f"hermes:skill:{category_dir.name}:{skill_dir.name}",
                name=skill_name,
                harness=self.harness,
                artifact_type="skill",
                source_scope="global",
                config_path=str(skill_md),
                command=str(skill_md),
                url=None,
                transport=None,
                args=risk_args,
                metadata=metadata,
            )
        )

        # Scan subdirectory files (references, templates, scripts, assets).
        for subdir_name in _SKILL_SUBDIRS:
            subdir = skill_dir / subdir_name
            if not subdir.is_dir():
                continue
            try:
                sub_files = sorted(subdir.rglob("*"))
            except (PermissionError, OSError):
                continue
            for file_path in sub_files:
                if not file_path.is_file():
                    continue
                if not _is_scannable(file_path):
                    continue
                file_inspection = inspect_hermes_text_file(file_path, scope_root=skill_dir)
                file_content = file_inspection.preview
                file_blocks = _extract_code_blocks(file_content)
                file_env = _extract_env_mentions(file_content)
                rel_path = file_path.relative_to(skill_dir)

                # Include both fenced code blocks AND non-fenced plain text for
                # risk analysis.  Plain scripts (.sh/.py) without fences get their
                # raw content included.  Truncate to avoid oversized artifacts.
                file_risk_args: tuple[str, ...] = tuple(file_blocks)
                file_plain = _extract_plain_markdown(file_content)
                if file_plain:
                    file_risk_args = (*file_risk_args, file_plain)

                file_metadata: dict[str, object] = {
                    "parent_skill": skill_name,
                    "subdir": subdir_name,
                    "has_code_blocks": bool(file_blocks),
                    "env_mentions": sorted(file_env),
                    **file_inspection_metadata(file_inspection),
                }
                file_signals = _inspection_signals(file_inspection, label="Hermes skill file")
                if file_signals:
                    file_metadata["runtime_request_signals"] = file_signals
                artifacts.append(
                    GuardArtifact(
                        artifact_id=(f"hermes:skill:{category_dir.name}:{skill_dir.name}:{rel_path}"),
                        name=f"{skill_name}/{rel_path}",
                        harness=self.harness,
                        artifact_type="skill_file",
                        source_scope="global",
                        config_path=str(file_path),
                        command=str(file_path),
                        url=None,
                        transport=None,
                        args=file_risk_args,
                        metadata=file_metadata,
                    )
                )

        return artifacts

    # ------------------------------------------------------------------
    # MCP server scanning
    # ------------------------------------------------------------------

    def _scan_mcp_servers(
        self,
        hermes_home: Path,
        found_paths: list[str],
        warnings: list[str],
    ) -> list[GuardArtifact]:
        """Read MCP server configs from config.yaml and mcp_servers.json."""
        artifacts: list[GuardArtifact] = []

        # Source 1: config.yaml (primary Hermes config).
        yaml_path = hermes_home / "config.yaml"
        if yaml_path.is_file():
            found_paths.append(str(yaml_path))
            inspection = inspect_hermes_config(yaml_path, syntax="yaml")
            if inspection.complete and inspection.payload is not None:
                yaml_servers = _mcp_servers_from_payload(inspection.payload)
                artifacts.extend(self._mcp_artifacts(yaml_servers, str(yaml_path), source="yaml"))
            else:
                artifacts.append(_config_failure_artifact(yaml_path, source="yaml", inspection=inspection))
                warnings.append(_config_failure_warning(yaml_path, inspection))

        # Source 2: mcp_servers.json (legacy / alternative).
        json_path = hermes_home / "mcp_servers.json"
        if json_path.is_file():
            found_paths.append(str(json_path))
            inspection = inspect_hermes_config(json_path, syntax="json")
            if inspection.complete and inspection.payload is not None:
                json_servers = {
                    name: config
                    for name, config in inspection.payload.items()
                    if isinstance(name, str) and isinstance(config, dict)
                }
                artifacts.extend(self._mcp_artifacts(json_servers, str(json_path), source="json"))
            else:
                artifacts.append(_config_failure_artifact(json_path, source="json", inspection=inspection))
                warnings.append(_config_failure_warning(json_path, inspection))

        return artifacts

    def _scan_host_home(
        self,
        host_home: Path,
        found_paths: list[str],
        warnings: list[str],
    ) -> list[GuardArtifact]:
        """Scan the host's real Hermes home when running inside a container.

        This mirrors the container-side detect() logic but targets the host's
        installation.  Skills and MCP servers discovered here are attributed
        to the Hermes harness — they belong to the agent even though the
        container can't see them directly.
        """
        artifacts: list[GuardArtifact] = []

        # Discover skills from the host's skills directory.
        skills_dir = host_home / "skills"
        if skills_dir.is_dir():
            try:
                category_dirs = sorted(skills_dir.iterdir())
            except (PermissionError, OSError):
                category_dirs = []
            for category_dir in category_dirs:
                if not category_dir.is_dir():
                    continue
                try:
                    skill_dirs = sorted(category_dir.iterdir())
                except (PermissionError, OSError):
                    continue
                for skill_dir in skill_dirs:
                    if not skill_dir.is_dir():
                        continue
                    skill_md = skill_dir / "SKILL.md"
                    if not skill_md.is_file():
                        continue
                    found_paths.append(str(skill_md))
                    artifacts.extend(
                        self._scan_skill(
                            category_dir,
                            skill_dir,
                            skill_md,
                            identity_scope_root=skills_dir,
                            warnings=warnings,
                        )
                    )

        # Discover MCP servers from the host's config files.
        artifacts.extend(self._scan_mcp_servers(host_home, found_paths, warnings))

        return artifacts

    def _scan_manifest_mcp_servers(
        self,
        context: HarnessContext,
        found_paths: list[str],
    ) -> list[GuardArtifact]:
        """Fall back to Guard-managed manifest.json for MCP server discovery.

        When the container's config.yaml has no mcp_servers (common in
        sandbox configs), the Guard-managed manifest.json written by
        install() may contain the server definitions.  This covers the case
        where install() ran on the host and the manifest was mounted or
        copied into the container.
        """
        manifest_path = _managed_root(context) / "manifest.json"
        if not manifest_path.is_file():
            return []

        payload = _json_payload(manifest_path)
        servers = payload.get("servers")
        if not isinstance(servers, dict) or not servers:
            return []

        found_paths.append(str(manifest_path))
        # Manifest stores servers keyed as "yaml:<name>" / "json:<name>".
        # Re-key by the real server name so artifacts report the correct name.
        real_servers: dict[str, dict[str, object]] = {}
        for _key, server_config in servers.items():
            if not isinstance(server_config, dict):
                continue
            real_name = server_config.get("name")
            if isinstance(real_name, str) and real_name:
                real_servers[real_name] = server_config
            elif isinstance(_key, str):
                real_servers[_key] = server_config
        return self._mcp_artifacts(real_servers, str(manifest_path), source="manifest")

    def _mcp_artifacts(
        self,
        servers: dict[str, dict[str, object]],
        config_path: str,
        *,
        source: str,
    ) -> list[GuardArtifact]:
        """Convert parsed MCP server dicts into GuardArtifacts."""
        artifacts: list[GuardArtifact] = []
        for name, server_config in servers.items():
            if not isinstance(name, str) or not isinstance(server_config, dict):
                continue

            # Skip disabled MCP servers unless explicitly enabled (default True).
            enabled = server_config.get("enabled", True)
            if enabled is False:
                continue

            command = server_config.get("command")
            url = server_config.get("url")
            args = server_config.get("args", [])
            env = server_config.get("env", {})
            headers = server_config.get("headers", {})
            sampling = server_config.get("sampling")

            if not isinstance(args, list):
                args = []
            if not isinstance(env, dict):
                env = {}
            if not isinstance(headers, dict):
                headers = {}

            args_tuple = tuple(str(a) for a in args if isinstance(a, str))
            transport = "http" if isinstance(url, str) else "stdio"

            # Filter non-string keys before sorting to avoid TypeError.
            header_keys = [k for k in headers if isinstance(k, str)]
            auth_header_keys = [
                k for k in header_keys if any(t in k.lower() for t in ("auth", "token", "key", "secret", "bearer"))
            ]

            sampling_enabled = None
            sampling_model = None
            if isinstance(sampling, dict):
                sampling_enabled = sampling.get("enabled", True)
                sampling_model = sampling.get("model")

            # Filter env keys to strings before sorting.
            env_str_keys = sorted(k for k in env if isinstance(k, str))
            configured_environment = {
                key.strip(): value
                for key, value in env.items()
                if isinstance(key, str) and key.strip() and isinstance(value, str)
            }
            configured_headers = {
                key.strip(): value
                for key, value in headers.items()
                if isinstance(key, str) and key.strip() and isinstance(value, str)
            }

            metadata: dict[str, object] = {
                "source": source,
                "env_keys": env_str_keys,
                "header_keys": sorted(header_keys),
                "headers_keys": sorted(header_keys),
                "auth_header_keys": sorted(auth_header_keys),
                "sampling_enabled": sampling_enabled,
                "sampling_model": sampling_model,
                "envConfigurationPresent": bool(env),
                "has_auth_headers": bool(auth_header_keys),
            }

            env_value_hints = [
                k for k, v in env.items() if isinstance(k, str) and isinstance(v, str) and _looks_like_secret(v)
            ]
            if env_value_hints:
                metadata["env_value_secret_keys"] = sorted(env_value_hints)

            header_value_hints = [
                k for k, v in headers.items() if isinstance(k, str) and isinstance(v, str) and _looks_like_secret(v)
            ]
            if header_value_hints:
                metadata["header_value_secret_keys"] = sorted(header_value_hints)

            metadata = enrich_mcp_server_metadata(
                metadata,
                command=command if isinstance(command, str) else None,
                args=args_tuple,
                url=url if isinstance(url, str) else None,
                transport=transport,
                configured_environment=configured_environment,
                configured_headers=configured_headers,
            )

            # Include source in artifact_id to prevent collisions when the
            # same server name appears in both config.yaml and mcp_servers.json.
            artifacts.append(
                GuardArtifact(
                    artifact_id=f"hermes:mcp:{source}:{name}",
                    name=name,
                    harness=self.harness,
                    artifact_type="mcp_server",
                    source_scope="global",
                    config_path=config_path,
                    command=command if isinstance(command, str) else None,
                    url=url if isinstance(url, str) else None,
                    transport=transport,
                    args=args_tuple,
                    metadata=metadata,
                )
            )

        return artifacts


# ------------------------------------------------------------------
# Module-level helpers (no dependency on adapter instance)
# ------------------------------------------------------------------


class _HermesConfigInspectionError(ValueError):
    def __init__(self, path: Path, inspection: HermesConfigInspection) -> None:
        reason = inspection.reason or "config_parse_error"
        super().__init__(f"Hermes config inspection failed for {path}: {reason}")
        self.inspection = inspection


def _inspection_signals(inspection: HermesFileInspection, *, label: str) -> list[str]:
    if not inspection.complete:
        reason = inspection.reason or "unknown"
        return [f"{label} inspection is incomplete ({reason}); unseen content cannot be treated as safe."]
    if inspection.analysis_truncated:
        return [f"{label} risk preview is truncated; review the complete content before approval."]
    return []


def _config_failure_artifact(
    path: Path,
    *,
    source: str,
    inspection: HermesConfigInspection,
) -> GuardArtifact:
    reason = inspection.reason or "config_parse_error"
    metadata = {
        **file_inspection_metadata(inspection.file),
        "config_parse_complete": False,
        "config_reason": reason,
        "runtime_request_signals": [
            f"Hermes {source.upper()} configuration inspection is incomplete ({reason}); review is required."
        ],
    }
    return GuardArtifact(
        artifact_id=f"hermes:config:{source}:incomplete",
        name=f"Incomplete Hermes {source.upper()} configuration",
        harness="hermes",
        artifact_type="configuration",
        source_scope="global",
        config_path=str(path),
        metadata=metadata,
    )


def _config_failure_warning(path: Path, inspection: HermesConfigInspection) -> str:
    reason = inspection.reason or "config_parse_error"
    return f"Hermes config {path.name} was not accepted ({reason}); no partial configuration was applied."


def _mcp_servers_from_payload(payload: dict[str, object]) -> dict[str, dict[str, object]]:
    mcp = payload.get("mcp_servers")
    if not isinstance(mcp, dict):
        return {}
    return {name: config for name, config in mcp.items() if isinstance(name, str) and isinstance(config, dict)}


def _is_scannable(file_path: Path) -> bool:
    """Check whether a file should be scanned based on extension or name."""
    if file_path.suffix.lower() in _SCANNABLE_EXTENSIONS:
        return True
    # Extensionless files with known names (e.g. .env, Makefile, deploy).
    if not file_path.suffix:
        name = file_path.name
        if name in _SCANNABLE_NAMES:
            return True
        # Files in scripts/ subdirs without extension are likely shell scripts.
        for subdir in ("scripts",):
            if subdir in file_path.parts:
                return True
    return False


def _parse_frontmatter(content: str) -> dict[str, object]:
    """Parse complete, bounded YAML frontmatter from the retained preview."""
    if not content.startswith("---"):
        return {}
    parts = content[3:].split("---", 1)
    if len(parts) != 2:
        return {}
    raw = parts[0].strip()

    parsed = parse_hermes_yaml_mapping(raw)
    if parsed is not None:
        # Flatten values to strings for consistent downstream handling.
        return {key: _flatten_yaml_value(value) for key, value in parsed.items()}
    return {}


def _flatten_yaml_value(value: object) -> str:
    """Convert a parsed YAML value to a flat string for frontmatter metadata."""
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    if isinstance(value, dict):
        return str(value)
    return str(value)


def _extract_code_blocks(content: str) -> list[str]:
    """Extract code blocks from markdown for risk analysis."""
    blocks: list[str] = []
    pattern = r"```[^\n]*\n(.*?)\n?```"
    for match in re.finditer(pattern, content, re.DOTALL):
        code = match.group(1).strip()
        if code:
            blocks.append(code)
    return blocks


def _extract_plain_markdown(content: str, max_len: int = 2048) -> str:
    """Extract non-fenced plain text from markdown for risk analysis.

    Strips code fences and frontmatter, returning the remaining plain
    text truncated to max_len.  Returns empty string if nothing remains.
    """
    # Remove fenced code blocks.
    stripped = re.sub(r"```[^\n]*\n.*?\n?```", "", content, flags=re.DOTALL)
    # Remove frontmatter.
    if stripped.startswith("---"):
        parts = stripped[3:].split("---", 1)
        if len(parts) == 2:
            stripped = parts[1]
    text = stripped.strip()
    if not text:
        return ""
    return text[:max_len]


def _extract_env_mentions(content: str) -> list[str]:
    """Find environment variable references like ${VAR}, os.environ['VAR'], process.env.VAR."""
    mentions: set[str] = set()
    for m in re.finditer(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", content):
        mentions.add(m.group(1))
    # os.environ.get('VAR') and os.getenv('VAR')
    for m in re.finditer(r"os\.(?:environ(?:\.get)?|getenv)\(['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]\)", content):
        mentions.add(m.group(1))
    # os.environ['VAR'] and os.environ["VAR"]
    for m in re.finditer(r"os\.environ\[(['\"])([A-Za-z_][A-Za-z0-9_]*)\1\]", content):
        mentions.add(m.group(2))
    for m in re.finditer(r"process\.env\.([A-Za-z_][A-Za-z0-9_]*)", content):
        mentions.add(m.group(1))
    return sorted(mentions)


def _looks_like_secret(value: str) -> bool:
    """Heuristic: does this value look like a secret/token?"""
    if len(value) < 8:
        return False
    lower = value.lower()
    secret_prefixes = (
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "sk-",
        "sk_",
        "xai-",
        "key-",
        "key_",
        "tok_",
        "token_",
    )
    return bool(
        any(lower.startswith(p) for p in secret_prefixes)
        or lower.startswith("bearer ")
        or re.fullmatch(r"[A-Za-z0-9+/=_-]{20,}", value)
    )


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
    command = [
        str(Path(sys.executable)),
        "-m",
        "codex_plugin_scanner.cli",
        "hermes",
        "pretool",
        "--guard-home",
        str(context.guard_home),
        "--json",
    ]
    if context.home_dir.resolve() != Path.home().resolve():
        command.extend(["--home", str(context.home_dir)])
    if context.workspace_dir is not None:
        command.extend(["--workspace", str(context.workspace_dir)])
    return {
        "command": command,
        "harness": "hermes",
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
    path.write_text(json.dumps({"servers": names}, indent=2) + "\n", encoding="utf-8")


def _previous_guard_section_path(context: HarnessContext) -> Path:
    return _managed_root(context) / _GUARD_PREVIOUS_SECTION_MANIFEST


def _read_previous_guard_section(context: HarnessContext) -> dict[str, object] | None:
    data = _json_payload(_previous_guard_section_path(context))
    section = data.get("guard")
    if not isinstance(section, dict):
        return None
    return section


def _write_previous_guard_section(context: HarnessContext, section: dict[str, object] | None) -> None:
    path = _previous_guard_section_path(context)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"guard": section}, indent=2) + "\n", encoding="utf-8")


def _write_guard_to_hermes_config_yaml(
    *,
    context: HarnessContext,
    config_yaml_path: Path,
    overlay_servers: dict[str, dict[str, object]],
    managed_names: list[str],
) -> tuple[list[str], dict[str, object] | None, bool]:
    """Write Guard-managed MCP proxy entries and guard section into Hermes config.yaml.

    Replaces Guard-managed entries (identified by ``managed_names`` from the
    manifest, not by prefix) with the current overlay servers.  User-configured
    MCP servers — including any that happen to start with ``guard-`` — are
    preserved.

    Returns a tuple of ``(new_managed_names, previous_guard_section, config_written)``.
    ``previous_guard_section`` is the user's existing ``guard`` section (or
    ``None`` if there wasn't one) so that ``uninstall()`` can restore it.
    ``config_written`` is ``True`` if config.yaml was written, ``False`` if the
    existing configuration could not be inspected completely.
    """
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
        "timeout_seconds": 5,
        "cache_ttl_seconds": 60,
        "fail_open": True,
        "token_env_var": "HERMES_GUARD_TOKEN",
        "enforce_mcp_tools": True,
        "pain_signals_enabled": True,
    }

    config_yaml_path.write_text(
        _yaml.dump(existing, default_flow_style=False, sort_keys=False),
        encoding="utf-8",
    )
    return new_managed, previous_guard, True


def _remove_guard_from_hermes_config_yaml(
    *,
    config_yaml_path: Path,
    managed_names: list[str],
    previous_guard: dict[str, object] | None = None,
) -> None:
    """Remove Guard-managed entries from Hermes config.yaml.

    Removes the MCP server entries listed in ``managed_names`` (from the
    manifest) and restores the user's previous ``guard`` section if one was
    saved during install.  User-configured servers — even those that happen
    to start with ``guard-`` — are preserved.
    """
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

    # Restore the user's previous guard section, or remove it if there wasn't one.
    if previous_guard is not None:
        raw[_GUARD_CONFIG_KEY] = previous_guard
    else:
        raw.pop(_GUARD_CONFIG_KEY, None)

    config_yaml_path.write_text(
        _yaml.dump(raw, default_flow_style=False, sort_keys=False),
        encoding="utf-8",
    )


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
