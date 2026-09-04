"""OpenClaw harness adapter."""

from __future__ import annotations

import json
from pathlib import Path

from ...safe_output import write_text_atomic_no_follow
from ..models import GuardArtifact, HarnessDetection
from ..shims import install_guard_shim, remove_guard_shim
from .base import (
    HarnessAdapter,
    HarnessContext,
    _command_available,
    _ensure_path_within_root,
    _json_payload,
    _run_command_probe,
)
from .cloud_identity import cloud_agent_identity_environment, cloud_agent_identity_hints
from .openclaw_config import load_config
from .openclaw_support import (
    config_artifacts,
    config_path,
    install_state,
    managed_root,
    overlay_payload,
    pretool_payload,
    skill_artifacts,
)

_OPENCLAW_MANAGED_APPROVAL_TIER = "native-or-center"
_OPENCLAW_MANAGED_PROMPT_CHANNEL = "native"


def _openclaw_manifest(context: HarnessContext) -> dict[str, object]:
    root = managed_root(context)
    manifest_path = root / "manifest.json"
    _ensure_path_within_root(context.guard_home, manifest_path, label="OpenClaw manifest")
    return _json_payload(manifest_path)


def _validated_managed_paths(
    context: HarnessContext,
    manifest: dict[str, object],
) -> tuple[Path, Path] | None:
    root = managed_root(context)
    expected_overlay = root / "overlay.json"
    expected_pretool = root / "pretool-hook.json"
    overlay_value = manifest.get("managed_overlay_path")
    pretool_value = manifest.get("pretool_hook_path")
    if not isinstance(overlay_value, str) or not isinstance(pretool_value, str):
        return None
    if not overlay_value or not pretool_value or "\x00" in overlay_value or "\x00" in pretool_value:
        return None
    try:
        _ensure_path_within_root(context.guard_home, root, label="OpenClaw managed")
        _ensure_path_within_root(root, expected_overlay, label="OpenClaw overlay")
        _ensure_path_within_root(root, expected_pretool, label="OpenClaw hook")
    except ValueError:
        return None
    if overlay_value != str(expected_overlay) or pretool_value != str(expected_pretool):
        return None
    return expected_overlay, expected_pretool


class OpenClawHarnessAdapter(HarnessAdapter):
    """Discover OpenClaw gateway config, channels, MCP servers, and skills."""

    harness = "openclaw"
    executable = "openclaw"
    approval_tier = "approval-center"
    approval_summary = (
        "Guard can scan OpenClaw gateway config, channels, skills, and MCP servers before agent sessions run."
    )
    fallback_hint = "Connect OpenClaw through the Guard-managed overlay or resolve requests in the approval center."
    approval_prompt_channel = "native-fallback"
    approval_auto_open_browser = False

    def policy_path(self, context: HarnessContext) -> Path:
        return config_path(context)

    def detect(self, context: HarnessContext) -> HarnessDetection:
        path = config_path(context)
        payload = load_config(path)
        found_paths: list[str] = []
        artifacts: list[GuardArtifact] = []
        if payload:
            found_paths.append(str(path))
            artifacts.extend(config_artifacts(context, path, payload))
        artifacts.extend(skill_artifacts(context, payload, found_paths))
        return HarnessDetection(
            harness=self.harness,
            installed=bool(found_paths) or _command_available(self.executable),
            command_available=_command_available(self.executable),
            config_paths=tuple(found_paths),
            artifacts=tuple(artifacts),
        )

    def install(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = install_guard_shim(self.harness, context)
        root = managed_root(context)
        manifest_path = root / "manifest.json"
        overlay_path = root / "overlay.json"
        pretool_path = root / "pretool-hook.json"
        root.mkdir(parents=True, exist_ok=True)
        existing_manifest = _openclaw_manifest(context)
        state = install_state(
            existing_manifest=existing_manifest,
            overlay_path=overlay_path,
            pretool_path=pretool_path,
        )
        detection = self.detect(context)
        cloud_identity = cloud_agent_identity_hints(context, runtime=self.harness)
        write_text_atomic_no_follow(overlay_path, json.dumps(overlay_payload(detection), indent=2) + "\n")
        write_text_atomic_no_follow(pretool_path, json.dumps(pretool_payload(context=context), indent=2) + "\n")
        raw_notes = shim_manifest.get("notes")
        shim_notes = (
            [str(note) for note in raw_notes if isinstance(note, str)] if isinstance(raw_notes, (list, tuple)) else []
        )
        notes = ["Guard generated an OpenClaw overlay bundle for gateway posture and pre-tool protection.", *shim_notes]
        manifest = {
            "harness": self.harness,
            "active": True,
            "config_path": str(overlay_path),
            **shim_manifest,
            "install_state": state,
            "managed_root": str(root),
            "managed_manifest_path": str(manifest_path),
            "managed_overlay_path": str(overlay_path),
            "pretool_hook_path": str(pretool_path),
            "capabilities": {
                "same_channel": True,
                "pretool": True,
                "channel_posture": True,
                "mcp_proxy": True,
            },
            "config_paths": list(detection.config_paths),
            "artifact_count": len(detection.artifacts),
            "notes": notes,
        }
        if cloud_identity is not None:
            manifest["cloud_agent_identity"] = cloud_identity
        write_text_atomic_no_follow(manifest_path, json.dumps(manifest, indent=2) + "\n")
        return manifest

    def uninstall(self, context: HarnessContext) -> dict[str, object]:
        shim_manifest = remove_guard_shim(self.harness, context)
        root = managed_root(context)
        manifest = _openclaw_manifest(context)
        removed_paths: list[str] = []
        for key in ("managed_manifest_path", "managed_overlay_path", "pretool_hook_path"):
            value = manifest.get(key)
            if not isinstance(value, str) or not value:
                continue
            path = Path(value)
            _ensure_path_within_root(root, path, label=key)
            if path.exists():
                path.unlink()
                removed_paths.append(str(path))
        raw_notes = shim_manifest.get("notes")
        shim_notes = (
            [str(note) for note in raw_notes if isinstance(note, str)] if isinstance(raw_notes, (list, tuple)) else []
        )
        return {
            "harness": self.harness,
            "active": False,
            "config_path": str(root / "overlay.json"),
            **shim_manifest,
            "removed_paths": removed_paths,
            "notes": [
                "Guard removed the managed OpenClaw overlay bundle and kept user OpenClaw config untouched.",
                *shim_notes,
            ],
        }

    def launch_environment(self, context: HarnessContext) -> dict[str, str]:
        manifest = _openclaw_manifest(context)
        managed_paths = _validated_managed_paths(context, manifest)
        if managed_paths is None:
            return {}
        overlay_path, pretool_path = managed_paths
        environment = {
            "OPENCLAW_GUARD_OVERLAY_PATH": str(overlay_path),
            "OPENCLAW_GUARD_PRETOOL_PATH": str(pretool_path),
            "OPENCLAW_GUARD_CHANNEL_POSTURE": "enabled",
        }
        environment.update(
            cloud_agent_identity_environment(
                cloud_agent_identity_hints(context, runtime=self.harness),
                prefix="OPENCLAW",
            )
        )
        return environment

    def runtime_probe(self, context: HarnessContext) -> dict[str, object] | None:
        manifest = _openclaw_manifest(context)
        managed_paths = _validated_managed_paths(context, manifest)
        overlay_path, pretool_path = managed_paths or (None, None)
        return {
            "command": _run_command_probe([self.executable, "--help"]) if _command_available(self.executable) else None,
            "managed_install_present": bool(manifest),
            "managed_install_ready": (
                overlay_path is not None
                and overlay_path.exists()
                and pretool_path is not None
                and pretool_path.exists()
            ),
            "cloud_agent_identity_configured": bool(cloud_agent_identity_hints(context, runtime=self.harness)),
        }

    def approval_flow(self, *, managed_install: dict[str, object] | None = None) -> dict[str, object]:
        manifest = managed_install.get("manifest") if isinstance(managed_install, dict) else None
        capabilities = manifest.get("capabilities") if isinstance(manifest, dict) else None
        same_channel = isinstance(capabilities, dict) and bool(capabilities.get("same_channel"))
        if same_channel:
            return {
                "tier": _OPENCLAW_MANAGED_APPROVAL_TIER,
                "summary": (
                    "Guard uses OpenClaw native agent/channel delivery first and falls back to the approval center."
                ),
                "fallback_hint": "Use the Guard approval center if OpenClaw cannot surface the pending request inline.",
                "prompt_channel": _OPENCLAW_MANAGED_PROMPT_CHANNEL,
                "auto_open_browser": False,
            }
        return {
            "tier": "approval-center",
            "summary": "Guard keeps OpenClaw approvals in the local approval center without forcing a browser open.",
            "fallback_hint": "Resolve pending OpenClaw requests from the Guard approval center.",
            "prompt_channel": "native-fallback",
            "auto_open_browser": False,
        }
