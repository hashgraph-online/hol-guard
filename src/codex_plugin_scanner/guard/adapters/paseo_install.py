"""Paseo's native-provider installation receipt and shared-hook ownership."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from ..codex_hook_integrity import atomic_write_text
from ..managed_install_proof import bind_managed_install_proof, verify_managed_install_proof
from . import get_adapter
from .base import HarnessContext
from .paseo_config import PaseoProvider, paseo_config_path, read_config_object, require_local_path

_RECEIPT_SCHEMA = "guard.paseo-native-install.v1"
_NATIVE_CONFIGS = {
    "claude-code": (".claude/settings.json",),
    "codex": (".codex/config.toml", ".codex/hooks.json"),
    "copilot": (".copilot/config.json", ".copilot/mcp-config.json"),
    "opencode": (
        ".config/opencode/opencode.json",
        ".config/opencode/opencode.jsonc",
        ".config/opencode/plugins/hol-guard-pretool.ts",
    ),
    "pi": (".pi/agent/settings.json", ".pi/agent/extensions/hol-guard.ts"),
    "omp": (".omp/agent/settings.json", ".omp/agent/extensions/hol-guard.ts"),
}


def native_context(context: HarnessContext) -> HarnessContext:
    # Paseo chooses a different cwd for every session/worktree. Do not pin hooks
    # to the workspace from which the user happened to run the installer.
    """Install hooks for the daemon user rather than the caller's current worktree."""
    return replace(context, workspace_dir=None, workspace_override_explicit=False)


def receipt_path(context: HarnessContext) -> Path:
    """Derive a safe per-daemon receipt path inside Guard's managed state."""
    identity = str(paseo_config_path(context).absolute())
    suffix = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]
    path = context.guard_home / "managed" / "paseo" / f"{suffix}.json"
    require_local_path(context.guard_home, path, home_dir=context.home_dir)
    return path


def read_receipt(context: HarnessContext) -> dict[str, object]:
    """Validate that a receipt belongs to this daemon configuration and schema."""
    payload = read_config_object(receipt_path(context))
    if not payload:
        return {}
    if payload.get("schema_version") != _RECEIPT_SCHEMA or payload.get("paseo_config_path") != str(
        paseo_config_path(context).absolute()
    ):
        raise ValueError("Paseo's installation receipt is invalid; run hol-guard apps repair paseo.")
    if not isinstance(payload.get("native_proofs"), dict):
        raise ValueError("Paseo's native installation proofs are missing; run hol-guard apps repair paseo.")
    return payload


def _proof_paths(proof: dict[str, object]) -> list[str]:
    """Extract only explicitly recorded native protection artifact paths."""
    envelope = proof.get("protection_artifact_proof")
    artifacts = envelope.get("artifacts", []) if isinstance(envelope, dict) else []
    if not isinstance(artifacts, list):
        return []
    return [item["path"] for item in artifacts if isinstance(item, dict) and isinstance(item.get("path"), str)]


def provider_status(provider: PaseoProvider, context: HarnessContext, receipt: dict[str, object]) -> str:
    """Distinguish disabled, unsupported, unavailable, missing, and changed native installs."""
    if not provider.enabled:
        return "disabled"
    if provider.unsupported_reason or provider.native_harness is None:
        return "unsupported"
    adapter = get_adapter(provider.native_harness)
    if adapter.resolved_executable(native_context(context)) is None:
        return "runtime-unavailable"
    proofs = receipt.get("native_proofs", {})
    proof = proofs.get(provider.native_harness) if isinstance(proofs, dict) else None
    if proof is None:
        return "not-installed"
    return "native-hooks-installed" if verify_managed_install_proof(proof, context) is True else "changed"


def preflight_native(harness: str, context: HarnessContext) -> None:
    """Validate every known native write target before shared configuration changes."""
    for relative in _NATIVE_CONFIGS[harness]:
        path = context.home_dir / relative
        require_local_path(context.home_dir, path, home_dir=context.home_dir)
        if path.suffix == ".json":
            read_config_object(path)
    managed = context.guard_home / "managed" / harness
    require_local_path(context.guard_home, managed, home_dir=context.home_dir)
    if managed.is_dir():
        for path in managed.rglob("*"):
            require_local_path(context.guard_home, path, home_dir=context.home_dir)
    if harness == "opencode":
        require_local_path(
            context.guard_home, context.guard_home / "opencode/plugins/hol-guard-pretool.ts", home_dir=context.home_dir
        )
    for path in get_adapter(harness).guard_launcher_paths(context):
        require_local_path(context.guard_home, path, home_dir=context.home_dir)


def install_native(harness: str, context: HarnessContext) -> dict[str, object]:
    """Install and register one native provider with all required artifact proofs."""
    from ..store import GuardStore

    preflight_native(harness, context)
    manifest = get_adapter(harness).install(native_context(context))
    primary = manifest.get("config_path")
    if manifest.get("active") is not True or not isinstance(primary, str) or not Path(primary).is_file():
        raise ValueError(f"The {harness} adapter did not install native protection; Paseo setup was not completed.")
    additional = [
        str(context.home_dir / relative)
        for relative in _NATIVE_CONFIGS[harness]
        if harness != "opencode" and (context.home_dir / relative).is_file()
    ]
    for key in ("managed_hook_manifest_path", "managed_hook_config_path", "managed_plugin_path", "global_plugin_path"):
        value = manifest.get(key)
        if isinstance(value, str):
            additional.append(value)
    bound = bind_managed_install_proof({**manifest, "protection_artifact_paths": additional}, context)
    proof = {"protection_artifact_proof": bound["protection_artifact_proof"]}
    if str(Path(primary).resolve()) not in _proof_paths(proof):
        raise ValueError(f"Cannot verify {harness}'s native installation inside the managed home.")
    # Native hook reviews retain the native harness identity. Register their
    # manifests too, so health checks, repairs and approval proofs see them.
    GuardStore(context.guard_home).set_managed_install(
        harness, True, None, bound, datetime.now(timezone.utc).isoformat()
    )
    return proof


def write_receipt(context: HarnessContext, proofs: dict[str, object]) -> dict[str, object]:
    """Publish a private receipt only while every native proof still verifies."""
    if not proofs or any(verify_managed_install_proof(proof, context) is not True for proof in proofs.values()):
        raise ValueError("Native protection changed during Paseo installation; rerun setup before relying on it.")
    payload: dict[str, object] = {
        "schema_version": _RECEIPT_SCHEMA,
        "paseo_config_path": str(paseo_config_path(context).absolute()),
        "native_proofs": proofs,
    }
    atomic_write_text(receipt_path(context), json.dumps(payload, indent=2) + "\n")
    return payload


def protection_paths(receipt: dict[str, object]) -> list[str]:
    """Deduplicate the native artifact paths included in the composite proof."""
    proofs = receipt.get("native_proofs", {})
    if not isinstance(proofs, dict):
        return []
    return sorted({path for proof in proofs.values() if isinstance(proof, dict) for path in _proof_paths(proof)})
