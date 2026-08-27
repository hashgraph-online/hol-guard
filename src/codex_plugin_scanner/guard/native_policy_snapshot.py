"""Bounded native policy snapshot publication.

Python remains the control plane that loads durable configuration. The hot path
consumes only the immutable, redacted snapshot installed in the Rust resident;
raw approvals, paths, tokens, and unrelated UI state are intentionally absent.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Mapping

from .config import GuardConfig, load_guard_config
from .native_runtime import native_resident_operation, native_runtime_status
from .runtime.extension_control_runtime import current_extension_control_snapshot

if TYPE_CHECKING:
    from .store import GuardStore

_POLICY_SCHEMA = "hol-guard-native-policy.v2"
_MAX_CONTROLS = 1_024
_MAX_RESTRICTIONS = 256


@dataclass(frozen=True, slots=True)
class NativePolicyInstallResult:
    generation: int
    snapshot_digest: str


def _sha(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _workspace_scope_digest(workspace: Path | None) -> str:
    if workspace is None:
        identity = "global"
    else:
        try:
            identity = str(workspace.expanduser().absolute())
        except (OSError, RuntimeError, ValueError):
            identity = str(workspace)
    return hashlib.sha256(identity.encode("utf-8", errors="surrogatepass")).hexdigest()


def _safe_config_payload(config: GuardConfig) -> dict[str, object]:
    return {
        "mode": config.mode,
        "security_level": config.security_level,
        "protection_posture": config.protection_posture,
        "default_action": config.default_action,
        "unknown_publisher_action": config.unknown_publisher_action,
        "changed_hash_action": config.changed_hash_action,
        "new_network_domain_action": config.new_network_domain_action,
        "subprocess_action": config.subprocess_action,
        "risk_actions": dict(sorted((config.risk_actions or {}).items())),
        "harness_risk_actions": {
            harness: dict(sorted(actions.items()))
            for harness, actions in sorted((config.harness_risk_actions or {}).items())
        },
        "managed_policy_status": config.managed_policy_status,
        "managed_policy_hash": config.managed_policy_hash,
        "managed_locked_settings": list(config.managed_locked_settings[:_MAX_RESTRICTIONS]),
    }


def _extension_controls() -> tuple[list[dict[str, str]], bool, str | None]:
    snapshot = current_extension_control_snapshot()
    if snapshot is None:
        return [], False, None
    controls: list[dict[str, str]] = []
    lockdown = False
    for layer in snapshot.layers:
        lockdown = lockdown or layer.global_lockdown
        for control in layer.controls:
            if len(controls) >= _MAX_CONTROLS:
                break
            controls.append(
                {
                    "target_kind": control.target.kind.value,
                    "target_id": control.target.target_id,
                    "state": control.state.value,
                }
            )
    controls.sort(key=lambda item: (item["target_kind"], item["target_id"], item["state"]))
    return controls, lockdown, snapshot.effective_digest


def build_native_policy_snapshot(
    config: GuardConfig,
    *,
    rule_digest: str,
    scope_digest: str | None = None,
    generation: int | None = None,
) -> dict[str, object]:
    safe_config = _safe_config_payload(config)
    config_digest = _sha(safe_config)
    controls, global_lockdown, control_digest = _extension_controls()
    policy_payload = {
        "config_digest": config_digest,
        "rule_digest": rule_digest,
        "control_digest": control_digest,
        "extension_controls": controls,
        "global_lockdown": global_lockdown,
    }
    return {
        "schema": _POLICY_SCHEMA,
        "generation": generation if generation is not None else time.time_ns(),
        "scope_digest": scope_digest or hashlib.sha256(b"global").hexdigest(),
        "policy_digest": _sha(policy_payload),
        "config_digest": config_digest,
        "rule_digest": rule_digest,
        "mode": "observe" if config.mode == "observe" else "enforce",
        "security_level": config.security_level,
        "global_lockdown": global_lockdown,
        "managed_restrictions": list(config.managed_locked_settings[:_MAX_RESTRICTIONS]),
        "extension_controls": controls,
    }


def publish_native_policy_snapshot(
    store: GuardStore,
    *,
    workspace: Path | None,
    generation: int | None = None,
    config: GuardConfig | None = None,
) -> NativePolicyInstallResult | None:
    status = native_runtime_status()
    if not status.available or not status.compatible or status.capabilities is None:
        return None
    resolved_config = config or load_guard_config(store.guard_home, workspace=workspace)
    snapshot = build_native_policy_snapshot(
        resolved_config,
        rule_digest=status.capabilities.rule_digest,
        scope_digest=_workspace_scope_digest(workspace),
        generation=generation,
    )
    response = native_resident_operation(
        operation="install_policy",
        request=snapshot,
        guard_home=store.guard_home,
        timeout_seconds=1.0,
    )
    if not isinstance(response, Mapping) or response.get("status") != "installed":
        return None
    installed_generation = response.get("generation")
    snapshot_digest = response.get("snapshot_digest")
    if not isinstance(installed_generation, int) or isinstance(installed_generation, bool):
        return None
    if not isinstance(snapshot_digest, str) or len(snapshot_digest) != 64:
        return None
    return NativePolicyInstallResult(installed_generation, snapshot_digest)


__all__ = [
    "NativePolicyInstallResult",
    "build_native_policy_snapshot",
    "publish_native_policy_snapshot",
]
