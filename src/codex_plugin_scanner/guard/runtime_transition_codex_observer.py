"""Observe fresh decisions from an authenticated, configured Codex hook.

Commands below are classification inputs only. The only launched program is
the exact argv authenticated by the installed manifest. Legacy packages use
fresh keyed activity/receipt linkage instead of the newer stderr channel.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import tomllib

from .adapters.codex import _CODEX_GUARD_TOOL_MATCHER, _payload_has_hooks_feature_enabled
from .codex_hook_bridge_runtime import bridge_config_from_argv, trusted_hook_launch
from .codex_hook_file_integrity import CodexHookIntegrityError, hook_validation_deadline, split_hook_command
from .codex_hook_integrity import hook_manifest_path, load_authenticated_hook_manifest
from .codex_hook_launch_runtime import run_isolated_hook_process
from .codex_hook_recovery import _snapshot
from .codex_hook_runtime_trust import TrustedCodexHookLaunch
from .codex_install_transaction import require_codex_install_owner
from .daemon.live_identity import DaemonArtifactBinding
from .native_runtime import NativeRuntimeIdentity
from .runtime.command_activity_correlation import (
    derive_proven_request_correlation,
    load_existing_installation_correlation_key,
)
from .runtime_transition import TransitionError
from .runtime_transition_admission import (
    NativeProtectionAdmission,
    _seal_verified_admission,
)
from .runtime_transition_hook_probe import PROBE_FIELD, PROBE_SCHEMA, transition_hook_observation
from .runtime_transition_legacy_receipt import read_legacy_codex_probe_receipt

if TYPE_CHECKING:
    from .store import GuardStore


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def observe_configured_codex_hook(
    *,
    operation_id: str,
    artifact_generation: str,
    expected_runtime: NativeRuntimeIdentity,
    guard_home: Path,
    config_path: Path,
    workspace: Path,
    deadline_monotonic: float,
    artifact_binding: DaemonArtifactBinding | None = None,
    receipt_store: GuardStore | None = None,
) -> NativeProtectionAdmission:
    """Require two bounded exact-argv launches and unchanged signed bindings.

    The transition owner must already hold the home-wide publication lock. The
    daemon driver separately verifies its authenticated live identity around
    this observation. File validation checks the original deadline on return;
    blocking filesystem calls themselves are not yet interruptible.
    """
    try:
        with hook_validation_deadline(deadline_monotonic):
            return _observe_configured_codex_hook(
                operation_id=operation_id,
                artifact_generation=artifact_generation,
                expected_runtime=expected_runtime,
                guard_home=guard_home,
                config_path=config_path,
                workspace=workspace,
                deadline_monotonic=deadline_monotonic,
                artifact_binding=artifact_binding,
                receipt_store=receipt_store,
            )
    except CodexHookIntegrityError as exc:
        if exc.reason == "codex_hook_validation_deadline_expired":
            raise TransitionError("admission_deadline_expired") from exc
        raise


def _observe_configured_codex_hook(
    *,
    operation_id: str,
    artifact_generation: str,
    expected_runtime: NativeRuntimeIdentity,
    guard_home: Path,
    config_path: Path,
    workspace: Path,
    deadline_monotonic: float,
    artifact_binding: DaemonArtifactBinding | None = None,
    receipt_store: GuardStore | None = None,
) -> NativeProtectionAdmission:
    def check_deadline() -> None:
        if time.monotonic() >= deadline_monotonic:
            raise TransitionError("admission_deadline_expired")

    check_deadline()
    try:
        if str(uuid.UUID(operation_id)) != operation_id or not artifact_generation:
            raise ValueError("invalid operation identity")
    except ValueError:
        raise TransitionError("admission_identity_invalid") from None
    require_codex_install_owner(guard_home)
    manifest_path = hook_manifest_path(guard_home, config_path)
    before_config, before_manifest = _snapshot(config_path), _snapshot(manifest_path)
    check_deadline()
    if before_config is None or before_manifest is None:
        raise TransitionError("admission_hook_authority_missing")
    try:
        manifest = load_authenticated_hook_manifest(guard_home, config_path)
        config = tomllib.loads(before_config.decode("utf-8"))
        if not _payload_has_hooks_feature_enabled(config):
            raise ValueError("hooks disabled")
        events = manifest.get("events")
        if not isinstance(events, list):
            raise ValueError("events missing")
        bindings = [entry for entry in events if isinstance(entry, dict) and entry.get("event") == "PreToolUse"]
        if len(bindings) != 1:
            raise ValueError("ambiguous pre-tool binding")
        binding = bindings[0]
        group, handler = binding.get("group"), binding.get("handler")
        if (
            not isinstance(group, dict)
            or not isinstance(handler, dict)
            or group.get("matcher") != _CODEX_GUARD_TOOL_MATCHER
            or group.get("hooks") != [handler]
            or binding.get("handler_index") != 0
            or handler.get("type") != "command"
        ):
            raise ValueError("unsupported installed hook")
        hooks = config.get("hooks")
        configured = hooks.get("PreToolUse") if isinstance(hooks, dict) else None
        if not isinstance(configured, list) or configured.count(group) != 1:
            raise ValueError("configured binding mismatch")
        command = handler.get("command")
        argv = split_hook_command(command) if isinstance(command, str) else None
        if argv is None or len(argv) < 3 or argv != binding.get("argv"):
            raise ValueError("configured argv mismatch")
        environment = handler.get("env", {})
        if not isinstance(environment, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in environment.items()
        ):
            raise ValueError("configured environment invalid")
        packaged = manifest.get("packaged_files")
        if not isinstance(packaged, list):
            raise ValueError("installed observation channel unavailable")
        roles = {entry.get("role") for entry in packaged if isinstance(entry, dict)}
        modern_channel = {"hook_probe", "native_receipt"} <= roles
        if not modern_channel and roles & {"hook_probe", "native_receipt"}:
            raise ValueError("installed observation channel unavailable")
        bridge_config = bridge_config_from_argv([argv[-2], argv[-1]], timeout_grace_seconds=0)
        if Path(bridge_config["manifest_path"]).resolve() != manifest_path.resolve():
            raise ValueError("foreign hook authority")
        if artifact_binding is None:
            trusted = trusted_hook_launch(
                manifest_path=bridge_config["manifest_path"],
                state_path=bridge_config["state_path"],
                fallback_command=bridge_config["fallback_command"],
                start_command=bridge_config["start_command"],
                config_json=bridge_config["config_json"],
                deadline_monotonic=deadline_monotonic,
            )
        else:
            from .frozen_codex_runtime import _validate_frozen_codex_hook_launch

            trusted = _validate_frozen_codex_hook_launch(
                manifest_path=bridge_config["manifest_path"],
                state_path=bridge_config["state_path"],
                fallback_command=bridge_config["fallback_command"],
                start_command=bridge_config["start_command"],
                config_json=bridge_config["config_json"],
                expected_artifact=artifact_binding,
            )
        if not isinstance(trusted, TrustedCodexHookLaunch):
            raise ValueError("installed launch context invalid")
    except (ValueError, OSError, SystemExit) as exc:
        raise TransitionError("admission_hook_binding_invalid") from exc
    check_deadline()
    legacy_key = None
    if not modern_channel:
        if receipt_store is None or receipt_store.guard_home.resolve() != guard_home.resolve():
            raise TransitionError("legacy_probe_store_unavailable")
        try:
            legacy_key = load_existing_installation_correlation_key(guard_home)
        except (ValueError, OSError, RecursionError) as exc:
            raise TransitionError("legacy_probe_correlation_invalid") from exc
        check_deadline()
        if legacy_key is None:
            raise TransitionError("legacy_probe_correlation_unavailable")

    def check_legacy_key() -> None:
        check_deadline()
        if legacy_key is not None:
            try:
                current = load_existing_installation_correlation_key(guard_home)
            except (ValueError, OSError, RecursionError) as exc:
                raise TransitionError("legacy_probe_correlation_changed") from exc
            check_deadline()
            if (
                current is None
                or current.key_id != legacy_key.key_id
                or not hmac.compare_digest(
                    current.derive(b"transition-generation"), legacy_key.derive(b"transition-generation")
                )
            ):
                raise TransitionError("legacy_probe_correlation_changed")

    if _snapshot(config_path) != before_config or _snapshot(manifest_path) != before_manifest:
        raise TransitionError("admission_hook_binding_changed")
    receipts: list[dict[str, object]] = []
    output_digests: list[str] = []
    launch_environment = dict(trusted.environment)
    launch_environment.update(environment)
    for probe_command, decision in (("pwd", "allow"), ("rm -rf /", "deny")):
        check_deadline()
        request_id = "transition-hook-" + uuid.uuid4().hex
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": probe_command},
            "cwd": str(workspace.resolve()),
        }
        if modern_channel:
            payload[PROBE_FIELD] = {"schema": PROBE_SCHEMA, "operation_id": operation_id, "request_id": request_id}
        else:
            payload["tool_call_id"] = request_id
        check_legacy_key()
        since = datetime.now(timezone.utc)
        result = run_isolated_hook_process(
            argv,
            input_text=json.dumps(payload),
            cwd=trusted.cwd,
            environment=launch_environment,
            output_limit=64 * 1024,
            deadline_monotonic=deadline_monotonic,
        )
        check_deadline()
        if result.returncode != 0 or result.timed_out or result.containment_failed or result.output_limit_exceeded:
            raise TransitionError("admission_hook_launch_failed")
        try:
            output = json.loads(result.stdout)
            if not isinstance(output, dict):
                raise ValueError("non-object observation")
            if modern_channel:
                observation = json.loads(result.stderr)
                if not isinstance(observation, dict):
                    raise ValueError("non-object observation")
                checked = transition_hook_observation(payload, observation.get("native_receipt"))
                if checked is None or checked != observation:
                    raise ValueError("observation mismatch")
                receipt = checked["native_receipt"]
                assert isinstance(receipt, dict)
            else:
                assert legacy_key is not None and receipt_store is not None
                correlation = derive_proven_request_correlation(
                    harness="codex",
                    event="PreToolUse",
                    payload=payload,
                    key=legacy_key,
                )
                if correlation is None:
                    raise ValueError("request correlation unavailable")
                while True:
                    check_legacy_key()
                    try:
                        receipt = read_legacy_codex_probe_receipt(
                            receipt_store,
                            correlation=correlation,
                            since=since,
                            deadline_monotonic=deadline_monotonic,
                        )
                    except sqlite3.Error as exc:
                        raise TransitionError("legacy_probe_storage_unavailable") from exc
                    if receipt is not None:
                        break
                    check_deadline()
                    time.sleep(min(0.025, max(0.0, deadline_monotonic - time.monotonic())))
            hook_output = output.get("hookSpecificOutput", {})
            permission = hook_output.get("permissionDecision") if isinstance(hook_output, dict) else None
            if (
                receipt["decision"] != decision
                or receipt["runtime_identity"] != expected_runtime.sha256
                or (
                    decision == "allow"
                    and (
                        output.get("continue") is False
                        or receipt["policy_action"] not in {"allow", "warn"}
                        or permission not in {None, "allow"}
                    )
                )
                or (decision == "deny" and permission != "deny")
            ):
                raise ValueError("protection mismatch")
        except (ValueError, KeyError, TypeError) as exc:
            raise TransitionError("admission_protection_failed") from exc
        receipts.append(receipt)
        output_digests.append(_digest(output))
    check_deadline()
    check_legacy_key()
    if _snapshot(config_path) != before_config or _snapshot(manifest_path) != before_manifest:
        raise TransitionError("admission_hook_binding_changed")
    check_deadline()
    allow, deny = receipts
    generation, policy_digest = allow["policy_generation"], allow["policy_digest"]
    if type(generation) is not int or not isinstance(policy_digest, str):
        raise TransitionError("admission_policy_mismatch")
    if (
        allow["policy_generation"] != deny["policy_generation"]
        or allow["policy_digest"] != deny["policy_digest"]
        or allow["request_digest"] == deny["request_digest"]
    ):
        raise TransitionError("admission_policy_mismatch")
    evidence: dict[str, object] = {
        "schema": "hol-guard.installed-hook-evidence.v1",
        "harness": "codex",
        "observation_channel": "probe-envelope" if modern_channel else "persisted-receipt",
        "config_sha256": hashlib.sha256(before_config).hexdigest(),
        "manifest_sha256": hashlib.sha256(before_manifest).hexdigest(),
        "argv_sha256": _digest(argv),
        "environment_sha256": _digest(environment),
        "output_sha256": output_digests,
    }
    return _seal_verified_admission(
        NativeProtectionAdmission(
            operation_id,
            artifact_generation,
            expected_runtime,
            generation,
            policy_digest,
            allow,
            deny,
            guard_home.resolve(),
            time.monotonic(),
            evidence,
        )
    )
