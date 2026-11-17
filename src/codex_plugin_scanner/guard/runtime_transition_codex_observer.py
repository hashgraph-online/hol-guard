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
from typing import TYPE_CHECKING, Any

from . import codex_hook_command_line as _command_line
from . import codex_hook_runtime_trust
from .codex_hook_file_integrity import CodexHookIntegrityError, hook_validation_deadline
from .codex_hook_integrity import hook_manifest_path, manifest_refusal
from .codex_hook_launch_runtime import (
    desktop_hook_proxy_context,
    isolated_hook_environment,
    private_hook_runtime_cwd,
    run_isolated_hook_process,
)
from .codex_hook_recovery import _snapshot
from .codex_hook_runtime_trust import TrustedCodexHookLaunch
from .codex_install_transaction import require_codex_install_owner
from .native_daemon_peer import DaemonArtifactBinding
from .native_runtime import NativeRuntimeIdentity
from .native_transition_files import publication
from .runtime.command_activity_correlation import (
    derive_proven_request_correlation,
    load_existing_installation_correlation_key,
)
from .runtime_transition import TransitionError
from .runtime_transition_admission import (
    NativeProtectionAdmission,
    _seal_verified_admission,
)
from .runtime_transition_hook_probe import (
    OBSERVATION_SCHEMA,
    PROBE_FIELD,
    PROBE_SCHEMA,
    transition_hook_observation,
)
from .runtime_transition_legacy_receipt import read_legacy_codex_probe_receipt

if TYPE_CHECKING:
    from .store import GuardStore


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def _probe_observation(stderr: str) -> dict[str, object]:
    """The observation line the hook wrote among the runtime's own diagnostics.

    The native bridge shares the hook's stderr with the runtime's resident
    phase tracing, so the observation is one line among others rather than the
    whole stream. Naming the line by its schema only finds it; the caller still
    rebuilds it from the probe and the receipt it carries, so a line that merely
    looks like one proves nothing.
    """

    for line in reversed(stderr.splitlines()):
        candidate = line.strip()
        if not candidate.startswith("{") or OBSERVATION_SCHEMA not in candidate:
            continue
        try:
            parsed = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(parsed, dict) and parsed.get("schema") == OBSERVATION_SCHEMA:
            return parsed
    raise ValueError("observation missing")


def _desktop_hook_proxy_context() -> dict[str, str]:
    """Carry the allow-listed Desktop proxy selectors into the hook probe."""

    return desktop_hook_proxy_context()


_BINDING_TEXT = ("manifest_path", "config_sha256", "manifest_sha256")


def _installed_binding(
    guard_home: Path, config_path: Path, artifact_binding: DaemonArtifactBinding | None
) -> dict[str, Any]:
    """Have the native runtime authenticate the one installed pre-tool launch.

    The runtime authenticates the manifest, checks the live config holds its
    Guard group once, splits the registered command and authenticates the
    launch its bridge config names. A Windows command can name 8.3 short
    paths; the answer then lists them and the request is asked again with
    their long forms.
    """

    frozen = None
    if artifact_binding is not None:
        executable = str(artifact_binding.executable)
        frozen = {
            "executable": executable,
            "artifact": {
                "executable": executable,
                "sha256": artifact_binding.executable_sha256,
                "package_version": artifact_binding.package_version,
            },
        }
    request: dict[str, object] = {
        "config": str(config_path),
        "windows": _command_line.hook_commands_use_windows_syntax(),
        "long_paths": {},
        "runtime_path": str(Path(codex_hook_runtime_trust.__file__)),
        "frozen": frozen,
    }
    for _ in range(2):
        try:
            answer = publication("observer_binding", guard_home, **request)
        except CodexHookIntegrityError as exc:
            if exc.message == exc.reason:
                # The runtime names a manifest refusal by its reason alone.
                raise manifest_refusal(exc.reason) from exc
            raise
        except OSError as exc:
            raise TransitionError("admission_hook_binding_invalid") from exc
        if not isinstance(answer, dict):
            raise TransitionError("native_transition_invalid")
        expand = answer.get("expand")
        if isinstance(expand, list):
            request["long_paths"] = {str(name): _command_line._long_path(str(name)) or "" for name in expand}
            continue
        argv, environment = answer.get("argv"), answer.get("environment")
        if (
            not isinstance(argv, list)
            or not all(isinstance(item, str) for item in argv)
            or not isinstance(environment, dict)
            or not all(isinstance(key, str) and isinstance(value, str) for key, value in environment.items())
            or not isinstance(answer.get("modern_channel"), bool)
            or not all(isinstance(answer.get(key), str) for key in _BINDING_TEXT)
        ):
            raise TransitionError("native_transition_invalid")
        return answer
    raise TransitionError("admission_hook_binding_invalid")


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
    binding = _installed_binding(guard_home, config_path, artifact_binding)
    if (
        binding["config_sha256"] != hashlib.sha256(before_config).hexdigest()
        or binding["manifest_sha256"] != hashlib.sha256(before_manifest).hexdigest()
    ):
        raise TransitionError("admission_hook_binding_changed")
    argv: list[str] = binding["argv"]
    environment: dict[str, str] = binding["environment"]
    modern_channel: bool = binding["modern_channel"]
    trusted = TrustedCodexHookLaunch(
        cwd=private_hook_runtime_cwd(Path(binding["manifest_path"])),
        environment=isolated_hook_environment(),
        deadline_monotonic=deadline_monotonic,
    )
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
    launch_environment.update(_desktop_hook_proxy_context())
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
            # Keep the manifest-authenticated command as the launch target.
            # Frozen Desktop bridge routing happens only after that exact
            # configured command has parsed and validated this probe.
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
                observation = _probe_observation(result.stderr)
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
