"""Install-time Guard protection helpers."""

from __future__ import annotations

import hashlib
import os
import shlex
import subprocess
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from .config import GuardConfig
from .models import GuardReceipt
from .native_protect_request import native_protect_advisory_merge, native_protect_request
from .redaction import redact_text

ProtectAction = Literal["allow", "review", "block"]
_DEFAULT_PROTECT_TIMEOUT_SECONDS = 300
_MAX_PROTECT_TIMEOUT_SECONDS = 3600


@dataclass(frozen=True, slots=True)
class ProtectTarget:
    """A requested install or registration target."""

    artifact_id: str
    artifact_name: str
    artifact_type: str
    ecosystem: str
    package_name: str | None
    package_url: str | None
    raw_spec: str | None
    version: str | None
    source_url: str | None
    harness: str | None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ProtectRequest:
    """Parsed install-time command."""

    command: tuple[str, ...]
    install_kind: str
    executor: str
    package_manager: str | None
    harness: str | None
    targets: tuple[ProtectTarget, ...]

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        return {**payload, "command": list(self.command), "targets": list(payload["targets"])}


@dataclass(frozen=True, slots=True)
class ProtectVerdict:
    """Decision returned before install execution."""

    action: ProtectAction
    reason: str
    risk_signals: tuple[str, ...]
    matched_advisories: tuple[dict[str, object], ...]

    @property
    def blocking(self) -> bool:
        return self.action != "allow"

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        return {
            **payload,
            "risk_signals": list(self.risk_signals),
            "matched_advisories": list(payload["matched_advisories"]),
            "blocking": self.blocking,
        }


def build_protect_payload(
    *,
    command: list[str],
    store: Any,
    workspace_dir: Path,
    dry_run: bool,
    now: str,
    config: GuardConfig | None = None,
    current_config_provider: Callable[[], GuardConfig] | None = None,
    unsafe_raw_output: bool = False,
) -> tuple[dict[str, object], int]:
    """Evaluate and optionally execute an install command."""

    if len(command) == 0:
        raise ValueError("Guard protect requires a command to wrap.")
    request, cached_verdict = _native_protect(command, guard_home=None, store=store, cwd=workspace_dir)
    observe_mode = config is not None and config.mode == "observe"
    cached_gate = cached_verdict.blocking and not observe_mode
    cached_policy_context = _cached_advisory_policy_context(cached_verdict)
    from .local_supply_chain import build_package_protect_payload

    def current_cached_advisory_authority() -> tuple[object | None, dict[str, object] | None]:
        current_verdict = evaluate_protect_request(request, store, cwd=workspace_dir)
        return current_verdict.action, _cached_advisory_policy_context(current_verdict)

    final_config_provider = current_config_provider
    final_advisory_provider: Callable[[], tuple[object | None, dict[str, object] | None]] = (
        current_cached_advisory_authority
    )
    if observe_mode:
        refresh_state: dict[str, object] = {"additional_ready": False, "force_block": False}

        def refresh_additional_authority() -> tuple[object | None, dict[str, object] | None]:
            if not bool(refresh_state.get("additional_ready")):
                try:
                    action, context = current_cached_advisory_authority()
                except Exception as error:
                    refresh_state["force_block"] = True
                    action = "block"
                    context = {
                        "available": False,
                        "error": type(error).__name__,
                        "status": "authority_refresh_failed",
                        "version": 1,
                    }
                refresh_state["additional_action"] = action
                refresh_state["additional_context"] = context
                refresh_state["additional_ready"] = True
            if bool(refresh_state.get("force_block")):
                context = refresh_state.get("additional_context")
                return (
                    "block",
                    context
                    if isinstance(context, dict)
                    else {
                        "available": False,
                        "status": "authority_refresh_failed",
                        "version": 1,
                    },
                )
            context = refresh_state.get("additional_context")
            return refresh_state.get("additional_action"), context if isinstance(context, dict) else None

        def refresh_current_config() -> GuardConfig:
            current_config = config
            if current_config_provider is not None:
                try:
                    candidate = current_config_provider()
                    if not isinstance(candidate, GuardConfig):
                        raise TypeError("current config provider returned an invalid value")
                    current_config = candidate
                except Exception as error:
                    refresh_state["force_block"] = True
                    refresh_state["additional_context"] = {
                        "available": False,
                        "error": type(error).__name__,
                        "reason_code": "package_config_refresh_failed",
                        "status": "authority_refresh_failed",
                        "version": 1,
                    }
                    refresh_state["additional_ready"] = True
            _ = refresh_additional_authority()
            if bool(refresh_state.get("force_block")):
                assert current_config is not None
                return replace(current_config, mode="enforce")
            assert current_config is not None
            return current_config

        final_config_provider = refresh_current_config
        final_advisory_provider = refresh_additional_authority

    package_payload = build_package_protect_payload(
        command=command,
        store=store,
        workspace_dir=workspace_dir,
        dry_run=dry_run or cached_gate,
        allow_saved_approval_execution=cached_gate and not dry_run,
        now=now,
        config=config,
        unsafe_raw_output=unsafe_raw_output,
        timeout_seconds=_protect_command_timeout_seconds(),
        additional_current_action=cached_verdict.action,
        additional_policy_context=cached_policy_context,
        current_config_provider=final_config_provider,
        additional_authority_provider=final_advisory_provider,
    )
    if package_payload is not None:
        current_cached_verdict = evaluate_protect_request(request, store, cwd=workspace_dir)
        if not observe_mode and current_cached_verdict.blocking:
            return _merge_cached_advisory_into_package_payload(
                package_payload,
                cached_verdict=current_cached_verdict,
                requested_dry_run=dry_run,
                store=store,
                now=now,
            )
        return package_payload
    verdict = _observe_only_verdict(cached_verdict) if observe_mode else cached_verdict
    receipt = _build_install_receipt(request, verdict)
    verdict_payload = verdict.to_dict()
    if observe_mode and cached_verdict.blocking:
        verdict_payload["observed_action"] = cached_verdict.action
        verdict_payload["observe_mode"] = True
    payload: dict[str, object] = {
        "generated_at": now,
        "request": request.to_dict(),
        "targets": [target.to_dict() for target in request.targets],
        "verdict": verdict_payload,
        "executed": False,
        "dry_run": dry_run,
        "receipt": receipt.to_dict(),
        "matched_advisories": list(verdict.matched_advisories),
    }
    if observe_mode and cached_verdict.blocking:
        payload["observed_verdict"] = cached_verdict.to_dict()
    if verdict.blocking or dry_run:
        store.add_receipt(receipt)
        store.add_event(
            f"install_time_{verdict.action}",
            {
                "artifact_id": request.targets[0].artifact_id,
                "artifact_name": request.targets[0].artifact_name,
                "executor": request.executor,
                "install_kind": request.install_kind,
                "action": verdict.action,
                "risk_signals": list(verdict.risk_signals),
            },
            now,
        )
        return (payload, 2 if verdict.blocking else 0)
    execution = subprocess.run(
        list(request.command),
        cwd=workspace_dir,
        capture_output=True,
        check=False,
        text=True,
        timeout=_protect_command_timeout_seconds(),
    )
    redacted_stdout = redact_text(execution.stdout)
    redacted_stderr = redact_text(execution.stderr)
    payload["executed"] = True
    payload["execution"] = {
        "returncode": execution.returncode,
        "stdout": execution.stdout if unsafe_raw_output else redacted_stdout.text,
        "stderr": execution.stderr if unsafe_raw_output else redacted_stderr.text,
        "stdout_redactions": redacted_stdout.to_dict(),
        "stderr_redactions": redacted_stderr.to_dict(),
        "raw_output_enabled": unsafe_raw_output,
    }
    if execution.returncode == 0:
        store.add_receipt(receipt)
        store.add_event(
            "install_time_allow",
            {
                "artifact_id": request.targets[0].artifact_id,
                "artifact_name": request.targets[0].artifact_name,
                "executor": request.executor,
                "install_kind": request.install_kind,
                "action": verdict.action,
                "risk_signals": list(verdict.risk_signals),
            },
            now,
        )
    else:
        store.add_event(
            "install_time_execution_failed",
            {
                "artifact_id": request.targets[0].artifact_id,
                "artifact_name": request.targets[0].artifact_name,
                "executor": request.executor,
                "install_kind": request.install_kind,
                "action": verdict.action,
                "returncode": execution.returncode,
                "risk_signals": list(verdict.risk_signals),
            },
            now,
        )
    return (payload, int(execution.returncode))


def _observe_only_verdict(verdict: ProtectVerdict) -> ProtectVerdict:
    """Project a watch-only verdict to execution while retaining observed evidence separately."""

    if not verdict.blocking:
        return verdict
    return ProtectVerdict(
        "allow",
        f"Watch only observed a `{verdict.action}` install decision. HOL Guard allowed the command to continue.",
        verdict.risk_signals,
        verdict.matched_advisories,
    )


def _cached_advisory_policy_context(verdict: ProtectVerdict) -> dict[str, object]:
    """Return the complete cached-advisory authority bound to package approval reuse."""

    return {
        "action": verdict.action,
        "matched_advisories": [dict(advisory) for advisory in verdict.matched_advisories],
        "reason": verdict.reason,
        "risk_signals": list(verdict.risk_signals),
        "version": 1,
    }


def _merge_cached_advisory_into_package_payload(
    result: tuple[dict[str, object], int],
    *,
    cached_verdict: ProtectVerdict,
    requested_dry_run: bool,
    store: Any,
    now: str,
) -> tuple[dict[str, object], int]:
    """Apply locally cached advisory blocks/reviews to package protect results.

    The native runtime decides the merge and leaves a saved package approval
    honored; Python persists the receipt update and event it returns.
    """

    payload, exit_code = result
    if payload.get("executed") is not False:
        # An install that already ran keeps its result; the native merge
        # leaves it unchanged, so its output never needs to cross the wire.
        return result
    merged = native_protect_advisory_merge(
        payload,
        cached={
            "action": cached_verdict.action,
            "reason": cached_verdict.reason,
            "risk_signals": list(cached_verdict.risk_signals),
            "matched_advisories": [dict(advisory) for advisory in cached_verdict.matched_advisories],
        },
        requested_dry_run=requested_dry_run,
        exit_code=exit_code,
        guard_home=Path(store.guard_home).expanduser().resolve(strict=False),
    )
    if merged is None:
        return result
    updated, merged_exit_code, receipt_update, event = merged
    if receipt_update is not None:
        store.update_receipt_policy_decision(*receipt_update)
    if event is not None:
        store.add_event(event[0], event[1], now)
    return ({**payload, **updated}, merged_exit_code)


def _protect_command_timeout_seconds() -> int:
    raw_timeout = os.getenv("GUARD_PROTECT_TIMEOUT_SECONDS")
    if raw_timeout is None:
        return _DEFAULT_PROTECT_TIMEOUT_SECONDS
    try:
        parsed_timeout = int(raw_timeout)
    except ValueError:
        return _DEFAULT_PROTECT_TIMEOUT_SECONDS
    if parsed_timeout < 1:
        return _DEFAULT_PROTECT_TIMEOUT_SECONDS
    return min(parsed_timeout, _MAX_PROTECT_TIMEOUT_SECONDS)


def parse_protect_command(command: list[str], *, guard_home: Path | None = None) -> ProtectRequest:
    """Parse a package install or harness registration command in the native resident."""

    request, _verdict = _native_protect(command, guard_home=guard_home, store=None)
    return request


def evaluate_protect_request(request: ProtectRequest, store: Any, *, cwd: Path | None = None) -> ProtectVerdict:
    """Calculate the local install-time verdict against the store's cached advisories."""

    _request, verdict = _native_protect(list(request.command), guard_home=None, store=store, cwd=cwd)
    return verdict


def _native_protect(
    command: list[str],
    *,
    guard_home: Path | None,
    store: Any | None,
    cwd: Path | None = None,
) -> tuple[ProtectRequest, ProtectVerdict]:
    home = Path(store.guard_home) if store is not None else guard_home
    store_path = Path(store.path) if store is not None else None
    request, verdict = native_protect_request(
        command,
        guard_home=None if home is None else home.expanduser().resolve(strict=False),
        store_path=None if store_path is None else store_path.expanduser().resolve(strict=False),
        cwd=cwd,
    )
    return (
        ProtectRequest(
            command=tuple(request["command"]),
            install_kind=request["install_kind"],
            executor=request["executor"],
            package_manager=request["package_manager"],
            harness=request["harness"],
            targets=tuple(ProtectTarget(**target) for target in request["targets"]),
        ),
        ProtectVerdict(
            action=verdict["action"],
            reason=verdict["reason"],
            risk_signals=verdict["risk_signals"],
            matched_advisories=verdict["matched_advisories"],
        ),
    )


def _build_install_receipt(request: ProtectRequest, verdict: ProtectVerdict) -> GuardReceipt:
    primary_target = request.targets[0]
    artifact_hash = _command_fingerprint(list(request.command))
    capabilities_summary = f"{request.executor} {request.install_kind.replace('_', ' ')}"
    provenance_summary = shlex.join(request.command)
    changed_capabilities = list(verdict.risk_signals)
    sample = ", ".join(changed_capabilities[:3])
    suffix = " ..." if len(changed_capabilities) > 3 else ""
    diff_summary = f"{len(changed_capabilities)} change(s): {sample}{suffix}" if changed_capabilities else None
    receipt_harness = request.harness
    if receipt_harness is None:
        if _is_package_tool_request(request):
            # Unsupported package subcommands (for example `bun run`) bypass
            # the structured package projection. Keep their receipt aligned
            # with the package path's shared runtime-origin resolver.
            from .runtime.package_protect_projection import resolve_local_supply_chain_harness

            receipt_harness = resolve_local_supply_chain_harness()
        else:
            receipt_harness = request.executor
    return GuardReceipt(
        receipt_id=f"guard-receipt-{uuid4()}",
        timestamp=datetime.now(timezone.utc).isoformat(),
        harness=receipt_harness,
        artifact_id=primary_target.artifact_id,
        artifact_hash=artifact_hash,
        policy_decision=verdict.action,
        capabilities_summary=capabilities_summary,
        changed_capabilities=tuple(changed_capabilities),
        provenance_summary=provenance_summary,
        artifact_name=primary_target.artifact_name,
        source_scope="install",
        diff_summary=diff_summary,
    )


def _is_package_tool_request(request: ProtectRequest) -> bool:
    if request.package_manager is not None:
        return True
    from .shims import package_shim_supported_managers

    return request.executor.strip().lower() in package_shim_supported_managers()


def _command_fingerprint(command: list[str]) -> str:
    payload = "\u0000".join(command).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
