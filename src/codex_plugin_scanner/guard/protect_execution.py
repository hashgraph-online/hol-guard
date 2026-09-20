"""Install execution and cached advisory projection through the live Protect facade."""

from __future__ import annotations


def build_protect_payload(
    *,
    command: list[str],
    store: _protect.Any,
    workspace_dir: _protect.Path,
    dry_run: bool,
    now: str,
    config: _protect.GuardConfig | None = None,
    current_config_provider: _protect.Callable[[], _protect.GuardConfig] | None = None,
    unsafe_raw_output: bool = False,
) -> tuple[dict[str, object], int]:
    """Evaluate and optionally execute an install command."""

    if len(command) == 0:
        raise ValueError("Guard protect requires a command to wrap.")
    request = _protect.parse_protect_command(command)
    advisories = store.list_cached_advisories(limit=None)
    cached_verdict = _protect.evaluate_protect_request(request, advisories)
    observe_mode = config is not None and config.mode == "observe"
    cached_gate = cached_verdict.blocking and not observe_mode
    cached_policy_context = _protect._cached_advisory_policy_context(cached_verdict)
    from .local_supply_chain import build_package_protect_payload

    def current_cached_advisory_authority() -> tuple[object | None, dict[str, object] | None]:
        current_verdict = _protect.evaluate_protect_request(request, store.list_cached_advisories(limit=None))
        return current_verdict.action, _protect._cached_advisory_policy_context(current_verdict)

    final_config_provider = current_config_provider
    final_advisory_provider: _protect.Callable[[], tuple[object | None, dict[str, object] | None]] = (
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

        def refresh_current_config() -> _protect.GuardConfig:
            current_config = config
            if current_config_provider is not None:
                try:
                    candidate = current_config_provider()
                    if not isinstance(candidate, _protect.GuardConfig):
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
                return _protect.replace(current_config, mode="enforce")
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
        timeout_seconds=_protect._protect_command_timeout_seconds(),
        additional_current_action=cached_verdict.action,
        additional_policy_context=cached_policy_context,
        current_config_provider=final_config_provider,
        additional_authority_provider=final_advisory_provider,
    )
    if package_payload is not None:
        current_cached_verdict = _protect.evaluate_protect_request(request, store.list_cached_advisories(limit=None))
        if (
            not observe_mode
            and current_cached_verdict.blocking
            and package_payload[0].get("executed") is False
            and not _protect._package_payload_uses_saved_approval(package_payload[0])
        ):
            return _protect._merge_cached_advisory_into_package_payload(
                package_payload,
                cached_verdict=current_cached_verdict,
                requested_dry_run=dry_run,
                store=store,
                now=now,
            )
        return package_payload
    verdict = _protect._observe_only_verdict(cached_verdict) if observe_mode else cached_verdict
    receipt = _protect._build_install_receipt(request, verdict)
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
    execution = _protect.subprocess.run(
        list(request.command),
        cwd=workspace_dir,
        capture_output=True,
        check=False,
        text=True,
        timeout=_protect._protect_command_timeout_seconds(),
    )
    redacted_stdout = _protect.redact_text(execution.stdout)
    redacted_stderr = _protect.redact_text(execution.stderr)
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


def _observe_only_verdict(verdict: _protect.ProtectVerdict) -> _protect.ProtectVerdict:
    """Project a watch-only verdict to execution while retaining observed evidence separately."""

    if not verdict.blocking:
        return verdict
    return _protect.ProtectVerdict(
        "allow",
        f"Watch only observed a `{verdict.action}` install decision. HOL Guard allowed the command to continue.",
        verdict.risk_signals,
        verdict.matched_advisories,
    )


def _cached_advisory_policy_context(verdict: _protect.ProtectVerdict) -> dict[str, object]:
    """Return the complete cached-advisory authority bound to package approval reuse."""

    return {
        "action": verdict.action,
        "matched_advisories": [dict(advisory) for advisory in verdict.matched_advisories],
        "reason": verdict.reason,
        "risk_signals": list(verdict.risk_signals),
        "version": 1,
    }


def _package_payload_uses_saved_approval(payload: dict[str, object]) -> bool:
    evaluation = payload.get("supply_chain_evaluation")
    verdict = payload.get("verdict")
    if not isinstance(evaluation, dict) or not isinstance(verdict, dict):
        return False
    if verdict.get("action") != "allow":
        return False
    reasons = evaluation.get("reasons")
    if not isinstance(reasons, list):
        return False
    return any(isinstance(reason, dict) and reason.get("code") == "saved_package_approval" for reason in reasons)


def _merge_cached_advisory_into_package_payload(
    result: tuple[dict[str, object], int],
    *,
    cached_verdict: _protect.ProtectVerdict,
    requested_dry_run: bool,
    store: _protect.Any,
    now: str,
) -> tuple[dict[str, object], int]:
    """Apply locally cached advisory blocks/reviews to package protect results."""

    payload, exit_code = result
    verdict = payload.get("verdict")
    if not isinstance(verdict, dict):
        return result
    package_action = verdict.get("action")
    if not isinstance(package_action, str):
        package_action = "allow"

    merged_action = package_action
    merged_reason = verdict.get("reason")
    if not isinstance(merged_reason, str):
        merged_reason = cached_verdict.reason
    merged_advisories = list(verdict.get("matched_advisories") or [])
    risk_signals = list(verdict.get("risk_signals") or [])

    if cached_verdict.action == "block":
        merged_action = "block"
        merged_reason = cached_verdict.reason
    elif cached_verdict.action == "review" and package_action in {"allow", "warn"}:
        merged_action = "review"
        merged_reason = cached_verdict.reason

    for item in cached_verdict.matched_advisories:
        if item not in merged_advisories:
            merged_advisories.append(item)
    for signal in cached_verdict.risk_signals:
        if signal not in risk_signals:
            risk_signals.append(signal)

    action_changed = merged_action != package_action
    advisories_changed = merged_advisories != list(verdict.get("matched_advisories") or [])
    if not action_changed and not advisories_changed:
        return result

    blocking = merged_action in {"block", "review"}
    updated_verdict = {
        **verdict,
        "action": merged_action,
        "reason": merged_reason,
        "risk_signals": risk_signals,
        "matched_advisories": merged_advisories,
        "blocking": blocking,
    }
    updated_payload: dict[str, object] = {
        **payload,
        "verdict": updated_verdict,
        "matched_advisories": merged_advisories,
        "executed": False,
        "dry_run": requested_dry_run or blocking,
    }
    exact_action = _protect.normalize_guard_action(merged_action, unknown_action="block")
    supply_chain_evaluation = payload.get("supply_chain_evaluation")
    if isinstance(supply_chain_evaluation, dict):
        canonical_copy = _protect.decision_from_legacy_policy_action(
            exact_action,
            reason=merged_reason,
        )
        existing_user_copy = supply_chain_evaluation.get("user_copy")
        user_copy = dict(existing_user_copy) if isinstance(existing_user_copy, dict) else {}
        user_copy.update(
            {
                "title": canonical_copy.user_title,
                "summary": canonical_copy.user_body,
                "next_step": canonical_copy.retry_instruction or canonical_copy.user_body,
                "harness_message": canonical_copy.harness_message,
            }
        )
        updated_payload["supply_chain_evaluation"] = {
            **supply_chain_evaluation,
            "decision": canonical_copy.action,
            "policy_action": exact_action,
            "risk_summary": merged_reason,
            "user_copy": user_copy,
        }
    receipt = payload.get("receipt")
    if isinstance(receipt, dict):
        action_envelope = receipt.get("action_envelope_json")
        updated_action_envelope = dict(action_envelope) if isinstance(action_envelope, dict) else None
        if updated_action_envelope is not None:
            for key in ("policy_action", "pre_execution_result"):
                if key in updated_action_envelope:
                    updated_action_envelope[key] = exact_action
        updated_receipt = {
            **receipt,
            "policy_decision": exact_action,
            **({"action_envelope_json": updated_action_envelope} if updated_action_envelope is not None else {}),
        }
        updated_payload["receipt"] = updated_receipt
        if action_changed:
            receipt_id = updated_receipt.get("receipt_id")
            if isinstance(receipt_id, str) and receipt_id:
                store.update_receipt_policy_decision(receipt_id, exact_action)
        if action_changed:
            request = payload.get("request")
            executor = request.get("executor") if isinstance(request, dict) else None
            install_kind = request.get("install_kind") if isinstance(request, dict) else None
            store.add_event(
                f"install_time_{merged_action}",
                {
                    "artifact_id": updated_receipt.get("artifact_id"),
                    "artifact_name": updated_receipt.get("artifact_name"),
                    "executor": executor,
                    "install_kind": install_kind,
                    "action": merged_action,
                    "risk_signals": risk_signals,
                    "cached_advisory_override": True,
                },
                now,
            )
    if blocking:
        return (updated_payload, 2)
    return (updated_payload, exit_code)


def _protect_command_timeout_seconds() -> int:
    raw_timeout = _protect.os.getenv("GUARD_PROTECT_TIMEOUT_SECONDS")
    if raw_timeout is None:
        return _protect._DEFAULT_PROTECT_TIMEOUT_SECONDS
    try:
        parsed_timeout = int(raw_timeout)
    except ValueError:
        return _protect._DEFAULT_PROTECT_TIMEOUT_SECONDS
    if parsed_timeout < 1:
        return _protect._DEFAULT_PROTECT_TIMEOUT_SECONDS
    return min(parsed_timeout, _protect._MAX_PROTECT_TIMEOUT_SECONDS)


# Resolve the facade after declarations so direct helper imports retain the cycle.
from . import protect as _protect  # noqa: E402
