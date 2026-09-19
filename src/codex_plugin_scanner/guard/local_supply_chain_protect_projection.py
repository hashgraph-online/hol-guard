"""Protect projection helpers using the original live supply-chain namespace."""

from __future__ import annotations


def _apply_package_protect_projection(
    *,
    payload: dict[str, object],
    authority: _api._PackageProtectAuthority,
    evaluation: _api.Any,
    command: _api.Sequence[str],
    blocking: bool,
    executed: bool,
    execution_policy_action: _api.GuardAction | None = None,
) -> _api._PackageProtectProjection:
    """Project one authority/evaluation pair into every user and audit surface."""

    intent = authority.intent
    context = _api._package_protect_verdict_context(
        authority=authority,
        evaluation=evaluation,
        execution_policy_action=execution_policy_action,
    )
    payload["request"] = {
        "command": _api.shlex.split(intent.redacted_command),
        "redacted_command": intent.redacted_command,
        "install_kind": intent.intent_kind,
        "executor": str(command[0]) if command else _api._LOCAL_SUPPLY_CHAIN_HARNESS,
        "package_manager": intent.package_manager,
        "harness": authority.invoking_harness,
        "targets": context.public_targets,
        "manifest_paths": list(intent.manifest_paths),
        "lockfile_paths": list(intent.lockfile_paths),
        "package_execution_context": authority.execution_context.to_evidence(),
    }
    payload["targets"] = [
        _api._protect_target_payload(target, harness=authority.invoking_harness) for target in intent.targets
    ]
    payload["verdict"] = {
        "action": context.verdict_action,
        "reason": context.verdict_reason,
        "risk_signals": list(context.risk_signals),
        "matched_advisories": context.matched_advisories,
        "blocking": blocking,
    }
    if context.observe_projected:
        payload["verdict"]["observe_mode"] = True
        payload["verdict"]["observed_policy_action"] = context.observed_policy_action
    payload["receipt"] = {
        **context.receipt.to_dict(),
        "action_envelope_json": context.receipt_policy_metadata,
    }
    payload["matched_advisories"] = context.matched_advisories
    payload["supply_chain_evaluation"] = evaluation.to_dict()
    payload["executed"] = executed
    return _api._PackageProtectProjection(
        receipt=context.receipt,
        receipt_policy_metadata=context.receipt_policy_metadata,
        verdict_action=context.verdict_action,
        risk_signals=context.risk_signals,
    )


def _install_time_event_payload(
    *,
    authority: _api._PackageProtectAuthority,
    command: _api.Sequence[str],
    action: _api.GuardAction,
    risk_signals: tuple[str, ...] | list[str],
    **extra: object,
) -> dict[str, object]:
    return {
        "artifact_id": authority.artifact.artifact_id,
        "artifact_name": authority.artifact.name,
        "executor": str(command[0]) if command else _api._LOCAL_SUPPLY_CHAIN_HARNESS,
        "harness": authority.invoking_harness,
        "install_kind": authority.intent.intent_kind,
        "action": action,
        "risk_signals": list(risk_signals),
        **extra,
    }


def _package_protect_denied_after_final_boundary(
    *,
    payload: dict[str, object],
    authority: _api._PackageProtectAuthority,
    evaluation: _api.Any,
    command: _api.Sequence[str],
    store: _api.Any,
    now: str,
) -> tuple[dict[str, object], int]:
    projection = _api._apply_package_protect_projection(
        payload=payload,
        authority=authority,
        evaluation=evaluation,
        command=command,
        blocking=True,
        executed=False,
    )
    store.add_receipt(projection.receipt)
    store.set_receipt_action_envelope(
        projection.receipt.receipt_id,
        projection.receipt_policy_metadata,
    )
    store.add_event(
        f"install_time_{projection.verdict_action}",
        _api._install_time_event_payload(
            authority=authority,
            command=command,
            action=projection.verdict_action,
            risk_signals=projection.risk_signals,
        ),
        now,
    )
    return payload, _api._package_execution_exit_code(evaluation.policy_action)


def redacted_command_tokens(command: _api.Sequence[str]) -> tuple[str, ...]:
    return tuple(_api._redact_command_token(str(token)) for token in command)


def _build_command_execution_payload(
    *,
    stdout: str,
    stderr: str,
    returncode: int,
    unsafe_raw_output: bool,
) -> dict[str, object]:
    redacted_stdout = _api.redact_text(stdout)
    redacted_stderr = _api.redact_text(stderr)
    return {
        "returncode": returncode,
        "stdout": stdout if unsafe_raw_output else redacted_stdout.text,
        "stderr": stderr if unsafe_raw_output else redacted_stderr.text,
        "stdout_redactions": redacted_stdout.to_dict(),
        "stderr_redactions": redacted_stderr.to_dict(),
        "raw_output_enabled": unsafe_raw_output,
    }


def _coerce_command_output(value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        return value
    return ""


def _coerce_command_error_output(error: _api.subprocess.TimeoutExpired | OSError) -> str:
    parts = [_api._coerce_command_output(getattr(error, "stderr", None))]
    message = str(error).strip()
    if message:
        parts.append(message)
    return "\n".join(part for part in parts if part)


def _evaluation_exit_code(decision: str) -> int:
    return 2 if decision in {"block", "ask"} else 0


def _package_execution_exit_code(policy_action: object) -> int:
    return 0 if _api.is_execution_permitted(policy_action) else 2


def _protect_action_for_policy_action(policy_action: object) -> _api.GuardAction:
    return _api.normalize_guard_action(policy_action, unknown_action="block")


def _evaluation_risk_signals(evaluation: object) -> list[str]:
    if not _api._is_package_request_evaluation(evaluation):
        return []
    reasons = evaluation.reasons
    signals: list[str] = []
    for item in reasons:
        if not isinstance(item, dict):
            continue
        message = item.get("message")
        if isinstance(message, str) and message:
            signals.append(message)
    if signals:
        return signals
    summary = getattr(evaluation, "risk_summary", None)
    return [summary] if isinstance(summary, str) and summary else []


def _matched_advisories(evaluation: object) -> list[dict[str, object]]:
    if not _api._is_package_request_evaluation(evaluation):
        return []
    packages = evaluation.packages
    advisories: list[dict[str, object]] = []
    for item in packages:
        if not isinstance(item, dict):
            continue
        for advisory_id in _api._string_items(item.get("related_advisory_ids")):
            advisories.append(
                {
                    "advisory_id": advisory_id,
                    "package_name": item.get("name"),
                    "version": item.get("version"),
                    "decision": item.get("decision"),
                }
            )
    return advisories


def _redact_command_token(token: str) -> str:
    token = _api.redact_package_request_token(token)
    if "=" in token:
        key, _, _ = token.partition("=")
        if any(fragment in key.lower() for fragment in ("token", "secret", "api_key", "api-key", "password")):
            return f"{key}=*****"
    if ":" in token:
        key, _, _ = token.partition(":")
        if any(fragment in key.lower() for fragment in ("token", "secret", "api_key", "api-key", "password")):
            return f"{key}: *****"
    return _api.redact_text(token).text


# Bind after declarations so importing this owner directly preserves the facade cycle.
from . import local_supply_chain as _api  # noqa: E402
