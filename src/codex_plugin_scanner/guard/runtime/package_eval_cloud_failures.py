"""Cloud failure decisions and package review copy."""

from __future__ import annotations


def _normalize_package_user_copy(
    user_copy: _eval.SupplyChainUserCopy, *, policy_action: _eval.GuardAction
) -> _eval.SupplyChainUserCopy:
    dashboard_url = user_copy.dashboard_url
    if _eval._looks_like_cloud_inbox_url(dashboard_url):
        dashboard_url = None
    harness_message = _eval._CLOUD_INBOX_URL_RE.sub("", user_copy.harness_message or "").strip()
    harness_message = " ".join(harness_message.split())
    harness_message = _eval._strip_review_evidence_tail(harness_message)
    terminal_action = policy_action in {"sandbox-required", "block"}
    if terminal_action:
        dashboard_url = None
        harness_message = _eval._LOCAL_APPROVAL_INSTRUCTION_RE.sub("", harness_message)
        harness_message = _eval._LOCAL_APPROVAL_REQUEST_URL_RE.sub("", harness_message)
        harness_message = _eval._LOCAL_REVIEW_INSTRUCTION_RE.sub("", harness_message)
        harness_message = " ".join(harness_message.split()).strip()
    needs_local_review = policy_action in {"review", "require-reapproval"}
    if needs_local_review and _eval._LOCAL_REVIEW_INSTRUCTION.lower() not in harness_message.lower():
        harness_message = f"{harness_message} {_eval._LOCAL_REVIEW_INSTRUCTION}".strip()
    return _eval.replace(user_copy, dashboard_url=dashboard_url, harness_message=harness_message)


def _strip_review_evidence_tail(message: str) -> str:
    stripped = message.strip()
    lower_stripped = stripped.lower()
    for suffix in ("Review evidence: .", "Review evidence:.", "Review evidence:"):
        if lower_stripped.endswith(suffix.lower()):
            return stripped[: -len(suffix)].rstrip()
    return stripped


def _looks_like_cloud_inbox_url(url: str | None) -> bool:
    if url is None or not url.strip():
        return False
    parsed = _eval.urllib.parse.urlparse(url.strip())
    return parsed.path.rstrip("/") == "/guard/inbox"


def _cloud_http_fail_closed_evaluation(
    *,
    status_code: int,
    artifact: _eval.GuardArtifact,
    targets: tuple[dict[str, object], ...],
    workspace_dir: _eval.Path | None,
    workspace_fingerprint: str | None,
    bundle_meta: dict[str, str] | None,
    fail_closed_decision: str,
) -> _eval.PackageRequestEvaluation | None:
    if status_code == 403:
        return _eval._cloud_fail_closed_evaluation(
            code="cloud_auth_error",
            message="Guard cloud evaluation was not authorized, so this package request needs review.",
            artifact=artifact,
            targets=targets,
            workspace_dir=workspace_dir,
            workspace_fingerprint=workspace_fingerprint,
            bundle_meta=bundle_meta,
            fail_closed_decision=fail_closed_decision,
        )
    if fail_closed_decision != "block":
        return None
    if status_code == 401:
        code = "cloud_auth_error"
        message = (
            "Guard Cloud could not authorize this package check. Guard blocked the install "
            "rather than bypassing Cloud package protection."
        )
    elif status_code in {400, 404}:
        code = "cloud_validation_error"
        message = (
            "Guard Cloud could not validate this package request. Guard blocked the install "
            "rather than bypassing Cloud package protection."
        )
    else:
        code = "cloud_http_error"
        message = (
            f"Guard Cloud returned HTTP {status_code} while verifying this package. Guard blocked the install "
            "rather than bypassing Cloud package protection."
        )
    return _eval._cloud_fail_closed_evaluation(
        code=code,
        message=message,
        artifact=artifact,
        targets=targets,
        workspace_dir=workspace_dir,
        workspace_fingerprint=workspace_fingerprint,
        bundle_meta=bundle_meta,
        fail_closed_decision=fail_closed_decision,
    )


def _cloud_fail_closed_evaluation(
    *,
    code: str,
    message: str,
    artifact: _eval.GuardArtifact,
    targets: tuple[dict[str, object], ...],
    workspace_dir: _eval.Path | None,
    workspace_fingerprint: str | None,
    bundle_meta: dict[str, str] | None,
    fail_closed_decision: str,
) -> _eval.PackageRequestEvaluation:
    reason = _eval._cloud_fallback_reason(code=code, message=message)
    decision = "block" if fail_closed_decision == "block" else "ask"
    severity = "critical" if decision == "block" else "high"
    packages = tuple(
        _eval._heuristic_package_result(
            target=target,
            decision=decision,
            code=code,
            message=message,
            severity=severity,
        )
        for target in targets
    )
    if not packages:
        packages = tuple(
            {
                **package,
                "decision": decision,
                "reasons": (reason,),
            }
            for package in _eval._fallback_package_results(
                targets=targets,
                artifact=artifact,
                workspace_dir=workspace_dir,
                fail_closed_unidentified=fail_closed_decision == "block",
            )
        )
    draft = _eval._EvaluationDraft(
        decision=decision,
        enforcement="premium_cloud",
        entitlement_state="premium",
        cache_status="cloud-error",
        packages=packages,
        reasons=(reason,),
        matched_rule_id=None,
        exception_id=None,
        refresh_required=False,
        record_monitor_evidence=False,
        bundle_version=bundle_meta.get("bundle_version") if bundle_meta is not None else None,
        policy_version=bundle_meta.get("policy_hash", "local:none") if bundle_meta is not None else "local:none",
    )
    evaluation = _eval._finalize_evaluation(
        draft,
        package_intent_hash=artifact.artifact_id.rsplit(":", 1)[-1],
        workspace_fingerprint=workspace_fingerprint,
    )
    if code == "cloud_auth_error":
        return _eval._with_cloud_auth_reconnect_copy(evaluation)
    return evaluation


def _with_cloud_auth_reconnect_copy(evaluation: _eval.PackageRequestEvaluation) -> _eval.PackageRequestEvaluation:
    reconnect_command = "hol-guard connect"
    reconnect_summary = "Guard Cloud needs a fresh sign-in before shared review can resume."
    summary = evaluation.user_copy.summary or ""
    if reconnect_summary.lower() not in summary.lower():
        summary = f"{summary} {reconnect_summary}".strip()
    reconnect_message = (
        "Guard kept this request local-only because Guard Cloud authorization expired. "
        f"Run `{reconnect_command}` to restore shared review and sync."
    )
    harness_message = evaluation.user_copy.harness_message or ""
    if reconnect_message.lower() not in harness_message.lower():
        harness_message = f"{harness_message} {reconnect_message}".strip()
    return _eval.replace(
        evaluation,
        user_copy=_eval._normalize_package_user_copy(
            _eval.SupplyChainUserCopy(
                title=evaluation.user_copy.title,
                summary=summary,
                next_step=evaluation.user_copy.next_step or reconnect_command,
                dashboard_url=evaluation.user_copy.dashboard_url,
                harness_message=harness_message,
            ),
            policy_action=evaluation.policy_action,
        ),
    )


def _cloud_fallback_requires_reconnect_copy(reason: dict[str, object]) -> bool:
    return _eval._optional_string(reason.get("code")) == "cloud_auth_error"


def _cloud_fail_closed_decision(
    *,
    store: _eval.GuardStore,
    workspace_dir: _eval.Path | None,
    config_reader: _eval.Callable[[_eval.Path], dict[str, object]] | None = None,
) -> str:
    config = _eval.load_guard_config(store.guard_home, workspace=workspace_dir, config_reader=config_reader)
    cloud_action = _eval.resolve_risk_action(config, "cloud_advisory", harness=None)
    if config.security_level in {"strict", "paranoid"}:
        return "block"
    if cloud_action == "block":
        return "block"
    return "ask"


def _unidentified_packages_fail_closed(
    *,
    store: _eval.GuardStore,
    workspace_dir: _eval.Path | None,
    config_reader: _eval.Callable[[_eval.Path], dict[str, object]] | None = None,
) -> bool:
    config = _eval.load_guard_config(store.guard_home, workspace=workspace_dir, config_reader=config_reader)
    return config.security_level in {"strict", "paranoid"}


def _unidentified_package_decision(
    ecosystem: str,
    *,
    fail_closed: bool,
    identity_resolved: bool = False,
) -> str:
    support_level = _eval.ecosystem_support_metadata(ecosystem)["support_level"]
    if support_level not in {"protected", "beta"}:
        return "monitor"
    if fail_closed:
        return "block"
    return "monitor" if identity_resolved else "ask"


# Resolve the facade after declarations so direct helper imports retain the cycle.
from . import supply_chain_package_eval as _eval  # noqa: E402
