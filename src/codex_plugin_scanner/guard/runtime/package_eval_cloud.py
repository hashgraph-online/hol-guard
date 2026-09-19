"""Cloud package evaluation and current authority callbacks."""

from __future__ import annotations


def _evaluate_with_cloud(
    *,
    artifact: _eval.GuardArtifact,
    targets: tuple[dict[str, object], ...],
    workspace_dir: _eval.Path | None,
    workspace_id: str | None,
    workspace_fingerprint: str | None,
    bundle_meta: dict[str, str] | None,
    bundle_defer_eligible: bool,
    bundle_decision: str | None,
    store: _eval.GuardStore,
    config_reader: _eval.Callable[[_eval.Path], dict[str, object]] | None = None,
) -> tuple[_eval.PackageRequestEvaluation | None, dict[str, object] | None]:
    if not targets or workspace_id is None or workspace_fingerprint is None:
        return None, None
    fail_closed_decision: str | None = None

    def resolve_fail_closed_decision() -> str:
        nonlocal fail_closed_decision
        if fail_closed_decision is None:
            fail_closed_decision = _eval._cloud_fail_closed_decision(
                store=store, workspace_dir=workspace_dir, config_reader=config_reader
            )
        result: str = fail_closed_decision
        return result

    cloud_entitlement: dict[str, object] | None = None

    def resolve_cloud_entitlement() -> dict[str, object]:
        nonlocal cloud_entitlement
        if cloud_entitlement is None:
            try:
                cloud_entitlement = _eval.resolve_package_firewall_entitlement(store)
            except Exception:
                # Never turn entitlement uncertainty into permission to bypass
                # Cloud package protection. Unknown state is protected state.
                cloud_entitlement = {
                    "allowed": False,
                    "reason": "guard_cloud_connect_required",
                    "tier": "unknown",
                }
        return cloud_entitlement

    def cloud_protection_is_explicitly_unpaid() -> bool:
        entitlement = resolve_cloud_entitlement()
        return str(entitlement.get("reason") or "").strip().lower() == "paid_guard_cloud_required"

    def can_fallback_from_cloud_failure() -> bool:
        # A signed cached Cloud block is safe to honor because it cannot weaken
        # enforcement even if the live Cloud request is unavailable.
        if bundle_meta is not None and bundle_defer_eligible and bundle_decision == "block":
            return True
        # Local fallback is otherwise allowed only when entitlement explicitly
        # proves the account is unpaid. Paid, expired, reconnect-required, and
        # unknown/unproven states all fail closed. Strict local policy remains
        # authoritative even for an explicitly unpaid account.
        return cloud_protection_is_explicitly_unpaid() and resolve_fail_closed_decision() != "block"

    def resolve_cloud_failure_decision() -> str:
        if cloud_protection_is_explicitly_unpaid():
            return resolve_fail_closed_decision()
        return "block"

    def handle_cloud_os_error(
        error: OSError,
    ) -> tuple[_eval.PackageRequestEvaluation | None, dict[str, object] | None]:
        if _eval._is_timeout_error(error):
            if resolve_cloud_failure_decision() == "block":
                return (
                    _eval._cloud_fail_closed_evaluation(
                        code="cloud_timeout",
                        message=(
                            "Guard Cloud evaluation timed out, so this package request is paused for explicit review."
                        ),
                        artifact=artifact,
                        targets=targets,
                        workspace_dir=workspace_dir,
                        workspace_fingerprint=workspace_fingerprint,
                        bundle_meta=bundle_meta,
                        # A timeout is a transient availability failure, not a
                        # package verdict. Keep the install stopped, but put it
                        # in the approval queue so a human can decide remotely.
                        fail_closed_decision="ask",
                    ),
                    None,
                )
            return None, _eval._cloud_fallback_reason(
                code="cloud_timeout",
                message="Guard cloud evaluation timed out, so Guard fell back to local intelligence.",
            )

        fail_closed_decision = resolve_cloud_failure_decision()
        if fail_closed_decision == "block":
            return (
                _eval._cloud_fail_closed_evaluation(
                    code="cloud_http_error",
                    message=(
                        "Guard Cloud evaluation could not be reached, so Guard blocked the install "
                        "rather than bypassing Cloud package protection."
                    ),
                    artifact=artifact,
                    targets=targets,
                    workspace_dir=workspace_dir,
                    workspace_fingerprint=workspace_fingerprint,
                    bundle_meta=bundle_meta,
                    fail_closed_decision=fail_closed_decision,
                ),
                None,
            )
        return None, _eval._cloud_fallback_reason(
            code="cloud_http_error",
            message="Guard Cloud evaluation could not be reached, so Guard used local package intelligence.",
        )

    try:
        auth_context = _eval._resolve_guard_sync_auth_context(store, allow_primary_repair=False)
    except _eval.GuardSyncAuthorizationExpiredError:
        if can_fallback_from_cloud_failure():
            return None, _eval._cloud_fallback_reason(
                code="cloud_auth_error",
                message="Guard cloud evaluation was not authorized, so Guard used local package intelligence.",
            )
        return (
            _eval._cloud_fail_closed_evaluation(
                code="cloud_auth_error",
                message="Guard cloud evaluation was not authorized, so this package request needs review.",
                artifact=artifact,
                targets=targets,
                workspace_dir=workspace_dir,
                workspace_fingerprint=workspace_fingerprint,
                bundle_meta=bundle_meta,
                fail_closed_decision=resolve_cloud_failure_decision(),
            ),
            None,
        )
    except _eval.GuardSyncEndpointUntrustedError:
        return (
            _eval._cloud_fail_closed_evaluation(
                code="cloud_validation_error",
                message="Guard cloud evaluation endpoint was not trusted, so this package request needs review.",
                artifact=artifact,
                targets=targets,
                workspace_dir=workspace_dir,
                workspace_fingerprint=workspace_fingerprint,
                bundle_meta=bundle_meta,
                fail_closed_decision=resolve_cloud_failure_decision(),
            ),
            None,
        )
    except _eval.GuardSyncNotConfiguredError:
        credentials_configured = bool(store.get_oauth_local_credential_health().get("configured"))
        if can_fallback_from_cloud_failure():
            if credentials_configured:
                return None, _eval._cloud_fallback_reason(
                    code="cloud_auth_error",
                    message="Guard Cloud credentials were unavailable, so Guard used local package intelligence.",
                )
            return None, None
        return (
            _eval._cloud_fail_closed_evaluation(
                code="cloud_auth_error",
                message=(
                    "Guard Cloud credentials were unavailable. Guard blocked this package request "
                    "rather than bypassing Cloud package protection."
                ),
                artifact=artifact,
                targets=targets,
                workspace_dir=workspace_dir,
                workspace_fingerprint=workspace_fingerprint,
                bundle_meta=bundle_meta,
                fail_closed_decision=resolve_cloud_failure_decision(),
            ),
            None,
        )
    except RuntimeError:
        return (
            _eval._cloud_fail_closed_evaluation(
                code="cloud_auth_error",
                message=(
                    "Guard cloud evaluation could not establish a trusted session, "
                    "so this package request needs review."
                ),
                artifact=artifact,
                targets=targets,
                workspace_dir=workspace_dir,
                workspace_fingerprint=workspace_fingerprint,
                bundle_meta=bundle_meta,
                # A trusted-session failure (typically a cloud token refresh
                # error) is availability, not a package verdict, so it gets the
                # same treatment as cloud timeouts: the install stays stopped,
                # but every security level routes the request to the approval
                # queue so a human can decide remotely.
                fail_closed_decision="ask",
            ),
            None,
        )
    sync_url = _eval._optional_string(auth_context.get("sync_url"))
    if sync_url is None:
        return (
            _eval._cloud_fail_closed_evaluation(
                code="cloud_validation_error",
                message="Guard cloud evaluation session was invalid, so this package request needs review.",
                artifact=artifact,
                targets=targets,
                workspace_dir=workspace_dir,
                workspace_fingerprint=workspace_fingerprint,
                bundle_meta=bundle_meta,
                fail_closed_decision=resolve_cloud_failure_decision(),
            ),
            None,
        )
    try:
        sync_url = _eval._validate_guard_sync_url(sync_url, issuer=_eval._optional_string(auth_context.get("issuer")))
    except _eval.GuardSyncNotConfiguredError:
        return (
            _eval._cloud_fail_closed_evaluation(
                code="cloud_validation_error",
                message="Guard cloud evaluation endpoint was not trusted, so this package request needs review.",
                artifact=artifact,
                targets=targets,
                workspace_dir=workspace_dir,
                workspace_fingerprint=workspace_fingerprint,
                bundle_meta=bundle_meta,
                fail_closed_decision=resolve_cloud_failure_decision(),
            ),
            None,
        )
    evaluate_url = _eval._normalized_supply_chain_evaluate_url(sync_url, workspace_id)
    request_payload = _eval._build_request_payload(
        artifact=artifact,
        targets=targets,
        workspace_dir=workspace_dir,
        workspace_fingerprint=workspace_fingerprint,
        policy_version=bundle_meta["policy_hash"] if bundle_meta is not None else "local:none",
    )
    request_data = _eval.json.dumps(request_payload).encode("utf-8")

    def evaluation_request(context: dict[str, object]) -> _eval.urllib.request.Request:
        return _eval._guard_sync_request(
            context,
            request_url=evaluate_url,
            method="POST",
            data=request_data,
        )

    request = evaluation_request(auth_context)
    response_payload: object | None = None
    try:
        response_payload = _eval._urlopen_json_with_timeout_retry(
            request=request,
            timeout_seconds=_eval._TIMEOUT_SECONDS,
            retry_timeout_seconds=_eval._RETRY_TIMEOUT_SECONDS,
        )
    except _eval.urllib.error.HTTPError as error:
        status_code: int | None = error.code
        if status_code == 401:
            try:
                refreshed_auth_context = _eval._resolve_guard_sync_auth_context(
                    store,
                    allow_primary_repair=False,
                    force_refresh=True,
                )
                response_payload = _eval._urlopen_json_with_timeout_retry(
                    request=evaluation_request(refreshed_auth_context),
                    timeout_seconds=_eval._TIMEOUT_SECONDS,
                    retry_timeout_seconds=_eval._RETRY_TIMEOUT_SECONDS,
                )
            except (_eval.GuardSyncAuthorizationExpiredError, _eval.GuardSyncNotConfiguredError, RuntimeError):
                response_payload = None
            except _eval.urllib.error.HTTPError as refreshed_error:
                status_code = refreshed_error.code
            except OSError as error:
                return handle_cloud_os_error(error)
            except ValueError:
                return (
                    _eval._cloud_fail_closed_evaluation(
                        code="cloud_validation_error",
                        message=(
                            "Guard cloud evaluation returned an invalid response, so this package request needs review."
                        ),
                        artifact=artifact,
                        targets=targets,
                        workspace_dir=workspace_dir,
                        workspace_fingerprint=workspace_fingerprint,
                        bundle_meta=bundle_meta,
                        fail_closed_decision=resolve_cloud_failure_decision(),
                    ),
                    None,
                )
            else:
                status_code = None
        if status_code is not None:
            fail_closed = _eval._cloud_http_fail_closed_evaluation(
                status_code=status_code,
                artifact=artifact,
                targets=targets,
                workspace_dir=workspace_dir,
                workspace_fingerprint=workspace_fingerprint,
                bundle_meta=bundle_meta,
                fail_closed_decision=resolve_cloud_failure_decision(),
            )
            if fail_closed is not None:
                return fail_closed, None
            if status_code == 401:
                return None, _eval._cloud_fallback_reason(
                    code="cloud_auth_error",
                    message="Guard cloud evaluation was not authorized, so Guard used local package intelligence.",
                )
            return None, _eval._cloud_fallback_reason(
                code="cloud_validation_error" if status_code in {400, 404} else "cloud_http_error",
                message=(
                    f"Guard cloud evaluation returned HTTP {status_code}, so Guard fell back to local intelligence."
                ),
            )
    except OSError as error:
        return handle_cloud_os_error(error)
    except (RuntimeError, ValueError):
        return (
            _eval._cloud_fail_closed_evaluation(
                code="cloud_validation_error",
                message="Guard cloud evaluation returned an invalid response, so this package request needs review.",
                artifact=artifact,
                targets=targets,
                workspace_dir=workspace_dir,
                workspace_fingerprint=workspace_fingerprint,
                bundle_meta=bundle_meta,
                fail_closed_decision=resolve_cloud_failure_decision(),
            ),
            None,
        )
    if not isinstance(response_payload, dict):
        return (
            _eval._cloud_fail_closed_evaluation(
                code="cloud_validation_error",
                message="Guard cloud evaluation returned an invalid response, so this package request needs review.",
                artifact=artifact,
                targets=targets,
                workspace_dir=workspace_dir,
                workspace_fingerprint=workspace_fingerprint,
                bundle_meta=bundle_meta,
                fail_closed_decision=resolve_cloud_failure_decision(),
            ),
            None,
        )
    if not isinstance(response_payload.get("packages"), list):
        return (
            _eval._cloud_fail_closed_evaluation(
                code="cloud_validation_error",
                message=(
                    "Guard cloud evaluation returned an invalid package payload, so this package request needs review."
                ),
                artifact=artifact,
                targets=targets,
                workspace_dir=workspace_dir,
                workspace_fingerprint=workspace_fingerprint,
                bundle_meta=bundle_meta,
                fail_closed_decision=resolve_cloud_failure_decision(),
            ),
            None,
        )
    packages = tuple(
        _eval._package_from_cloud_result(item) for item in _eval._dict_items(response_payload.get("packages"))
    )
    reasons = _eval._dict_items(response_payload.get("reasons"))
    normalized_decision = _eval._normalize_bundle_action(str(response_payload.get("decision") or "monitor"))
    draft = _eval._EvaluationDraft(
        decision=normalized_decision,
        enforcement=str(response_payload.get("enforcement") or "premium_cloud"),
        entitlement_state=str(response_payload.get("entitlementState") or "premium"),
        cache_status=str(response_payload.get("cacheStatus") or "miss"),
        packages=packages,
        reasons=reasons,
        matched_rule_id=None,
        exception_id=None,
        refresh_required=False,
        record_monitor_evidence=normalized_decision == "monitor",
        bundle_version=bundle_meta["bundle_version"] if bundle_meta is not None else None,
        policy_version=str(
            response_payload.get("policyVersion")
            or (bundle_meta["policy_hash"] if bundle_meta is not None else "local:none")
        ),
    )
    evaluation = _eval._finalize_evaluation(
        draft,
        package_intent_hash=artifact.artifact_id.rsplit(":", 1)[-1],
        workspace_fingerprint=workspace_fingerprint,
    )
    copy_payload = response_payload.get("copy")
    if isinstance(copy_payload, dict):
        title = _eval._optional_string(copy_payload.get("title"))
        summary = _eval._optional_string(copy_payload.get("summary"))
        if title is not None or summary is not None:
            updated_summary = summary or evaluation.user_copy.summary
            harness_parts = [evaluation.risk_summary, updated_summary]
            if evaluation.user_copy.next_step:
                harness_parts.append(f"Fix: run `{evaluation.user_copy.next_step}`.")
            evaluation = _eval.replace(
                evaluation,
                user_copy=_eval._normalize_package_user_copy(
                    _eval.SupplyChainUserCopy(
                        title=title or evaluation.user_copy.title,
                        summary=updated_summary,
                        next_step=evaluation.user_copy.next_step,
                        dashboard_url=evaluation.user_copy.dashboard_url,
                        harness_message=" ".join(harness_parts),
                    ),
                    policy_action=evaluation.policy_action,
                ),
            )
    return evaluation, None


# Resolve the facade after declarations so direct helper imports retain the cycle.
from . import supply_chain_package_eval as _eval  # noqa: E402
