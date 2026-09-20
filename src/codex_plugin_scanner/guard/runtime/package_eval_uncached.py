"""Uncached package evaluation through the live evaluator."""

from __future__ import annotations


def _evaluate_package_request_artifact_uncached(
    *,
    artifact: _eval.GuardArtifact,
    store: _eval.GuardStore,
    workspace_dir: _eval.Path | None,
    now: str | None = None,
    external_archive_network_authorized: bool = False,
    retain_external_archive_blob: bool = False,
    config_reader: _eval.Callable[[_eval.Path], dict[str, object]] | None = None,
) -> _eval.PackageRequestEvaluation:
    now_value = now or _eval.datetime.now(_eval.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    now_timestamp = _eval._parse_evaluation_timestamp(now_value)
    targets = _eval._evaluation_targets(artifact, workspace_dir)
    cloud_targets = _eval._cloud_evaluation_targets(artifact, workspace_dir)
    package_intent_hash = artifact.artifact_id.rsplit(":", 1)[-1]
    external_archive_targets = tuple(target for target in targets if _eval._target_is_external_https_archive(target))
    external_archive_source_hashes = tuple(
        _eval.stable_digest_hex(source_url.encode("utf-8"))
        for target in external_archive_targets
        if (source_url := _eval._optional_string(target.get("source_url"))) is not None
    )
    incomplete_lockfile = _eval._first_incomplete_lockfile_result(workspace_dir, artifact)
    if incomplete_lockfile is not None:
        return _eval._finalize_incomplete_lockfile_evaluation(
            artifact=artifact,
            store=store,
            target=targets[0] if targets else _eval.incomplete_lockfile_fallback_target(incomplete_lockfile),
            workspace_dir=workspace_dir,
            parse_result=incomplete_lockfile,
            package_intent_hash=package_intent_hash,
            now=now_value,
            config_reader=config_reader,
        )
    if external_archive_targets:
        # External archives use a deliberately local two-phase evaluation.  In
        # particular, neither cloud evaluation nor archive DNS may run before
        # the exact request has crossed the approval boundary.
        if len(external_archive_targets) > _eval._EXTERNAL_ARCHIVE_MAX_TARGETS:
            limit_package = _eval._heuristic_package_result(
                target=external_archive_targets[0],
                decision="block",
                code="external_archive_target_limit",
                message="External archive request exceeded Guard's per-command target limit.",
                severity="high",
            )
            external_archive_draft = _eval._EvaluationDraft(
                decision="block",
                enforcement="free_local",
                entitlement_state="free",
                cache_status="miss",
                packages=(limit_package,),
                reasons=tuple(_eval._dict_items(limit_package.get("reasons"))),
                matched_rule_id=None,
                exception_id=None,
                refresh_required=False,
                record_monitor_evidence=False,
                bundle_version=None,
                policy_version="local:none",
                external_archive_source_hashes=external_archive_source_hashes,
            )
        elif len(external_archive_targets) != len(targets):
            mixed_package = _eval._heuristic_package_result(
                target=external_archive_targets[0],
                decision="block",
                code="external_archive_mixed_request_unsupported",
                message=(
                    "External archives must be installed in a separate command so Guard can preserve "
                    "registry advisory evaluation and bind the inspected blob to execution."
                ),
                severity="high",
            )
            external_archive_draft = _eval._EvaluationDraft(
                decision="block",
                enforcement="free_local",
                entitlement_state="free",
                cache_status="miss",
                packages=(mixed_package,),
                reasons=tuple(_eval._dict_items(mixed_package.get("reasons"))),
                matched_rule_id=None,
                exception_id=None,
                refresh_required=False,
                record_monitor_evidence=False,
                bundle_version=None,
                policy_version="local:none",
                external_archive_source_hashes=external_archive_source_hashes,
            )
        else:
            external_archive_draft = _eval._heuristic_result(
                artifact=artifact,
                store=store,
                targets=targets,
                workspace_dir=workspace_dir,
                external_archive_network_authorized=external_archive_network_authorized,
                retain_external_archive_blob=retain_external_archive_blob,
                external_archive_request_deadline=(
                    _eval.time.monotonic() + _eval._EXTERNAL_ARCHIVE_REQUEST_TIMEOUT_SECONDS
                    if external_archive_network_authorized
                    else None
                ),
            )
        if external_archive_draft is None:
            external_archive_draft = _eval._EvaluationDraft(
                decision="block",
                enforcement="free_local",
                entitlement_state="free",
                cache_status="miss",
                packages=(),
                reasons=(
                    {
                        "code": "external_archive_inspection_incomplete",
                        "message": "Guard could not establish an external archive evaluation.",
                        "severity": "high",
                        "source": "guard-local",
                    },
                ),
                matched_rule_id=None,
                exception_id=None,
                refresh_required=False,
                record_monitor_evidence=False,
                bundle_version=None,
                policy_version="local:none",
                external_archive_source_hashes=external_archive_source_hashes,
            )
        if not external_archive_draft.external_archive_source_hashes:
            external_archive_draft = _eval.replace(
                external_archive_draft,
                external_archive_source_hashes=external_archive_source_hashes,
            )
        try:
            external_archive_result = _eval._finalize_evaluation(
                external_archive_draft,
                package_intent_hash=package_intent_hash,
                workspace_fingerprint=None,
            )
            _eval._persist_evidence(
                store=store,
                artifact=artifact,
                evaluation=external_archive_result,
                now=now_value,
            )
            return external_archive_result
        except BaseException:
            for download in external_archive_draft.external_archive_downloads:
                download.cleanup()
            raise
    source_review_targets = tuple(target for target in targets if _eval._target_requires_npm_source_review(target))
    if source_review_targets:
        if len(source_review_targets) != len(targets):
            mixed_source_package = _eval._heuristic_package_result(
                target=source_review_targets[0],
                decision="block",
                code="npm_source_mixed_request_unsupported",
                message=(
                    "npm source dependencies must be installed separately so Guard can preserve registry "
                    "advisory evaluation and source approval identity."
                ),
                severity="high",
            )
            source_review_draft = _eval._EvaluationDraft(
                decision="block",
                enforcement="free_local",
                entitlement_state="free",
                cache_status="miss",
                packages=(mixed_source_package,),
                reasons=tuple(_eval._dict_items(mixed_source_package.get("reasons"))),
                matched_rule_id=None,
                exception_id=None,
                refresh_required=False,
                record_monitor_evidence=False,
                bundle_version=None,
                policy_version="local:none",
            )
        else:
            source_review_draft = _eval._heuristic_result(
                artifact=artifact,
                store=store,
                targets=targets,
                workspace_dir=workspace_dir,
                external_archive_network_authorized=False,
                retain_external_archive_blob=False,
            )
        if source_review_draft is None:
            raise AssertionError("npm source review target did not produce a local decision")
        source_review_result = _eval._finalize_evaluation(
            source_review_draft,
            package_intent_hash=package_intent_hash,
            workspace_fingerprint=None,
        )
        _eval._persist_evidence(
            store=store,
            artifact=artifact,
            evaluation=source_review_result,
            now=now_value,
        )
        return source_review_result
    workspace_id = store.get_cloud_workspace_id()
    bundle_payload = store.get_cached_supply_chain_bundle(workspace_id) if workspace_id is not None else None
    bundle_response: _eval.SupplyChainBundleResponse | None = None
    bundle_meta: dict[str, str] | None = None
    if isinstance(bundle_payload, dict):
        try:
            bundle_response = _eval.load_supply_chain_bundle_response(bundle_payload)
            bundle_meta = _eval._bundle_meta(bundle_payload)
        except (AssertionError, KeyError, _eval.SupplyChainBundleMalformedError, TypeError, ValueError):
            bundle_response = None
            bundle_meta = None
    workspace_fingerprint = (
        _eval._workspace_fingerprint(
            workspace_id, workspace_dir=workspace_dir, artifact=artifact, bundle_meta=bundle_meta
        )
        if workspace_id is not None
        else None
    )
    if workspace_id is not None and bundle_meta is not None:
        cached = store.get_cached_supply_chain_evaluation(
            workspace_id=workspace_id,
            package_intent_hash=package_intent_hash,
            feed_snapshot_hash=bundle_meta["feed_snapshot_hash"],
            policy_hash=bundle_meta["policy_hash"],
            scoring_version=bundle_meta["scoring_version"],
            bundle_version=bundle_meta["bundle_version"],
        )
        if isinstance(cached, dict):
            cached_workspace_fingerprint = _eval._optional_string(cached.get("workspace_fingerprint"))
            if cached_workspace_fingerprint == workspace_fingerprint and _eval._cached_supply_chain_eval_is_reusable(
                cached,
                now_timestamp=now_timestamp,
            ):
                cached_result = _eval.PackageRequestEvaluation.from_cache_dict(
                    cached,
                    package_intent_hash=package_intent_hash,
                    policy_version=bundle_meta["policy_hash"],
                    bundle_version=bundle_meta["bundle_version"],
                    workspace_fingerprint=workspace_fingerprint,
                )
                if not _eval._cached_cloud_validation_error_requires_uncached_retry(
                    cached,
                    store=store,
                    artifact=artifact,
                    evaluation=cached_result,
                    workspace_dir=workspace_dir,
                    now=now_value,
                ):
                    _eval._persist_evidence(store=store, artifact=artifact, evaluation=cached_result, now=now_value)
                    return cached_result
    bundle_evaluation = (
        _eval._evaluate_with_bundle(
            artifact=artifact,
            targets=targets,
            bundle_response=bundle_response,
            workspace_dir=workspace_dir,
            workspace_id=workspace_id,
            now_timestamp=now_timestamp,
        )
        if bundle_response is not None
        else None
    )
    if not _eval._artifact_has_package_material(artifact, targets):
        no_material_result = _eval._empty_package_material_result(
            artifact=artifact,
            workspace_id=workspace_id,
            bundle_meta=bundle_meta,
            package_intent_hash=package_intent_hash,
            workspace_fingerprint=workspace_fingerprint,
        )
        _eval._persist_evidence(store=store, artifact=artifact, evaluation=no_material_result, now=now_value)
        return no_material_result
    bundle_defer_eligible = bundle_evaluation is not None and (
        bundle_evaluation.decision == "block" or not bundle_evaluation.refresh_required
    )
    cloud_result, cloud_fallback_reason = _eval._evaluate_with_cloud(
        artifact=artifact,
        targets=cloud_targets,
        workspace_dir=workspace_dir,
        workspace_id=workspace_id,
        workspace_fingerprint=workspace_fingerprint,
        bundle_meta=bundle_meta,
        bundle_defer_eligible=bundle_defer_eligible,
        bundle_decision=bundle_evaluation.decision if bundle_evaluation is not None else None,
        store=store,
        config_reader=config_reader,
    )
    if cloud_result is not None and _eval._cloud_result_should_defer_to_bundle(
        cloud_result, bundle_evaluation=bundle_evaluation
    ):
        if cloud_fallback_reason is None and cloud_result.reasons:
            first_reason = cloud_result.reasons[0]
            if isinstance(first_reason, dict):
                cloud_fallback_reason = dict(first_reason)
        cloud_result = None
    if cloud_result is not None:
        upgraded = cloud_result
        if cloud_result.enforcement == "upgrade_required":
            heuristic = _eval._heuristic_result(
                artifact=artifact,
                store=store,
                targets=targets,
                workspace_dir=workspace_dir,
                external_archive_network_authorized=external_archive_network_authorized,
                retain_external_archive_blob=retain_external_archive_blob,
            )
            if heuristic is not None and _eval._decision_rank(heuristic.decision) > _eval._decision_rank(
                cloud_result.decision
            ):
                upgraded = _eval._finalize_evaluation(
                    _eval._EvaluationDraft(
                        decision=heuristic.decision,
                        enforcement="free_local",
                        entitlement_state="free",
                        cache_status="upgrade-gated",
                        packages=heuristic.packages,
                        reasons=heuristic.reasons,
                        matched_rule_id=heuristic.matched_rule_id,
                        exception_id=heuristic.exception_id,
                        refresh_required=False,
                        record_monitor_evidence=heuristic.record_monitor_evidence,
                        bundle_version=None,
                        policy_version=bundle_meta["policy_hash"] if bundle_meta is not None else "local:none",
                    ),
                    package_intent_hash=package_intent_hash,
                    workspace_fingerprint=workspace_fingerprint,
                )
        _eval._cache_reusable_cloud_validation_error(
            store=store,
            workspace_id=workspace_id,
            bundle_meta=bundle_meta,
            package_intent_hash=package_intent_hash,
            evaluation=upgraded,
            now=now_value,
        )
        _eval._persist_evidence(store=store, artifact=artifact, evaluation=upgraded, now=now_value)
        return upgraded
    if (
        bundle_evaluation is not None
        and bundle_evaluation.refresh_required
        and not bool(store.get_oauth_local_credential_health().get("configured"))
    ):
        fallback = _eval._finalize_evaluation(
            bundle_evaluation,
            package_intent_hash=package_intent_hash,
            workspace_fingerprint=workspace_fingerprint,
        )
        _eval._persist_evidence(store=store, artifact=artifact, evaluation=fallback, now=now_value)
        store.add_event(
            "supply_chain_bundle_refresh_requested",
            {
                "artifact_id": artifact.artifact_id,
                "artifact_name": artifact.name,
                "reason": "feed_stale",
            },
            now_value,
        )
        return fallback
    if bundle_evaluation is not None:
        fallback = _eval._finalize_evaluation(
            bundle_evaluation, package_intent_hash=package_intent_hash, workspace_fingerprint=workspace_fingerprint
        )
        if cloud_fallback_reason is not None:
            fallback = _eval._with_additional_reason(fallback, cloud_fallback_reason)
            if _eval._cloud_fallback_requires_reconnect_copy(cloud_fallback_reason):
                fallback = _eval._with_cloud_auth_reconnect_copy(fallback)
        if (
            bundle_meta is not None
            and bundle_evaluation.decision != "monitor"
            and fallback.cache_status != "cloud-error"
            and isinstance(bundle_payload, dict)
        ):
            cache_workspace_id = workspace_id
            if cache_workspace_id is None:
                bundle_section = bundle_payload.get("bundle")
                if isinstance(bundle_section, dict):
                    bundle_workspace_id = bundle_section.get("workspaceId")
                    if isinstance(bundle_workspace_id, str) and bundle_workspace_id:
                        cache_workspace_id = bundle_workspace_id
            if cache_workspace_id:
                store.cache_supply_chain_evaluation(
                    workspace_id=cache_workspace_id,
                    package_intent_hash=package_intent_hash,
                    feed_snapshot_hash=bundle_meta["feed_snapshot_hash"],
                    policy_hash=bundle_meta["policy_hash"],
                    scoring_version=bundle_meta["scoring_version"],
                    bundle_version=bundle_meta["bundle_version"],
                    decision=fallback.to_cache_dict(),
                    now=now_value,
                )
        _eval._persist_evidence(store=store, artifact=artifact, evaluation=fallback, now=now_value)
        if fallback.refresh_required:
            store.add_event(
                "supply_chain_bundle_refresh_requested",
                {
                    "artifact_id": artifact.artifact_id,
                    "artifact_name": artifact.name,
                    "reason": "feed_stale",
                },
                now_value,
            )
        return fallback
    heuristic = _eval._heuristic_result(
        artifact=artifact,
        store=store,
        targets=targets,
        workspace_dir=workspace_dir,
        external_archive_network_authorized=external_archive_network_authorized,
        retain_external_archive_blob=retain_external_archive_blob,
    )
    if heuristic is None:
        fail_closed_unidentified = _eval._unidentified_packages_fail_closed(
            store=store, workspace_dir=workspace_dir, config_reader=config_reader
        )
        fallback_packages = _eval._fallback_package_results(
            targets=targets,
            artifact=artifact,
            workspace_dir=workspace_dir,
            fail_closed_unidentified=fail_closed_unidentified,
            verify_registry_identity=(
                cloud_fallback_reason is not None
                and _eval._optional_string(cloud_fallback_reason.get("code")) == "cloud_auth_error"
            ),
        )
        fallback_decision = max(
            (str(package.get("decision") or "monitor") for package in fallback_packages),
            key=_eval._decision_rank,
            default="monitor",
        )
        fallback_reasons = tuple(
            reason for package in fallback_packages for reason in _eval._dict_items(package.get("reasons"))
        )
        heuristic = _eval._EvaluationDraft(
            decision=fallback_decision,
            enforcement="free_local" if workspace_id is None else "local_fallback",
            entitlement_state="free" if workspace_id is None else "premium",
            cache_status="miss",
            packages=fallback_packages,
            reasons=fallback_reasons,
            matched_rule_id=None,
            exception_id=None,
            refresh_required=False,
            record_monitor_evidence=fallback_decision == "monitor",
            bundle_version=None,
            policy_version=bundle_meta["policy_hash"] if bundle_meta is not None else "local:none",
        )
    result = _eval._finalize_evaluation(
        heuristic, package_intent_hash=package_intent_hash, workspace_fingerprint=workspace_fingerprint
    )
    if cloud_fallback_reason is not None:
        result = _eval._with_additional_reason(result, cloud_fallback_reason)
        if _eval._cloud_fallback_requires_reconnect_copy(cloud_fallback_reason):
            result = _eval._with_cloud_auth_reconnect_copy(result)
    _eval._persist_evidence(store=store, artifact=artifact, evaluation=result, now=now_value)
    return result


# Resolve the facade after declarations so direct helper imports retain the cycle.
from . import supply_chain_package_eval as _eval  # noqa: E402
