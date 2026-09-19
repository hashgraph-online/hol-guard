"""Package evaluation dispatch and cache admission through the live evaluator."""

from __future__ import annotations


def evaluate_package_request_artifact(
    *,
    artifact: _eval.GuardArtifact,
    store: _eval.GuardStore,
    workspace_dir: _eval.Path | None,
    now: str | None = None,
    external_archive_network_authorized: bool = False,
    retain_external_archive_blob: bool = False,
    config_reader: _eval.Callable[[_eval.Path], dict[str, object]] | None = None,
) -> _eval.PackageRequestEvaluation:
    cache_token = _eval._LOCKFILE_PARSE_CACHE.set({})
    try:
        with _eval.workspace_input_snapshot():
            try:
                return _eval._evaluate_package_request_artifact_uncached(
                    artifact=artifact,
                    store=store,
                    workspace_dir=workspace_dir,
                    now=now,
                    external_archive_network_authorized=external_archive_network_authorized,
                    retain_external_archive_blob=retain_external_archive_blob,
                    config_reader=config_reader,
                )
            except _eval.WorkspaceInputSnapshotError as error:
                parse_result = _eval.incomplete_lockfile_result(
                    error.relative_path,
                    b"",
                    error_reason=error.reason,
                    budget_ms=_eval._LOCKFILE_PARSE_MAX_BUDGET_SECONDS * 1000,
                    source_hash=error.source_hash,
                    source_hash_complete=error.source_hash is not None,
                    source_byte_count=error.bytes_observed,
                    source_byte_limit=error.byte_limit,
                )
                targets = _eval._targets_from_artifact(artifact)
                return _eval._finalize_incomplete_lockfile_evaluation(
                    artifact=artifact,
                    store=store,
                    target=targets[0] if targets else _eval.incomplete_lockfile_fallback_target(parse_result),
                    workspace_dir=workspace_dir,
                    parse_result=parse_result,
                    package_intent_hash=artifact.artifact_id.rsplit(":", 1)[-1],
                    now=now
                    or _eval.datetime.now(_eval.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
                    config_reader=config_reader,
                )
    finally:
        _eval._LOCKFILE_PARSE_CACHE.reset(cache_token)


def _artifact_has_package_material(artifact: _eval.GuardArtifact, targets: tuple[dict[str, object], ...]) -> bool:
    if targets:
        return True
    return _eval._has_non_empty_string_item(
        artifact.metadata.get("manifest_paths")
    ) or _eval._has_non_empty_string_item(artifact.metadata.get("lockfile_paths"))


def _has_non_empty_string_item(value: object) -> bool:
    if not isinstance(value, (list, tuple)):
        return False
    return any(isinstance(item, str) and item for item in value)


def _empty_package_material_result(
    *,
    artifact: _eval.GuardArtifact,
    workspace_id: str | None,
    bundle_meta: dict[str, str] | None,
    package_intent_hash: str,
    workspace_fingerprint: str | None,
) -> _eval.PackageRequestEvaluation:
    draft = _eval._EvaluationDraft(
        decision="monitor",
        enforcement="free_local" if workspace_id is None else "local_fallback",
        entitlement_state="free" if workspace_id is None else "premium",
        cache_status="empty",
        packages=(),
        reasons=(
            {
                "code": "no_package_material",
                "message": "Guard found no package targets, manifests, or lockfiles to evaluate for this request.",
                "severity": "unknown",
                "source": "guard-local",
            },
        ),
        matched_rule_id=None,
        exception_id=None,
        refresh_required=False,
        record_monitor_evidence=False,
        bundle_version=bundle_meta.get("bundle_version") if bundle_meta is not None else None,
        policy_version=bundle_meta.get("policy_hash", "local:none") if bundle_meta is not None else "local:none",
    )
    return _eval._finalize_evaluation(
        draft,
        package_intent_hash=package_intent_hash,
        workspace_fingerprint=workspace_fingerprint,
    )


def _cached_supply_chain_eval_is_reusable(
    cached: dict[str, object],
    *,
    now_timestamp: float | None,
) -> bool:
    if not _eval._cached_eval_has_reason_code(cached, "cloud_validation_error"):
        return True
    if now_timestamp is None:
        return False
    updated_at = _eval._optional_string(cached.get("updated_at"))
    if updated_at is None:
        return False
    try:
        cached_at = _eval._parse_evaluation_timestamp(updated_at)
    except ValueError:
        return False
    if cached_at is None:
        return False
    return (now_timestamp - cached_at) <= _eval._CLOUD_VALIDATION_ERROR_CACHE_TTL_SECONDS


def _cached_eval_has_reason_code(cached: dict[str, object], code: str) -> bool:
    return any(
        isinstance(reason, dict) and str(reason.get("code") or "") == code
        for reason in _eval._dict_items(cached.get("reasons"))
    )


def _cache_reusable_cloud_validation_error(
    *,
    store: _eval.GuardStore,
    workspace_id: str | None,
    bundle_meta: dict[str, str] | None,
    package_intent_hash: str,
    evaluation: _eval.PackageRequestEvaluation,
    now: str,
) -> None:
    if (
        workspace_id is None
        or bundle_meta is None
        or not _eval._evaluation_has_reason_code(evaluation, "cloud_validation_error")
    ):
        return
    store.cache_supply_chain_evaluation(
        workspace_id=workspace_id,
        package_intent_hash=package_intent_hash,
        feed_snapshot_hash=bundle_meta["feed_snapshot_hash"],
        policy_hash=bundle_meta["policy_hash"],
        scoring_version=bundle_meta["scoring_version"],
        bundle_version=bundle_meta["bundle_version"],
        decision=evaluation.to_cache_dict(),
        now=now,
    )


def _cached_cloud_validation_error_requires_uncached_retry(
    cached: dict[str, object],
    *,
    store: _eval.GuardStore,
    artifact: _eval.GuardArtifact,
    evaluation: _eval.PackageRequestEvaluation,
    workspace_dir: _eval.Path | None,
    now: str,
) -> bool:
    if not _eval._cached_eval_has_reason_code(cached, "cloud_validation_error"):
        return False
    return not _eval._cached_cloud_validation_error_has_saved_policy(
        store=store,
        artifact=artifact,
        evaluation=evaluation,
        workspace_dir=workspace_dir,
        now=now,
    )


def _cached_cloud_validation_error_has_saved_policy(
    *,
    store: _eval.GuardStore,
    artifact: _eval.GuardArtifact,
    evaluation: _eval.PackageRequestEvaluation,
    workspace_dir: _eval.Path | None,
    now: str,
) -> bool:
    if workspace_dir is None:
        return False
    try:
        from ..local_supply_chain import (  # local import avoids the runtime/local helper cycle
            _stored_package_policy_is_stale_policy_bundle_family,
            package_request_policy_hash,
        )

        artifact_hash = package_request_policy_hash(
            artifact=artifact,
            store=store,
            workspace_dir=workspace_dir,
            evaluation=evaluation,
        )
    except (ImportError, TypeError, ValueError, OSError):
        return False
    lookup = store.resolve_policy_decision_lookup(
        artifact.harness,
        artifact.artifact_id,
        artifact_hash,
        str(workspace_dir),
        artifact.publisher,
        now,
        consume_one_shot=False,
    )
    decision = lookup["decision"]
    if not isinstance(decision, dict):
        return False
    if _stored_package_policy_is_stale_policy_bundle_family(decision, store=store):
        return False
    # This cache-error probe does not have the current Guard/sandbox context,
    # so it cannot establish exact v1 approval reuse. A stored block remains a
    # conservative reason to keep the cached block; an allow must proceed to a
    # full uncached evaluation and the normal current-context launch gate.
    return decision.get("action") == "block"


def _evaluation_has_reason_code(evaluation: _eval.PackageRequestEvaluation, code: str) -> bool:
    return any(isinstance(reason, dict) and str(reason.get("code") or "") == code for reason in evaluation.reasons)


# Resolve the facade after declarations so direct helper imports retain the cycle.
from . import supply_chain_package_eval as _eval  # noqa: E402
