"""Lockfile parse status and incomplete-result policy."""

from __future__ import annotations


def _lockfile_parse_results(
    workspace_dir: _eval.Path | None,
    artifact: _eval.GuardArtifact,
) -> tuple[_eval.LockfileParseResult, ...]:
    return _eval.collect_lockfile_parse_results(
        workspace_dir,
        artifact.metadata.get("lockfile_paths"),
        budget_ms=_eval._LOCKFILE_PARSE_BUDGET_SECONDS * 1000,
        parse_text_result=_eval._parse_lockfile_text_result,
    )


def _parse_lockfile_text_result(path: str, source: str | bytes) -> _eval.LockfileParseResult:
    cache = _eval._LOCKFILE_PARSE_CACHE.get()
    try:
        source_bytes = source if isinstance(source, bytes) else source.encode("utf-8")
    except MemoryError:
        return _eval.incomplete_lockfile_result(
            path,
            b"",
            error_reason="resource_limit_exceeded",
            budget_ms=_eval._LOCKFILE_PARSE_BUDGET_SECONDS * 1000,
        )
    cache_key = (path.casefold(), source_bytes)
    if cache is not None and (cached := cache.get(cache_key)) is not None:
        return cached
    result = _eval.parse_lockfile_with_budget(
        path,
        source_bytes,
        budget_seconds=_eval._lockfile_parse_budget_seconds(len(source_bytes)),
        dependency_parser=_eval._dependency_map_for_path,
        package_lock_parser=_eval._package_lock_entries,
    )
    if cache is not None and result.complete:
        cache[cache_key] = result
    return result


def _lockfile_parse_budget_seconds(byte_count: int) -> float:
    source_mib = byte_count / (1024 * 1024)
    return min(
        _eval._LOCKFILE_PARSE_MAX_BUDGET_SECONDS,
        _eval._LOCKFILE_PARSE_BUDGET_SECONDS + (_eval._LOCKFILE_PARSE_BUDGET_PER_MIB_SECONDS * source_mib),
    )


def _first_incomplete_lockfile_result(
    workspace_dir: _eval.Path | None,
    artifact: _eval.GuardArtifact,
) -> _eval.LockfileParseResult | None:
    return next(
        (result for result in _eval._lockfile_parse_results(workspace_dir, artifact) if not result.complete), None
    )


def _finalize_incomplete_lockfile_evaluation(
    *,
    artifact: _eval.GuardArtifact,
    store: _eval.GuardStore,
    target: dict[str, object],
    workspace_dir: _eval.Path | None,
    parse_result: _eval.LockfileParseResult,
    package_intent_hash: str,
    now: str,
    config_reader: _eval.Callable[[_eval.Path], dict[str, object]] | None = None,
) -> _eval.PackageRequestEvaluation:
    config = _eval.load_guard_config(store.guard_home, workspace=workspace_dir, config_reader=config_reader)
    decision = (
        "block" if config.security_level in {"strict", "paranoid"} or not parse_result.source_hash_complete else "ask"
    )
    package = _eval._incomplete_lockfile_package_result(
        target=target,
        parse_result=parse_result,
        decision=decision,
    )
    draft = _eval._EvaluationDraft(
        decision=decision,
        enforcement="free_local",
        entitlement_state="free",
        cache_status="miss",
        packages=(package,),
        reasons=tuple(_eval._dict_items(package.get("reasons"))),
        matched_rule_id=None,
        exception_id=None,
        refresh_required=False,
        record_monitor_evidence=False,
        bundle_version=None,
        policy_version="local:none",
    )
    fingerprint = _eval._stable_hash(
        {
            "lockfile_hash": parse_result.source_hash,
            "lockfile_parser_version": parse_result.parser_version,
            **({"lockfile_hash_complete": False} if not parse_result.source_hash_complete else {}),
        }
    )
    evaluation = _eval._finalize_evaluation(
        draft,
        package_intent_hash=package_intent_hash,
        workspace_fingerprint=fingerprint,
    )
    _eval._persist_evidence(store=store, artifact=artifact, evaluation=evaluation, now=now)
    return evaluation


def _incomplete_lockfile_package_result(
    *,
    target: dict[str, object],
    parse_result: _eval.LockfileParseResult,
    decision: str = "ask",
) -> dict[str, object]:
    error_reason = parse_result.error_reason or "parse_error"
    input_admission_failure = parse_result.source_byte_limit is not None
    message = (
        f"Guard could not read the package input within its resource budget ({error_reason}), "
        "so this package request is paused. Reduce the input size or retry when the workspace is responsive."
        if input_admission_failure
        else (
            f"Guard could not completely parse the existing {parse_result.format} lockfile "
            f"({error_reason}), so this package request is paused. Repair the lockfile, then retry."
        )
    )
    package = _eval._heuristic_package_result(
        target=target,
        decision=decision,
        code="lockfile_parse_incomplete",
        message=message,
        severity="high",
    )
    metadata = _eval.incomplete_lockfile_metadata(parse_result)
    package.update(metadata)
    first_reason = _eval._first_dict_item(package.get("reasons"))
    if first_reason is not None:
        package["reasons"] = ({**first_reason, **metadata},)
    return package


def _lockfile_context(workspace_dir: _eval.Path | None, artifact: _eval.GuardArtifact) -> dict[str, object] | None:
    if workspace_dir is None:
        return None
    lockfile_paths = artifact.metadata.get("lockfile_paths")
    if not isinstance(lockfile_paths, list) or not lockfile_paths:
        return None
    lockfile_path = _eval.resolve_path_within_workspace(workspace_dir, str(lockfile_paths[0]))
    if lockfile_path is None:
        return None
    if lockfile_path.name.lower() == "bun.lockb":
        return None
    lockfile_source = _eval.read_bytes_within_workspace(workspace_dir, str(lockfile_paths[0]))
    if lockfile_source is None:
        return None
    parse_result = _eval._parse_lockfile_text_result(lockfile_path.name, lockfile_source)
    if not parse_result.complete:
        return {
            "dependencyCount": 0,
            "fileName": lockfile_path.name,
            "lockfileHash": parse_result.source_hash,
            "lockfileParserVersion": parse_result.parser_version,
            "parseComplete": False,
            "parseError": parse_result.error_reason,
        }
    manifest_hashes = _eval._hash_paths(workspace_dir, artifact.metadata.get("manifest_paths"))
    return {
        "dependencyCount": len(parse_result.entries),
        "fileName": lockfile_path.name,
        "lockfileHash": parse_result.source_hash,
        "lockfileParserVersion": parse_result.parser_version,
        "manifestHash": manifest_hashes[0] if manifest_hashes else None,
        "parseComplete": True,
        "repository": workspace_dir.name,
    }


def _safe_dependency_map_for_path(path: str, text: str, *, deadline: float) -> dict[str, str]:
    return _eval._safe_dependency_map_result_for_path(path, text, deadline=deadline).dependency_map()


def _safe_dependency_map_result_for_path(
    path: str,
    text: str,
    *,
    deadline: float,
) -> _eval.LockfileParseResult:
    budget_ms = max(0.0, (deadline - _eval.time.monotonic()) * 1000)
    return _eval.parse_lockfile_text(
        path,
        text,
        deadline=deadline,
        budget_ms=budget_ms,
        dependency_parser=_eval._dependency_map_for_path,
        package_lock_parser=_eval._package_lock_entries,
    )


def _lockfile_parse_warning_result(
    *,
    target: dict[str, object],
    artifact: _eval.GuardArtifact,
    workspace_dir: _eval.Path | None,
) -> dict[str, object] | None:
    if workspace_dir is None:
        return None
    lockfile_paths = artifact.metadata.get("lockfile_paths")
    if not isinstance(lockfile_paths, list):
        return None
    target_ecosystem = _eval._optional_string(target.get("ecosystem")) or "npm"
    for relative_path in lockfile_paths:
        lockfile_path = _eval.resolve_path_within_workspace(workspace_dir, str(relative_path))
        if lockfile_path is None:
            continue
        if lockfile_path.name.lower() == "bun.lockb":
            continue
        lockfile_ecosystem = _eval._lockfile_ecosystem(lockfile_path.name)
        if lockfile_ecosystem is not None and lockfile_ecosystem != target_ecosystem:
            continue
        lockfile_source = _eval.read_bytes_within_workspace(workspace_dir, str(relative_path))
        if lockfile_source is None:
            continue
        parse_result = _eval._parse_lockfile_text_result(lockfile_path.name, lockfile_source)
        if parse_result.complete:
            continue
        return _eval._incomplete_lockfile_package_result(
            target=target,
            parse_result=parse_result,
        )
    return None


# Resolve the facade after declarations so direct helper imports retain the cycle.
from . import supply_chain_package_eval as _eval  # noqa: E402
