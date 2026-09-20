"""Audit evaluation helpers using the original live supply-chain namespace."""

from __future__ import annotations


def build_workspace_scan_payload(
    *,
    store: _api.Any,
    config: _api.GuardConfig,
    workspace_dir: _api.Path,
    now: str,
) -> tuple[dict[str, object], int]:
    return _api.build_workspace_audit_payload(
        store=store,
        config=config,
        workspace_dir=workspace_dir,
        now=now,
        command_name="scan",
        sbom_paths=(),
    )


def build_workspace_audit_payload(
    *,
    store: _api.Any,
    config: _api.GuardConfig,
    workspace_dir: _api.Path,
    now: str,
    command_name: str,
    sbom_paths: _api.Sequence[str],
    ci: bool = False,
    fail_on: str = "high",
    before_workspace_dir: _api.Path | None = None,
    after_workspace_dir: _api.Path | None = None,
) -> tuple[dict[str, object], int]:
    runner = _api._runtime_runner_module()

    target_workspace_dir = after_workspace_dir or workspace_dir
    posture = _api.build_local_supply_chain_posture(store, config, now=now)
    diff_summary: dict[str, object] | None = None
    if before_workspace_dir is not None and after_workspace_dir is not None:
        manifest_paths, lockfile_paths, resolved_sbom_paths, inventory, diff_summary = (
            _api._workspace_diff_audit_inventory(
                before_workspace_dir=before_workspace_dir,
                after_workspace_dir=after_workspace_dir,
                sbom_paths=sbom_paths,
            )
        )
    else:
        manifest_paths, lockfile_paths, resolved_sbom_paths, inventory = _api._workspace_audit_inventory(
            target_workspace_dir,
            sbom_paths=sbom_paths,
        )
    if not inventory:
        audit_outcome, message = _api._resolve_empty_audit_outcome(
            manifest_paths=manifest_paths,
            lockfile_paths=lockfile_paths,
            posture=posture,
        )
        return (
            {
                "generated_at": now,
                "mode": command_name,
                "manifest_paths": list(manifest_paths),
                "lockfile_paths": list(lockfile_paths),
                "sbom_paths": list(resolved_sbom_paths),
                "audit_outcome": audit_outcome,
                "audit_status": "incomplete",
                "message": message,
                "supply_chain": posture,
            },
            1,
        )
    evaluation: dict[str, object]
    source = "local"
    fallback_reason: dict[str, object] | None = None
    if _api._should_use_cloud_workspace_audit(store=store, posture=posture):
        try:
            auth_context = _api._resolve_guard_sync_auth_context(store)
            workspace_id = store.get_cloud_workspace_id()
            assert workspace_id is not None
            request_payload = _api._build_cloud_audit_payload(
                workspace_dir=target_workspace_dir,
                workspace_id=workspace_id,
                store=store,
                manifest_paths=manifest_paths,
                lockfile_paths=lockfile_paths,
                inventory=inventory,
            )
            cloud_response, fallback_reason = _api._run_cloud_workspace_audit(
                request_payload=request_payload,
                auth_context=auth_context,
                workspace_id=workspace_id,
            )
            if cloud_response is not None:
                evaluation = _api._normalize_cloud_audit_response(cloud_response)
                source = "cloud"
            else:
                evaluation = _api._workspace_local_evaluation(
                    store=store,
                    workspace_dir=target_workspace_dir,
                    inventory=inventory,
                    manifest_paths=manifest_paths,
                    lockfile_paths=lockfile_paths,
                    command_name=command_name,
                    now=now,
                )
        except (runner.GuardSyncAuthorizationExpiredError, runner.GuardSyncNotConfiguredError, RuntimeError):
            fallback_reason = {
                "code": "cloud_auth_error",
                "message": "Guard cloud authorization could not be refreshed, so Guard fell back locally.",
            }
            evaluation = _api._workspace_local_evaluation(
                store=store,
                workspace_dir=target_workspace_dir,
                inventory=inventory,
                manifest_paths=manifest_paths,
                lockfile_paths=lockfile_paths,
                command_name=command_name,
                now=now,
            )
    else:
        evaluation = _api._workspace_local_evaluation(
            store=store,
            workspace_dir=target_workspace_dir,
            inventory=inventory,
            manifest_paths=manifest_paths,
            lockfile_paths=lockfile_paths,
            command_name=command_name,
            now=now,
        )
    evaluation = _api._enrich_evaluation_packages_with_advisory_aliases(evaluation, store)
    payload: dict[str, object] = {
        "generated_at": now,
        "mode": command_name,
        "source": source,
        "manifest_paths": list(manifest_paths),
        "lockfile_paths": list(lockfile_paths),
        "sbom_paths": list(resolved_sbom_paths),
        "inventory": _api._inventory_summary(inventory),
        "evaluation": evaluation,
        "supply_chain": posture,
    }
    lockfile_warnings = _api._audit_lockfile_warnings(target_workspace_dir, lockfile_paths)
    if lockfile_warnings:
        payload["lockfile_warnings"] = list(lockfile_warnings)
    if diff_summary is not None:
        payload["diff"] = diff_summary
    if fallback_reason is not None:
        payload["fallback_reason"] = fallback_reason
    exit_code = _api._evaluation_exit_code(str(evaluation.get("decision") or "monitor"))
    if ci:
        ci_result = _api._ci_gate_result(evaluation, threshold=fail_on)
        payload["ci"] = ci_result
        if ci_result["matched"]:
            exit_code = 3
    return (payload, exit_code)


def _workspace_local_evaluation(
    *,
    store: _api.Any,
    workspace_dir: _api.Path,
    inventory: tuple[dict[str, object], ...],
    manifest_paths: tuple[str, ...],
    lockfile_paths: tuple[str, ...],
    command_name: str,
    now: str,
) -> dict[str, object]:
    intent = _api._workspace_scan_intent(
        workspace_dir,
        command_name=command_name,
        inventory=inventory,
        manifest_paths=manifest_paths,
        lockfile_paths=lockfile_paths,
    )
    assert intent is not None
    artifact = _api.build_package_request_artifact(
        _api._LOCAL_SUPPLY_CHAIN_HARNESS,
        intent,
        config_path="hol-guard.toml",
        source_scope="project",
    )
    evaluation = _api.evaluate_package_request_artifact(
        artifact=artifact,
        store=store,
        workspace_dir=workspace_dir,
        now=now,
    )
    return evaluation.to_dict()


def build_supply_chain_explain_payload(
    *,
    store: _api.Any,
    config: _api.GuardConfig,
    workspace_dir: _api.Path,
    package_spec: str,
    ecosystem: str,
    now: str,
) -> tuple[dict[str, object], int]:
    posture = _api.build_local_supply_chain_posture(store, config, now=now)
    manifest_paths, lockfile_paths = _api._workspace_files(workspace_dir)
    intent = _api.PackageIntent(
        package_manager=_api._PACKAGE_MANAGER_BY_ECOSYSTEM.get(ecosystem, ecosystem),
        intent_kind="install",
        command_tokens=("hol-guard", "supply-chain", "explain", package_spec),
        redacted_command=_api.shlex.join(("hol-guard", "supply-chain", "explain", package_spec)),
        targets=(_api._target_for_package_spec(ecosystem, package_spec),),
        manifest_paths=manifest_paths,
        lockfile_paths=lockfile_paths,
    )
    artifact = _api.build_package_request_artifact(
        _api._LOCAL_SUPPLY_CHAIN_HARNESS,
        intent,
        config_path="hol-guard.toml",
        source_scope="project",
    )
    evaluation = _api.evaluate_package_request_artifact(
        artifact=artifact,
        store=store,
        workspace_dir=workspace_dir,
        now=now,
    )
    payload: dict[str, object] = {
        "generated_at": now,
        "request": {
            "package": package_spec,
            "ecosystem": ecosystem,
            "manifest_paths": list(intent.manifest_paths),
            "lockfile_paths": list(intent.lockfile_paths),
        },
        "evaluation": evaluation.to_dict(),
        "supply_chain": posture,
    }
    return (payload, _api._evaluation_exit_code(evaluation.decision))


def _workspace_scan_intent(
    workspace_dir: _api.Path,
    *,
    command_name: str,
    inventory: tuple[dict[str, object], ...] | None = None,
    manifest_paths: tuple[str, ...] | None = None,
    lockfile_paths: tuple[str, ...] | None = None,
) -> _api.PackageIntent | None:
    resolved_manifest_paths, resolved_lockfile_paths = (
        _api._workspace_files(workspace_dir)
        if manifest_paths is None or lockfile_paths is None
        else (manifest_paths, lockfile_paths)
    )
    if inventory is None:
        inventory = _api._workspace_inventory_from_paths(
            workspace_dir, resolved_manifest_paths, resolved_lockfile_paths
        )
    if not inventory and not resolved_manifest_paths and not resolved_lockfile_paths:
        return None
    targets = tuple(_api._target_from_inventory_item(item) for item in inventory)
    package_manager = _api._package_manager_for_scan(resolved_manifest_paths)
    return _api.PackageIntent(
        package_manager=package_manager,
        intent_kind="install",
        command_tokens=("hol-guard", "supply-chain", command_name),
        redacted_command=f"hol-guard supply-chain {command_name}",
        targets=targets,
        manifest_paths=resolved_manifest_paths,
        lockfile_paths=resolved_lockfile_paths,
    )


# Bind after declarations so importing this owner directly preserves the facade cycle.
from . import local_supply_chain as _api  # noqa: E402
