"""Policy identity helpers using the original live supply-chain namespace."""

from __future__ import annotations


def recompute_package_protect_artifact_hash(
    command: _api.Sequence[str],
    *,
    store: _api.Any,
    workspace_dir: _api.Path,
    now: str | None = None,
    config: _api.GuardConfig | None = None,
) -> str | None:
    evaluation_timestamp = now or _api.datetime.now(_api.timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )
    authority = _api._build_package_protect_authority(
        command=command,
        store=store,
        workspace_dir=workspace_dir,
        now=evaluation_timestamp,
        config=config,
        additional_current_action=None,
        additional_policy_context=None,
    )
    return authority.artifact_hash if authority is not None else None


def _package_target_identities(artifact: _api.GuardArtifact) -> tuple[_api.ProtectTargetIdentity, ...]:
    metadata = artifact.metadata if isinstance(artifact.metadata, dict) else {}
    targets = metadata.get("targets")
    if not isinstance(targets, list):
        return ()
    identities: list[_api.ProtectTargetIdentity] = []
    for item in targets:
        if not isinstance(item, dict):
            continue
        ecosystem = str(item.get("ecosystem") or "")
        package_name = item.get("package_name") if isinstance(item.get("package_name"), str) else None
        raw_spec = str(item.get("raw_spec") or package_name or "")
        version = item.get("requested_specifier") if isinstance(item.get("requested_specifier"), str) else None
        source_url = item.get("source_url") if isinstance(item.get("source_url"), str) else None
        artifact_id = f"{ecosystem}:{package_name or raw_spec}"
        artifact_name = package_name or raw_spec
        identities.append(
            _api.ProtectTargetIdentity(
                artifact_id=artifact_id,
                artifact_name=artifact_name,
                ecosystem=ecosystem,
                package_name=package_name,
                package_url=_api.build_package_url(ecosystem, package_name, version),
                source_url=source_url,
            )
        )
    return tuple(identities)


def _package_matched_cached_advisory_ids(store: _api.Any, artifact: _api.GuardArtifact) -> tuple[str, ...]:
    advisories = store.list_cached_advisories(limit=None)
    identities = _api._package_target_identities(artifact)
    matched_ids: set[str] = set()
    for advisory in advisories:
        for identity in identities:
            if _api.advisory_matches_target(advisory, identity):
                advisory_id = advisory.get("id")
                if isinstance(advisory_id, str) and advisory_id:
                    matched_ids.add(advisory_id)
                break
    return tuple(sorted(matched_ids))


def _package_feed_snapshot_hash(store: _api.Any) -> str | None:
    workspace_id = store.get_cloud_workspace_id()
    if workspace_id is None:
        return None
    cached_bundle = store.get_cached_supply_chain_bundle(workspace_id)
    if not isinstance(cached_bundle, dict):
        return None
    bundle = cached_bundle.get("bundle")
    if not isinstance(bundle, dict):
        return None
    value = bundle.get("feedSnapshotHash")
    return value if isinstance(value, str) and value else None


def _package_policy_gate_context(
    store: _api.Any,
    artifact: _api.GuardArtifact,
    evaluation: _api.Any,
) -> dict[str, object]:
    return {
        "bundle_version": evaluation.bundle_version,
        "decision": evaluation.decision,
        "enforcement": evaluation.enforcement,
        "entitlement_state": evaluation.entitlement_state,
        "exception_id": evaluation.exception_id,
        "feed_snapshot_hash": _api._package_feed_snapshot_hash(store),
        "matched_advisory_ids": list(_api._package_matched_cached_advisory_ids(store, artifact)),
        "matched_rule_id": evaluation.matched_rule_id,
        "packages": list(evaluation.packages),
        "policy_action": evaluation.policy_action,
        "policy_version": evaluation.policy_version,
        "reasons": list(evaluation.reasons),
    }


def _package_config_policy_context(
    *,
    artifact: _api.GuardArtifact,
    config: _api.GuardConfig | None,
) -> dict[str, object]:
    if config is None:
        return {"available": False}
    harness_package_script_action = (config.harness_risk_actions or {}).get(artifact.harness, {}).get("package_script")
    artifact_override = (config.artifact_actions or {}).get(artifact.artifact_id)
    publisher_override = (
        (config.publisher_actions or {}).get(artifact.publisher) if artifact.publisher is not None else None
    )
    harness_override = (config.harness_actions or {}).get(artifact.harness)
    return {
        "artifact_override": artifact_override,
        "available": True,
        "effective_package_script_action": _api.resolve_risk_action(
            config,
            "package_script",
            harness=artifact.harness,
        ),
        "global_package_script_action": _api.resolve_risk_action(config, "package_script", harness=None),
        "harness": artifact.harness,
        "harness_override": harness_override,
        "harness_package_script_action": harness_package_script_action,
        "managed_locked_settings": list(config.managed_locked_settings),
        "managed_policy_hash": config.managed_policy_hash,
        "managed_policy_status": config.managed_policy_status,
        "mode": config.mode,
        "publisher_override": publisher_override,
        "resolved_override": config.resolve_action_override(
            artifact.harness,
            artifact.artifact_id,
            artifact.publisher,
        ),
        "security_level": config.security_level,
    }


def compose_current_package_policy_action(
    *,
    artifact: _api.GuardArtifact,
    evaluation: _api.Any,
    config: _api.GuardConfig | None,
    additional_current_action: object | None = None,
) -> _api.GuardAction:
    """Compose feed and effective Guard configuration before approval reuse."""

    actions: list[object] = [evaluation.policy_action]
    if additional_current_action is not None:
        actions.append(additional_current_action)
    if config is not None:
        config_policy = _api._package_config_policy_context(artifact=artifact, config=config)
        for key in ("effective_package_script_action", "resolved_override"):
            action = config_policy.get(key)
            if action is not None:
                actions.append(action)
    return _api.most_restrictive_guard_action(*actions, unknown_action="block")


def _package_current_policy_context(
    *,
    artifact: _api.GuardArtifact,
    store: _api.Any,
    evaluation: _api.Any,
    config: _api.GuardConfig | None,
    additional_current_action: object | None = None,
    additional_policy_context: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "configuration": _api._package_config_policy_context(artifact=artifact, config=config),
        "current_action": _api.compose_current_package_policy_action(
            artifact=artifact,
            evaluation=evaluation,
            config=config,
            additional_current_action=additional_current_action,
        ),
        "additional": additional_policy_context if additional_policy_context is not None else {"available": False},
        "feed": _api._package_policy_gate_context(store, artifact, evaluation),
        "version": 1,
    }


def _package_request_artifact_hash(
    artifact: _api.GuardArtifact,
    *,
    workspace_dir: _api.Path,
    store: _api.Any,
    evaluation: _api.Any,
    execution_context: _api.PackageExecutionContext | None = None,
    launch_identity: _api.Mapping[str, object] | None = None,
    config: _api.GuardConfig | None = None,
    additional_current_action: object | None = None,
    additional_policy_context: dict[str, object] | None = None,
) -> str:
    policy_context = _api._package_current_policy_context(
        artifact=artifact,
        store=store,
        evaluation=evaluation,
        config=config,
        additional_current_action=additional_current_action,
        additional_policy_context=additional_policy_context,
    )
    metadata = artifact.metadata if isinstance(artifact.metadata, dict) else {}
    resolved_execution_context = execution_context or _api.build_package_execution_context(
        workspace_dir=workspace_dir,
        artifact=artifact,
    )
    approval_identity = _api._package_approval_identity(
        artifact=artifact,
        evaluation=evaluation,
        execution_context=resolved_execution_context,
    )
    manifest_paths = _api._string_items(metadata.get("manifest_paths"))
    lockfile_paths = _api._string_items(metadata.get("lockfile_paths"))
    content_material: dict[str, object] = {}
    if manifest_paths or lockfile_paths:
        content_material.update(
            {
                "manifest_paths": list(manifest_paths),
                "lockfile_paths": list(lockfile_paths),
                "manifest_hashes": _api._hash_existing_paths(workspace_dir, manifest_paths),
                "lockfile_hashes": _api._hash_existing_paths(workspace_dir, lockfile_paths),
            }
        )
    component_digests = {component.name: component.digest for component in resolved_execution_context.components}
    return _api.build_approval_context_token(
        identity={
            "approval_identity": approval_identity,
            "artifact_id": artifact.artifact_id,
            "config_path": artifact.config_path,
            "exact_workspace": component_digests.get("exact_workspace"),
            "package_manager_executable": component_digests.get("package_manager_executable"),
            "package_launch_identity": _api._package_launch_approval_identity(launch_identity),
            "publisher": artifact.publisher,
            "repository_identity": component_digests.get("repository_identity"),
            "source_scope": artifact.source_scope,
            "workspace_identity": component_digests.get("workspace_identity"),
        },
        content={
            **content_material,
            "lockfile_parser_version": _api.LOCKFILE_PARSER_VERSION,
            "manifests_and_lockfiles": component_digests.get("manifests_and_lockfiles"),
            "workspace_configuration": component_digests.get("workspace_configuration"),
        },
        capabilities={
            "environment_policy": component_digests.get("environment_policy"),
            "lifecycle_hooks_overrides_and_patches": component_digests.get("lifecycle_hooks_overrides_and_patches"),
            "registry_and_proxy_configuration": component_digests.get("registry_and_proxy_configuration"),
        },
        policy=policy_context,
        sandbox={
            "analysis": config.sandbox_analysis if config is not None else "unknown",
            "required": policy_context["current_action"] == "sandbox-required",
        },
    )


def _package_launch_approval_identity(launch_identity: _api.Mapping[str, object] | None) -> dict[str, object]:
    """Bind the raw launch vector without duplicating non-portable paths.

    The package execution context already contains the normalized manager,
    shebang interpreter, code-loading, and cwd identity. This additional
    material binds the exact argv shape and forces wrapper launches to remain
    one-attempt-only without breaking linked-worktree portability.
    """

    if launch_identity is None:
        return {"available": False}
    wrapper_resolution = launch_identity.get("wrapper_resolution")
    return {
        "argv_sha256": launch_identity.get("argv_sha256"),
        "wrapper_resolution": (
            wrapper_resolution if isinstance(wrapper_resolution, _api.Mapping) else {"status": "direct"}
        ),
    }


def _package_approval_identity(
    *,
    artifact: _api.GuardArtifact,
    evaluation: _api.Any,
    execution_context: _api.PackageExecutionContext,
) -> dict[str, object]:
    """Return the complete, secret-free preimage for a package approval."""

    metadata = artifact.metadata if isinstance(artifact.metadata, dict) else {}
    raw_targets = metadata.get("targets")
    targets = (
        [
            {
                "alias": _api._string_value(target.get("alias")),
                "ecosystem": _api._string_value(target.get("ecosystem")),
                "package_name": _api._string_value(target.get("package_name")),
                "raw_spec": _api._string_value(target.get("raw_spec")),
                "raw_spec_hash": _api._string_value(target.get("raw_spec_hash")),
                "requested_specifier": _api._string_value(target.get("requested_specifier")),
                "source_url_hash": _api._string_value(target.get("source_url_hash"))
                or (
                    _api.stable_digest_hex(source_url.encode("utf-8"))
                    if (source_url := _api._string_value(target.get("source_url"))) is not None
                    else None
                ),
            }
            for target in raw_targets
            if isinstance(target, dict)
        ]
        if isinstance(raw_targets, list)
        else []
    )
    raw_packages = getattr(evaluation, "packages", ())
    packages = (
        [
            {
                "dependency_path": _api._string_value(package.get("dependencyPath")),
                "ecosystem": _api._string_value(package.get("ecosystem")),
                "name": _api._string_value(package.get("name")),
                "namespace": _api._string_value(package.get("namespace")),
                "package_manager": _api._string_value(package.get("packageManager")),
                "requested_version": _api._string_value(package.get("requestedVersion")),
                "resolved_version": _api._string_value(package.get("resolvedVersion")),
            }
            for package in raw_packages
            if isinstance(package, dict)
        ]
        if isinstance(raw_packages, (tuple, list))
        else []
    )
    return {
        "context_digest": execution_context.digest,
        "context_version": execution_context.version,
        "manager": _api._string_value(metadata.get("package_manager")),
        "packages": packages,
        "targets": targets,
        "version": 1,
    }


def package_request_policy_hash(
    *,
    artifact: _api.GuardArtifact,
    store: _api.Any,
    workspace_dir: _api.Path,
    evaluation: _api.Any,
    execution_context: _api.PackageExecutionContext | None = None,
    config: _api.GuardConfig | None = None,
) -> str:
    """Hash a package request using manifest and lockfile contents."""

    return _api._package_request_artifact_hash(
        artifact,
        workspace_dir=workspace_dir,
        store=store,
        evaluation=evaluation,
        execution_context=execution_context,
        config=config,
    )


# Bind after declarations so importing this owner directly preserves the facade cycle.
from . import local_supply_chain as _api  # noqa: E402
