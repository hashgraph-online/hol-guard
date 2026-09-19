"""Package target projection and identity checks."""

from __future__ import annotations


def _evaluation_targets(
    artifact: _eval.GuardArtifact,
    workspace_dir: _eval.Path | None,
) -> tuple[dict[str, object], ...]:
    return _eval._manifest_evaluation_targets(
        artifact,
        workspace_dir,
        explicit_targets=_eval._targets_from_artifact(artifact),
    )


def _cloud_evaluation_targets(
    artifact: _eval.GuardArtifact,
    workspace_dir: _eval.Path | None,
) -> tuple[dict[str, object], ...]:
    return _eval._manifest_evaluation_targets(
        artifact,
        workspace_dir,
        explicit_targets=_eval._targets_from_artifact(artifact),
        include_locked=True,
    )


def _targets_from_artifact(artifact: _eval.GuardArtifact) -> tuple[dict[str, object], ...]:
    public_targets = artifact.metadata.get("targets")
    if not isinstance(public_targets, list):
        return ()
    private_targets = artifact.runtime_private_metadata.get("package_targets")
    private_integrity_invalid = False
    if isinstance(private_targets, list):
        private_integrity_invalid = not _eval._private_package_targets_match_public(private_targets, public_targets)
        raw_targets = public_targets if private_integrity_invalid else private_targets
    else:
        raw_targets = public_targets
        private_integrity_invalid = not _eval._public_package_targets_are_self_consistent(public_targets)
    parsed: list[dict[str, object]] = []
    package_manager = str(artifact.metadata.get("package_manager") or "npm")
    redacted_command = _eval._optional_string(artifact.metadata.get("redacted_command"))
    for item in raw_targets:
        if not isinstance(item, dict):
            continue
        ecosystem = str(item.get("ecosystem") or "npm")
        package_name = _eval._optional_string(item.get("package_name"))
        if package_name is None:
            continue
        namespace, name = _eval._split_namespace_name(package_name, ecosystem=ecosystem)
        requested = _eval._optional_string(item.get("requested_specifier"))
        raw_spec = _eval._optional_string(item.get("raw_spec")) or package_name
        source_url = _eval._optional_string(item.get("source_url"))
        if source_url is None:
            source_url = _eval._source_url_from_specifier(requested)
        if source_url is None and "source_kind" not in item:
            source_url = _eval._source_url_from_raw_spec(raw_spec)
        if source_url is not None:
            requested = None
        source_spec = _eval._npm_source_spec(source_url, ecosystem=ecosystem)
        if requested is None and source_url is None:
            requested = _eval._default_registry_range(ecosystem)
        exact_version = (
            None
            if _eval._requested_specifier_is_range(requested, ecosystem=ecosystem)
            else _eval._exact_version(requested)
        )
        parsed.append(
            {
                "ecosystem": ecosystem,
                "package_name": package_name,
                "normalized_name": _eval._normalize_package_name(ecosystem, package_name),
                "namespace": namespace,
                "name": name,
                "raw_spec": raw_spec,
                "version": exact_version,
                "range": requested if exact_version is None else None,
                "source_url": source_url,
                "source_kind": source_spec.source_kind if source_spec is not None else None,
                "source_repository": source_spec.canonical_repository if source_spec is not None else None,
                "source_revision_kind": source_spec.revision_kind if source_spec is not None else None,
                "source_identity": source_spec.identity if source_spec is not None else None,
                "source_redacted": source_spec.redacted if source_spec is not None else None,
                "source_invalid_reason": source_spec.reason if source_spec is not None else None,
                "alias": _eval._optional_string(item.get("alias")),
                "dependency_group": _eval._optional_string(item.get("dependency_group")),
                "extras": _eval._string_tuple(item.get("extras")),
                "editable": bool(item.get("editable")),
                "package_manager": package_manager,
                "redacted_command": redacted_command,
                "external_archive_source_integrity_invalid": private_integrity_invalid,
            }
        )
    return tuple(parsed)


def _private_package_targets_match_public(
    private_targets: list[object],
    public_targets: list[object],
) -> bool:
    if len(private_targets) != len(public_targets):
        return False
    structural_fields = (
        "ecosystem",
        "package_name",
        "requested_specifier",
        "alias",
        "dependency_group",
        "extras",
        "editable",
        "source_kind",
        "source_repository",
        "source_revision_kind",
        "source_identity",
        "source_invalid_reason",
    )
    for private_target, public_target in zip(private_targets, public_targets, strict=True):
        if not isinstance(private_target, dict) or not isinstance(public_target, dict):
            return False
        if any(private_target.get(field) != public_target.get(field) for field in structural_fields):
            return False
        private_raw_spec = _eval._optional_string(private_target.get("raw_spec"))
        expected_raw_spec_hash = _eval._optional_string(public_target.get("raw_spec_hash"))
        if (
            private_raw_spec is None
            or expected_raw_spec_hash is None
            or _eval.hashlib.sha256(private_raw_spec.encode("utf-8")).hexdigest() != expected_raw_spec_hash
        ):
            return False
        private_source_url = _eval._optional_string(private_target.get("source_url"))
        expected_source_hash = _eval._optional_string(public_target.get("source_url_hash"))
        if private_source_url is None:
            if expected_source_hash is not None:
                return False
        elif (
            expected_source_hash is None
            or _eval.hashlib.sha256(private_source_url.encode("utf-8")).hexdigest() != expected_source_hash
        ):
            return False
    return True


def _public_package_targets_are_self_consistent(public_targets: list[object]) -> bool:
    """Permit serialized targets only when no exact value was redacted away."""

    for target in public_targets:
        if not isinstance(target, dict):
            return False
        raw_spec = _eval._optional_string(target.get("raw_spec"))
        raw_spec_hash = _eval._optional_string(target.get("raw_spec_hash"))
        if raw_spec_hash is not None and (
            raw_spec is None or _eval.hashlib.sha256(raw_spec.encode("utf-8")).hexdigest() != raw_spec_hash
        ):
            return False
        source_url = _eval._optional_string(target.get("source_url"))
        source_url_hash = _eval._optional_string(target.get("source_url_hash"))
        if source_url_hash is not None and (
            source_url is None or _eval.hashlib.sha256(source_url.encode("utf-8")).hexdigest() != source_url_hash
        ):
            return False
    return True


# Resolve the facade after declarations so direct helper imports retain the cycle.
from . import supply_chain_package_eval as _eval  # noqa: E402
