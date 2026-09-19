"""Transitive lockfile package evaluation and bundle indexing."""

from __future__ import annotations


def _transitive_lockfile_results(
    *,
    bundle_response: _eval.SupplyChainBundleResponse,
    artifact: _eval.GuardArtifact,
    workspace_dir: _eval.Path | None,
    now_timestamp: float | None = None,
) -> list[dict[str, object]]:
    if workspace_dir is None:
        return []
    lockfile_paths = artifact.metadata.get("lockfile_paths")
    if not isinstance(lockfile_paths, list):
        return []
    results: list[dict[str, object]] = []
    bundle_stale = _eval._is_bundle_stale(bundle_response, now_timestamp=now_timestamp)
    bundle_index = _eval._bundle_package_index(bundle_response)
    direct_target_names_by_ecosystem: dict[str, set[str]] = {}
    all_direct_target_names: set[str] = set()
    direct_targets = _eval._evaluation_targets(artifact, workspace_dir)
    for target in direct_targets:
        ecosystem = _eval._optional_string(target.get("ecosystem")) or "npm"
        candidate_names = {str(target["normalized_name"]), *_eval._target_candidate_names(target)}
        direct_target_names_by_ecosystem.setdefault(ecosystem, set()).update(candidate_names)
        all_direct_target_names.update(candidate_names)
    for relative_path in lockfile_paths:
        lockfile_path = _eval.resolve_path_within_workspace(workspace_dir, str(relative_path))
        if lockfile_path is None:
            continue
        if lockfile_path.name.lower() == "bun.lockb":
            continue
        lockfile_ecosystem = _eval._lockfile_ecosystem(lockfile_path.name)
        direct_target_names = (
            direct_target_names_by_ecosystem.get(lockfile_ecosystem, all_direct_target_names)
            if lockfile_ecosystem is not None
            else all_direct_target_names
        )
        lockfile_source = _eval.read_bytes_within_workspace(workspace_dir, str(relative_path))
        if lockfile_source is None:
            continue
        dependency_entries: list[tuple[str, str, str, bool]] = []
        parse_result = _eval._parse_lockfile_text_result(lockfile_path.name, lockfile_source)
        if not parse_result.complete:
            results.append(
                _eval._incomplete_lockfile_package_result(
                    target=(
                        direct_targets[0] if direct_targets else _eval.incomplete_lockfile_fallback_target(parse_result)
                    ),
                    parse_result=parse_result,
                )
            )
            continue
        for entry in parse_result.entries:
            normalized_dependency_path = entry.dependency_path.strip("/")
            if not normalized_dependency_path:
                continue
            package_name = (
                entry.package_name
                if lockfile_path.name == "package-lock.json"
                else _eval._dependency_package_name(normalized_dependency_path)
            )
            if package_name is None:
                continue
            dependency_entries.append(
                (
                    entry.dependency_path,
                    package_name,
                    entry.version,
                    normalized_dependency_path in direct_target_names,
                )
            )
        for dependency_path, package_name, version, direct in dependency_entries:
            if direct:
                continue
            package_match = _eval._bundle_package_from_index(
                bundle_index,
                package_name=package_name,
                package_version=version,
                ecosystem=lockfile_ecosystem,
            )
            offline = _eval.evaluate_cached_supply_chain_bundle(
                bundle_response,
                package_name=package_name,
                package_version=version,
                ecosystem=lockfile_ecosystem,
                now=now_timestamp,
            )
            if offline.emergency_deny and offline.action == "block":
                results.append(
                    {
                        "decision": "block",
                        "ecosystem": lockfile_ecosystem or "npm",
                        "name": package_name.rsplit("/", 1)[-1],
                        "namespace": (
                            package_name.rsplit("/", 1)[0]
                            if package_name.startswith("@") and "/" in package_name
                            else None
                        ),
                        "requestedVersion": version,
                        "resolvedVersion": version,
                        "recommendedFixVersion": offline.recommended_fix_version,
                        "riskScore": None,
                        "direct": False,
                        "dependencyPath": dependency_path,
                        "packageManager": str(artifact.metadata.get("package_manager") or "npm"),
                        "redactedCommand": _eval._optional_string(artifact.metadata.get("redacted_command")),
                        "reasons": (
                            {
                                "code": offline.reason,
                                "message": _eval._emergency_deny_bundle_message(
                                    target={
                                        "name": package_name.rsplit("/", 1)[-1],
                                        "namespace": (
                                            package_name.rsplit("/", 1)[0]
                                            if package_name.startswith("@") and "/" in package_name
                                            else None
                                        ),
                                        "ecosystem": lockfile_ecosystem or "npm",
                                    },
                                    resolved_version=version,
                                    reason=offline.reason,
                                ),
                                "severity": "critical",
                                "source": "bundle",
                            },
                        ),
                    }
                )
                continue
            if package_match is None:
                continue
            decision = _eval._transitive_lockfile_decision(package=package_match, stale=bundle_stale)
            if decision not in {"ask", "block", "warn"}:
                continue
            downgraded_low_confidence = (
                decision == "warn" and _eval._normalize_bundle_action(package_match.default_action) == "block"
            )
            package_label = _eval._bundle_package_label(package_match, version=version)
            results.append(
                {
                    "decision": decision,
                    "ecosystem": package_match.ecosystem,
                    "name": package_match.name,
                    "namespace": package_match.namespace,
                    "requestedVersion": version,
                    "resolvedVersion": version,
                    "recommendedFixVersion": package_match.recommended_fix_version,
                    "riskScore": package_match.risk_score,
                    "direct": False,
                    "dependencyPath": dependency_path,
                    "packageManager": str(artifact.metadata.get("package_manager") or "npm"),
                    "redactedCommand": _eval._optional_string(artifact.metadata.get("redacted_command")),
                    "reasons": (
                        {
                            "code": "transitive_low_confidence_match"
                            if downgraded_low_confidence
                            else "transitive_lockfile_match",
                            "message": (
                                (
                                    f"Existing lockfile includes {package_label} at transitive dependency path "
                                    f"{dependency_path} with lower-confidence risk signals."
                                )
                                if downgraded_low_confidence
                                else (
                                    f"Existing lockfile already includes vulnerable {package_label} "
                                    f"at dependency path {dependency_path}."
                                )
                            ),
                            "severity": package_match.normalized_severity,
                            "source": "lockfile",
                        },
                    ),
                }
            )
    return results


def _transitive_lockfile_decision(*, package: _eval.SupplyChainBundlePackage, stale: bool) -> str:
    decision = _eval._normalize_bundle_action(
        package.default_action if package.default_action != "allow" else "monitor"
    )
    if stale and not _eval._is_high_confidence_block(package):
        return "warn" if decision in {"block", "ask", "warn"} else "monitor"
    if decision != "block":
        return decision
    if _eval._is_high_confidence_block(package):
        return "block"
    if package.confidence >= _eval._TRANSITIVE_BLOCK_CONFIDENCE_THRESHOLD:
        return "block"
    return "warn"


def _is_bundle_stale(bundle_response: _eval.SupplyChainBundleResponse, *, now_timestamp: float | None) -> bool:
    try:
        _eval.check_supply_chain_bundle_freshness(bundle_response.bundle, now=now_timestamp)
    except _eval.SupplyChainBundleExpiredError:
        return True
    return False


def _bundle_package_index(
    bundle_response: _eval.SupplyChainBundleResponse,
) -> _eval.Mapping[_eval.CanonicalPackageIdentity, _eval.SupplyChainBundlePackage]:
    return bundle_response.bundle.package_index.exact


def _bundle_package_from_index(
    index: _eval.Mapping[_eval.CanonicalPackageIdentity, _eval.SupplyChainBundlePackage],
    *,
    package_name: str,
    package_version: str,
    ecosystem: str | None = None,
) -> _eval.SupplyChainBundlePackage | None:
    if ecosystem is None:
        return None
    try:
        identity = _eval.parse_package_identity(
            ecosystem=ecosystem,
            package_name=package_name,
            version=package_version,
        )
    except _eval.PackageIdentityError:
        return None
    return index.get(identity)


def _parse_evaluation_timestamp(now_value: str) -> float | None:
    try:
        return _eval.datetime.fromisoformat(now_value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _lockfile_ecosystem(lockfile_name: str) -> str | None:
    lower_name = lockfile_name.lower()
    if lower_name in {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"}:
        return "npm"
    if lower_name in {"poetry.lock", "uv.lock", "pipfile.lock"}:
        return "pypi"
    if lower_name == "cargo.lock":
        return "cargo"
    if lower_name == "composer.lock":
        return "packagist"
    if lower_name == "gemfile.lock":
        return "rubygems"
    if lower_name == "go.sum":
        return "go"
    if lower_name == "gradle.lockfile":
        return "maven"
    return None


# Resolve the facade after declarations so direct helper imports retain the cycle.
from . import supply_chain_package_eval as _eval  # noqa: E402
