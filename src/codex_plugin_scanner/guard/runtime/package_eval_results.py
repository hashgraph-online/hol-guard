"""Package evaluation result construction."""

from __future__ import annotations


def _bundle_package_result(
    *,
    target: dict[str, object],
    bundle_response: _eval.SupplyChainBundleResponse,
    package: _eval.SupplyChainBundlePackage,
    decision: str,
    reason: str,
    stale: bool,
    resolved_version: str,
) -> dict[str, object]:
    severity = package.normalized_severity if stale is False else "unknown"
    advisory_aliases = _eval._bundle_advisory_aliases(bundle_response, package)
    result: dict[str, object] = {
        "decision": decision,
        "ecosystem": package.ecosystem,
        "name": package.name,
        "namespace": package.namespace,
        "requestedVersion": _eval._optional_string(target.get("range"))
        or _eval._optional_string(target.get("version")),
        "resolvedVersion": resolved_version,
        "recommendedFixVersion": package.recommended_fix_version,
        "riskScore": package.risk_score,
        "direct": True,
        "dependencyPath": None,
        "packageManager": _eval._optional_string(target.get("package_manager")) or "npm",
        "redactedCommand": _eval._optional_string(target.get("redacted_command")),
        "alias": _eval._optional_string(target.get("alias")),
        "sourceIdentity": _eval._optional_string(target.get("source_identity")),
        "sourceRepository": _eval._optional_string(target.get("source_repository")),
        "sourceRevisionKind": _eval._optional_string(target.get("source_revision_kind")),
        "relatedAdvisoryIds": list(package.related_advisory_ids),
        "reasons": (
            {
                "advisoryId": _eval._primary_bundle_advisory_id(bundle_response, package),
                "code": reason,
                "message": _eval._bundle_reason_message(package, decision=decision, reason=reason, stale=stale),
                "severity": severity,
                "source": "bundle",
            },
        ),
    }
    if advisory_aliases:
        result["advisoryAliases"] = advisory_aliases
    return result


def _system_package_monitor_result(target: dict[str, object]) -> dict[str, object]:
    command = _eval._optional_string(target.get("redacted_command")) or ""
    signals = _eval.detect_supply_chain_risk(command)
    if signals:
        strongest = sorted(signals, key=lambda item: _eval._severity_rank_value(item.severity), reverse=True)[0]
        return _eval._heuristic_package_result(
            target=target,
            decision="warn",
            code="system_package_manager_generic_risk",
            message=strongest.plain_reason,
            severity=strongest.severity,
        )
    return _eval._heuristic_package_result(
        target=target,
        decision="warn",
        code="system_package_manager_monitor_only",
        message=(
            "Guard treats system package managers as monitor-only coverage today and will not "
            "pretend advisory blocking."
        ),
        severity="low",
    )


def _homebrew_package_monitor_result(target: dict[str, object]) -> dict[str, object]:
    command = _eval._optional_string(target.get("redacted_command")) or ""
    signals = _eval.detect_supply_chain_risk(command)
    if signals:
        strongest = sorted(signals, key=lambda item: _eval._severity_rank_value(item.severity), reverse=True)[0]
        return _eval._heuristic_package_result(
            target=target,
            decision="warn",
            code="homebrew_package_manager_generic_risk",
            message=strongest.plain_reason,
            severity=strongest.severity,
        )
    return _eval._heuristic_package_result(
        target=target,
        decision="warn",
        code="homebrew_package_manager_monitor_only",
        message=(
            "Guard intercepts Homebrew requests today, records formula, cask, tap, and Brewfile intent, "
            "and treats them as monitor-only until Homebrew advisory enforcement is available."
        ),
        severity="low",
    )


def _unsupported_ecosystem_result(target: dict[str, object]) -> dict[str, object]:
    command = _eval._optional_string(target.get("redacted_command")) or ""
    signals = _eval.detect_supply_chain_risk(command)
    if signals:
        strongest = sorted(signals, key=lambda item: _eval._severity_rank_value(item.severity), reverse=True)[0]
        decision = "block" if strongest.severity in {"critical", "high"} else "warn"
        return _eval._heuristic_package_result(
            target=target,
            decision=decision,
            code="unsupported_ecosystem_generic_risk",
            message=strongest.plain_reason,
            severity=strongest.severity,
        )
    return _eval._heuristic_package_result(
        target=target,
        decision="monitor",
        code="unsupported_ecosystem_monitor_only",
        message="Guard recorded this unsupported package-manager request and applied generic risk detection only.",
        severity="low",
    )


def _local_source_dependency_result(target: dict[str, object]) -> dict[str, object] | None:
    source_url = _eval._optional_string(target.get("source_url"))
    if source_url is None or not source_url.startswith("file:"):
        return None
    return _eval._heuristic_package_result(
        target=target,
        decision="ask",
        code="local_path_dependency_source",
        message="Local path dependency requires review before install.",
        severity="medium",
    )


def _policy_package_result(target: dict[str, object], *, decision: str, rule_id: str) -> dict[str, object]:
    return {
        "decision": decision,
        "ecosystem": target["ecosystem"],
        "name": target["name"],
        "namespace": target["namespace"],
        "requestedVersion": _eval._optional_string(target.get("version"))
        or _eval._optional_string(target.get("range")),
        "resolvedVersion": _eval._optional_string(target.get("version")),
        "recommendedFixVersion": None,
        "riskScore": None,
        "direct": True,
        "dependencyPath": None,
        "packageManager": _eval._optional_string(target.get("package_manager")) or "npm",
        "redactedCommand": _eval._optional_string(target.get("redacted_command")),
        "alias": _eval._optional_string(target.get("alias")),
        "ruleId": rule_id,
        "reasons": (
            {
                "code": "policy_override",
                "message": f"Local synced policy rule {rule_id} matched this package request.",
                "severity": "low",
                "source": "policy",
            },
        ),
    }


def _package_from_cloud_result(item: dict[str, object]) -> dict[str, object]:
    dependency_path = _eval._optional_string(item.get("dependencyPath"))
    direct_value = item.get("direct")
    direct = direct_value if isinstance(direct_value, bool) else dependency_path is None
    return {
        "decision": _eval._normalize_bundle_action(str(item.get("decision") or "monitor")),
        "ecosystem": str(item.get("ecosystem") or "npm"),
        "name": str(item.get("name") or "unknown"),
        "namespace": _eval._optional_string(item.get("namespace")),
        "requestedVersion": _eval._optional_string(item.get("requestedVersion")),
        "resolvedVersion": _eval._optional_string(item.get("resolvedVersion")),
        "recommendedFixVersion": _eval._optional_string(item.get("recommendedFixVersion")),
        "riskScore": item.get("riskScore"),
        "direct": direct,
        "dependencyPath": dependency_path,
        "reasons": _eval._dict_items(item.get("reasons")),
    }


def _package_target_result(
    target: dict[str, object],
    *,
    decision: str,
    reasons: tuple[dict[str, object], ...],
    rule_id: str | None = None,
) -> dict[str, object]:
    result = {
        "decision": decision,
        "ecosystem": target["ecosystem"],
        "name": target["name"],
        "namespace": target["namespace"],
        "requestedVersion": _eval._optional_string(target.get("range"))
        or _eval._optional_string(target.get("version")),
        "resolvedVersion": _eval._optional_string(target.get("version")),
        "recommendedFixVersion": None,
        "riskScore": None,
        "direct": True,
        "dependencyPath": None,
        "packageManager": _eval._optional_string(target.get("package_manager")) or "npm",
        "redactedCommand": _eval._optional_string(target.get("redacted_command")),
        "alias": _eval._optional_string(target.get("alias")),
    }
    if rule_id is not None:
        result["ruleId"] = rule_id
    result["reasons"] = reasons
    return result


def _unknown_package_result(
    target: dict[str, object],
    *,
    fail_closed_unidentified: bool = False,
    identity_resolved: bool = False,
) -> dict[str, object]:
    ecosystem = _eval._optional_string(target.get("ecosystem")) or "npm"
    decision = _eval._unidentified_package_decision(
        ecosystem,
        fail_closed=fail_closed_unidentified,
        identity_resolved=identity_resolved,
    )
    requires_review = decision in {"ask", "block"}
    package_name = str(target.get("name") or "this package")
    no_match_message = (
        (
            f"Local Guard does not have enough current information to automatically allow {package_name}. "
            "Review this install now. Guard Cloud is optional and can add live package reputation."
        )
        if requires_review
        else "Guard recorded this package request and will keep watching for new intelligence."
    )
    reasons: list[dict[str, object]] = [
        {
            "code": "no_cached_match",
            "message": no_match_message,
            "severity": "high" if decision == "block" else ("medium" if requires_review else "unknown"),
            "source": "guard-local",
        },
    ]
    if requires_review:
        reasons.append(
            {
                "code": "unidentified_package",
                "message": (
                    f"Local checks could not confirm current safety details for {target['name']}. "
                    "This does not mean the package is unsafe; approve it once if you trust it."
                ),
                "severity": "medium",
                "source": "guard-local",
            }
        )
    return _eval._package_target_result(target, decision=decision, reasons=tuple(reasons))


def _fallback_package_results(
    *,
    targets: tuple[dict[str, object], ...],
    artifact: _eval.GuardArtifact,
    workspace_dir: _eval.Path | None,
    fail_closed_unidentified: bool = False,
    verify_registry_identity: bool = False,
) -> tuple[dict[str, object], ...]:
    bun_fallback_packages = _eval._bun_lockfile_binary_fallback_packages(
        targets=targets,
        artifact=artifact,
        workspace_dir=workspace_dir,
        fail_closed_unidentified=fail_closed_unidentified,
    )
    if bun_fallback_packages:
        return tuple(bun_fallback_packages)
    lockfile_versions = _eval._lockfile_dependency_versions(workspace_dir, artifact, targets)
    flags = set(_eval._string_tuple(artifact.metadata.get("flags")))
    return tuple(
        _eval._unknown_package_result(
            target,
            fail_closed_unidentified=fail_closed_unidentified,
            identity_resolved=(
                (
                    _eval._optional_string(target.get("ecosystem")) == "npm"
                    and "--ignore-scripts" in flags
                    and _eval._lockfile_target_key(target) in lockfile_versions
                )
                or (
                    verify_registry_identity
                    and (requested_range := _eval._optional_string(target.get("range"))) is not None
                    and _eval._registry_resolved_target_version(target=target, requested_range=requested_range)
                    is not None
                )
            ),
        )
        for target in targets
    )


def _bun_lockfile_binary_fallback_packages(
    *,
    targets: tuple[dict[str, object], ...],
    artifact: _eval.GuardArtifact,
    workspace_dir: _eval.Path | None,
    fail_closed_unidentified: bool = False,
) -> list[dict[str, object]]:
    if workspace_dir is None:
        return []
    lockfile_paths = artifact.metadata.get("lockfile_paths")
    if not isinstance(lockfile_paths, list):
        return []
    bun_lock_path = next(
        (
            resolved
            for relative_path in lockfile_paths
            if _eval.Path(str(relative_path)).name == "bun.lockb"
            and (resolved := _eval.resolve_path_within_workspace(workspace_dir, str(relative_path))) is not None
            and _eval.path_exists_within_workspace(workspace_dir, str(relative_path))
        ),
        None,
    )
    if bun_lock_path is None:
        return []
    message = "Guard could not verify package identity from Bun's binary lockfile (bun.lockb)."
    if targets:
        return [
            _eval._heuristic_package_result(
                target=target,
                decision=_eval._unidentified_package_decision(
                    _eval._optional_string(target.get("ecosystem")) or "npm",
                    fail_closed=fail_closed_unidentified,
                ),
                code="bun_lockfile_binary_fallback",
                message=f"{message} Approval is required before install.",
                severity="high" if fail_closed_unidentified else "medium",
            )
            for target in targets
        ]
    decision = _eval._unidentified_package_decision("npm", fail_closed=fail_closed_unidentified)
    return [
        _eval._heuristic_package_result(
            target={"ecosystem": "npm", "name": "workspace", "namespace": None, "package_manager": "bun"},
            decision=decision,
            code="bun_lockfile_binary_fallback",
            message=f"{message} Approval is required before install.",
            severity="high" if decision == "block" else "medium",
        )
    ]


def _recommended_fix_allow_package_result(
    *,
    target: dict[str, object],
    resolved_version: str,
    bundle_response: _eval.SupplyChainBundleResponse,
) -> dict[str, object] | None:
    for package in _eval._bundle_packages_for_target(bundle_response, target):
        if package.version == resolved_version:
            continue
        if package.recommended_fix_version != resolved_version:
            continue
        return {
            "decision": "allow",
            "ecosystem": package.ecosystem,
            "name": target["name"],
            "namespace": target["namespace"],
            "requestedVersion": _eval._optional_string(target.get("range")) or resolved_version,
            "resolvedVersion": resolved_version,
            "recommendedFixVersion": None,
            "riskScore": None,
            "direct": True,
            "dependencyPath": None,
            "packageManager": _eval._optional_string(target.get("package_manager")) or "npm",
            "redactedCommand": _eval._optional_string(target.get("redacted_command")),
            "alias": _eval._optional_string(target.get("alias")),
            "reasons": (
                {
                    "code": "recommended_fix_version",
                    "message": (
                        f"Requested version {resolved_version} matches Guard's recommended fix for "
                        f"{_eval._package_display_name(target)}."
                    ),
                    "severity": "low",
                    "source": "bundle",
                },
            ),
        }
    return None


# Resolve the facade after declarations so direct helper imports retain the cycle.
from . import supply_chain_package_eval as _eval  # noqa: E402
