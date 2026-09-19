"""Cached package bundle evaluation and advisory matching."""

from __future__ import annotations


def _evaluate_with_bundle(
    *,
    artifact: _eval.GuardArtifact,
    targets: tuple[dict[str, object], ...],
    bundle_response,
    workspace_dir: _eval.Path | None,
    workspace_id: str | None,
    now_timestamp: float | None,
) -> _eval._EvaluationDraft | None:
    bundle_meta = _eval._bundle_meta(bundle_response.to_dict())
    refresh_required = False
    packages: list[dict[str, object]] = []
    lockfile_versions = _eval._lockfile_dependency_versions(workspace_dir, artifact, targets)
    for target in targets:
        if target.get("manifest_unsynced") is True:
            packages.append(
                _eval._heuristic_package_result(
                    target=target,
                    decision="ask",
                    code="manifest_lockfile_unsynced",
                    message=(
                        f"{target['package_name']} is declared in the project manifest but is not pinned "
                        "in the existing lockfile yet, so Guard requires review before install."
                    ),
                    severity="high",
                )
            )
            continue
        resolved_version = _eval._resolved_target_version(
            target=target,
            lockfile_versions=lockfile_versions,
        )
        package_match = (
            _eval._bundle_package(
                bundle_response,
                target=target,
                package_version=resolved_version,
            )
            if resolved_version is not None
            else None
        )
        resolved_npm_version = (
            resolved_version if (_eval._optional_string(target.get("ecosystem")) or "npm") == "npm" else None
        )
        policy_target = _eval.target_for_resolved_npm_policy_match(target, resolved_version=resolved_npm_version)
        matched_rule = _eval._matching_policy_rule(
            bundle_response.bundle.policy_rules,
            target=policy_target,
            harness=artifact.harness,
            package_severity=package_match.normalized_severity if package_match is not None else None,
        )
        if matched_rule is not None:
            decision = _eval._normalize_bundle_action(matched_rule.action)
            package = _eval.bind_resolved_npm_policy_result(
                _eval._policy_package_result(target, decision=decision, rule_id=matched_rule.rule_id),
                resolved_version=resolved_npm_version,
            )
            packages.append(package)
            continue
        confusion_result = _eval._dependency_confusion_policy_package_result(
            bundle_response.bundle.policy_rules,
            target=target,
        )
        if confusion_result is not None:
            packages.append(confusion_result)
            continue
        if resolved_version is None:
            continue
        offline = _eval.evaluate_cached_supply_chain_bundle(
            bundle_response,
            package_name=str(target["normalized_name"]),
            package_version=resolved_version,
            ecosystem=_eval._optional_string(target.get("ecosystem")) or "npm",
            now=now_timestamp,
        )
        if offline.emergency_deny and offline.action == "block":
            packages.append(
                _eval._heuristic_package_result(
                    target=target,
                    decision="block",
                    code=offline.reason,
                    message=_eval._emergency_deny_bundle_message(
                        target=target,
                        resolved_version=resolved_version,
                        reason=offline.reason,
                    ),
                    severity="critical",
                    resolved_version=resolved_version,
                    recommended_fix_version=offline.recommended_fix_version,
                )
            )
            continue
        if package_match is None:
            if offline.action == "block":
                packages.append(
                    _eval._heuristic_package_result(
                        target=target,
                        decision="block",
                        code=offline.reason,
                        message=_eval._emergency_deny_bundle_message(
                            target=target,
                            resolved_version=resolved_version,
                            reason=offline.reason,
                        ),
                        severity="critical",
                        resolved_version=resolved_version,
                        recommended_fix_version=offline.recommended_fix_version,
                    )
                )
                continue
            safe_allow = _eval._recommended_fix_allow_package_result(
                target=target,
                resolved_version=resolved_version,
                bundle_response=bundle_response,
            )
            if safe_allow is not None:
                packages.append(safe_allow)
            continue
        refresh_required = refresh_required or offline.stale
        package = _eval._bundle_package_result(
            target=target,
            bundle_response=bundle_response,
            package=package_match,
            decision=_eval._normalize_bundle_action(offline.action),
            reason=offline.reason,
            stale=offline.stale,
            resolved_version=resolved_version,
        )
        packages.append(package)
    direct_identities = {_eval._result_package_identity(package) for package in packages}
    packages.extend(
        package
        for package in _eval._transitive_lockfile_results(
            bundle_response=bundle_response,
            artifact=artifact,
            workspace_dir=workspace_dir,
            now_timestamp=now_timestamp,
        )
        if _eval.package_has_incomplete_lockfile(package)
        or _eval._result_package_identity(package) not in direct_identities
    )
    if not packages:
        return None
    packages.sort(key=lambda item: _eval._decision_rank(str(item.get("decision") or "monitor")), reverse=True)
    decision = str(packages[0].get("decision") or "monitor")
    winning_rule_id = _eval._optional_string(packages[0].get("ruleId"))
    return _eval._EvaluationDraft(
        decision=decision,
        enforcement="policy_override" if winning_rule_id is not None else "offline_cached",
        entitlement_state="premium" if workspace_id is not None else "free",
        cache_status="stale" if refresh_required else "miss",
        packages=tuple(packages),
        reasons=tuple(reason for package in packages for reason in _eval._dict_items(package.get("reasons"))),
        matched_rule_id=winning_rule_id,
        exception_id=winning_rule_id if decision == "allow" else None,
        refresh_required=refresh_required,
        record_monitor_evidence=decision == "monitor",
        bundle_version=bundle_meta["bundle_version"],
        policy_version=bundle_meta["policy_hash"],
    )


def _primary_bundle_advisory_id(
    bundle_response: _eval.SupplyChainBundleResponse,
    package: _eval.SupplyChainBundlePackage,
) -> str | None:
    if not package.related_advisory_ids:
        return None
    advisory_lookup: dict[str, str] = {}
    for advisory in bundle_response.bundle.advisories:
        advisory_lookup[advisory.advisory_id] = advisory.advisory_id
        for alias in advisory.aliases:
            advisory_lookup.setdefault(alias, advisory.advisory_id)
    for advisory_id in package.related_advisory_ids:
        canonical_id = advisory_lookup.get(advisory_id)
        if canonical_id is not None:
            return canonical_id
    return package.related_advisory_ids[0]


def _bundle_advisory_aliases(
    bundle_response: _eval.SupplyChainBundleResponse,
    package: _eval.SupplyChainBundlePackage,
) -> list[str]:
    advisory_ids = list(package.related_advisory_ids)
    primary_id = _eval._primary_bundle_advisory_id(bundle_response, package)
    if primary_id is not None and primary_id not in advisory_ids:
        advisory_ids.append(primary_id)
    if not advisory_ids:
        return []
    advisory_lookup: dict[str, tuple[str, ...]] = {}
    for advisory in bundle_response.bundle.advisories:
        alias_tuple = (advisory.advisory_id, *advisory.aliases)
        upper_tuple = tuple(alias.upper() for alias in alias_tuple)
        advisory_lookup[advisory.advisory_id.upper()] = upper_tuple
        for alias in alias_tuple:
            advisory_lookup.setdefault(alias.upper(), upper_tuple)
    aliases: list[str] = []
    seen: set[str] = set()
    for advisory_id in advisory_ids:
        for alias in advisory_lookup.get(advisory_id.upper(), (advisory_id.upper(),)):
            if alias in seen:
                continue
            seen.add(alias)
            aliases.append(alias)
    return aliases


def _bundle_meta(bundle_payload: dict[str, object]) -> dict[str, str]:
    bundle = bundle_payload["bundle"]
    assert isinstance(bundle, dict)
    return {
        "bundle_version": str(bundle["bundleVersion"]),
        "feed_snapshot_hash": str(bundle["feedSnapshotHash"]),
        "policy_hash": str(bundle["policyHash"]),
        "scoring_version": str(bundle["scoringVersion"]),
    }


def _bundle_package_versions(bundle_response: _eval.SupplyChainBundleResponse, target: dict[str, object]) -> list[str]:
    return [item.version for item in _eval._bundle_packages_for_target(bundle_response, target)]


def _bundle_packages_for_target(
    bundle_response: _eval.SupplyChainBundleResponse, target: dict[str, object]
) -> tuple[_eval.SupplyChainBundlePackage, ...]:
    index = bundle_response.bundle.package_index
    target_ecosystem = _eval._optional_string(target.get("ecosystem"))
    ecosystems = index.ecosystems if target_ecosystem is None else (target_ecosystem,)
    matches: list[_eval.SupplyChainBundlePackage] = []
    for ecosystem in ecosystems:
        try:
            identity = _eval.canonical_package_identity(
                ecosystem=ecosystem,
                namespace=_eval._optional_string(target.get("namespace")),
                name=str(target["name"]),
                version="*",
            )
        except _eval.PackageIdentityError:
            continue
        matches.extend(index.by_name.get(identity, ()))
    if target_ecosystem is None and len(ecosystems) > 1:
        # Legacy ecosystem-less callers use signed order across ecosystems.
        matches.sort(
            key=lambda package: index.positions[
                _eval.canonical_package_identity(
                    ecosystem=package.ecosystem, namespace=package.namespace, name=package.name, version=package.version
                )
            ]
        )
    return tuple(matches)


def _bundle_package_name_matches(package: _eval.SupplyChainBundlePackage, target: dict[str, object]) -> bool:
    target_ecosystem = _eval._optional_string(target.get("ecosystem"))
    if target_ecosystem is not None and package.ecosystem != _eval.normalize_ecosystem(target_ecosystem):
        return False
    try:
        # Bundle ingestion has already canonicalized package fields; the target
        # remains case-sensitive for ecosystems such as Go.
        package_identity = _eval.canonical_package_identity(
            ecosystem=package.ecosystem,
            namespace=package.namespace,
            name=package.name,
            version="*",
        )
        target_identity = _eval.canonical_package_identity(
            ecosystem=target_ecosystem or package.ecosystem,
            namespace=_eval._optional_string(target.get("namespace")),
            name=str(target["name"]),
            version="*",
        )
    except _eval.PackageIdentityError:
        return False
    return package_identity == target_identity


def _matching_policy_rule(
    rules: tuple[_eval.SupplyChainBundlePolicyRule, ...],
    *,
    target: dict[str, object],
    harness: str,
    package_severity: str | None,
) -> _eval.SupplyChainBundlePolicyRule | None:
    current_time = _eval.datetime.now(_eval.timezone.utc).timestamp()
    sorted_rules = sorted(
        rules, key=lambda item: (item.priority if item.priority is not None else 10_000, item.rule_id)
    )
    for rule in sorted_rules:
        if rule.enabled is False:
            continue
        if rule.expires_at is not None:
            try:
                if _eval.datetime.fromisoformat(rule.expires_at.replace("Z", "+00:00")).timestamp() <= current_time:
                    continue
            except ValueError:
                pass
        if rule.harness_selector not in {None, "*", harness}:
            continue
        if rule.ecosystem_selector is not None and rule.ecosystem_selector != target["ecosystem"]:
            continue
        if rule.package_selector is not None:
            selector = rule.package_selector.strip().lower()
            candidates = {
                str(target["normalized_name"]),
                str(target["name"]).lower(),
                f"{target['namespace']}/{target['name']}".lower()
                if target["namespace"] is not None
                else str(target["name"]).lower(),
                f"pkg:{target['ecosystem']}/{target['normalized_name']}",
            }
            if selector not in candidates:
                continue
        if rule.version_range_selector is not None and not _eval.policy_selector_matches_target(
            rule.version_range_selector,
            target,
        ):
            continue
        if rule.severity_threshold is not None:
            if package_severity is None:
                continue
            if _eval._severity_rank_value(package_severity) < _eval._severity_rank_value(rule.severity_threshold):
                continue
        return rule
    return None


def _bundle_package(
    bundle_response: _eval.SupplyChainBundleResponse,
    *,
    target: dict[str, object],
    package_version: str,
) -> _eval.SupplyChainBundlePackage | None:
    index = bundle_response.bundle.package_index
    target_ecosystem = _eval._optional_string(target.get("ecosystem"))
    selected: tuple[int, _eval.SupplyChainBundlePackage] | None = None
    for ecosystem in index.ecosystems if target_ecosystem is None else (target_ecosystem,):
        try:
            identity = _eval.canonical_package_identity(
                ecosystem=ecosystem,
                namespace=_eval._optional_string(target.get("namespace")),
                name=str(target["name"]),
                version=package_version,
            )
        except _eval.PackageIdentityError:
            continue
        item = index.exact.get(identity)
        if item is not None and item.version == package_version:
            position = index.positions[identity]
            if selected is None or position < selected[0]:
                selected = (position, item)
    return selected[1] if selected is not None else None


def _severity_rank_value(value: str) -> int:
    return _eval._SEVERITY_RANK.get(value.strip().lower(), _eval._SEVERITY_RANK["unknown"])


def _normalize_bundle_action(value: str) -> str:
    if value == "review":
        return "ask"
    if value in _eval._DECISION_RANK:
        return value
    return "monitor"


def _emergency_deny_bundle_message(
    *,
    target: dict[str, object],
    resolved_version: str,
    reason: str,
) -> str:
    package_label = f"{_eval._package_display_name(target)}@{resolved_version}"
    if reason == "known_malware":
        return f"Emergency denylist blocked {package_label} for known malware."
    if reason == "known_exploited":
        return f"Emergency denylist blocked {package_label} because it is a known exploited vulnerability."
    if reason == "critical_active_exploit":
        return f"Emergency denylist blocked {package_label} for a critical active exploit."
    return f"Emergency denylist blocked {package_label}."


def _bundle_reason_message(
    package: _eval.SupplyChainBundlePackage,
    *,
    decision: str,
    reason: str,
    stale: bool,
) -> str:
    package_label = _eval._bundle_package_label(package)
    if stale:
        if decision == "block":
            return f"Cached bundle is stale, but Guard still blocked {package_label} from advisory intelligence."
        if decision == "ask":
            return f"Cached bundle is stale, so Guard still requires approval for {package_label}."
        if decision == "warn":
            return f"Cached bundle is stale, so Guard still warns on {package_label}."
        return f"Cached bundle is stale, so Guard kept {package_label} in monitor mode."
    if reason == "known_malware_or_kev":
        return f"Cached bundle flagged {package_label} from advisory intelligence."
    if reason == "maintainer_compromise":
        return f"Cached bundle flagged {package_label} for probable maintainer compromise."
    return f"Cached bundle matched {package_label}."


def _bundle_package_label(package: _eval.SupplyChainBundlePackage, *, version: str | None = None) -> str:
    package_name = f"{package.namespace}/{package.name}" if package.namespace is not None else package.name
    return f"{package_name}@{version or package.version}"


# Resolve the facade after declarations so direct helper imports retain the cycle.
from . import supply_chain_package_eval as _eval  # noqa: E402
