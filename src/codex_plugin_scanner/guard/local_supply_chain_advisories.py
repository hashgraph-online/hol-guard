"""Advisories helpers using the original live supply-chain namespace."""

from __future__ import annotations


def _package_advisory_ids(package: dict[str, object]) -> list[str]:
    advisory_ids: list[str] = []
    seen: set[str] = set()

    def add_id(value: object) -> None:
        if not isinstance(value, str):
            return
        trimmed = value.strip()
        if not trimmed or trimmed in seen:
            return
        seen.add(trimmed)
        advisory_ids.append(trimmed)

    for key in ("advisoryIds", "advisory_ids", "relatedAdvisoryIds", "related_advisory_ids"):
        raw = package.get(key)
        if isinstance(raw, list):
            for entry in raw:
                add_id(entry)
    add_id(package.get("advisoryId"))
    add_id(package.get("advisory_id"))
    reasons = package.get("reasons")
    if isinstance(reasons, list):
        for reason in reasons:
            if not isinstance(reason, dict):
                continue
            add_id(reason.get("advisoryId"))
            add_id(reason.get("advisory_id"))
    return advisory_ids


def _cached_supply_chain_bundle_payload(store: _api.Any) -> dict[str, object] | None:
    workspace_id = store.get_cloud_workspace_id()
    if workspace_id is None:
        return None
    cached_bundle = store.get_cached_supply_chain_bundle(workspace_id)
    if not isinstance(cached_bundle, dict):
        return None
    bundle_payload = cached_bundle.get("bundle")
    if isinstance(bundle_payload, dict):
        return bundle_payload
    return None


def _resolve_advisory_aliases_from_bundle(
    bundle: dict[str, object] | None,
    advisory_ids: list[str],
) -> list[str]:
    aliases: list[str] = []
    seen: set[str] = set()
    lookup: dict[str, tuple[str, ...]] = {}
    if isinstance(bundle, dict):
        advisories = bundle.get("advisories")
        if isinstance(advisories, list):
            for advisory in advisories:
                if not isinstance(advisory, dict):
                    continue
                advisory_id = advisory.get("advisoryId")
                if not isinstance(advisory_id, str) or not advisory_id.strip():
                    continue
                raw_aliases = advisory.get("aliases")
                alias_tuple: tuple[str, ...] = (advisory_id,)
                if isinstance(raw_aliases, list):
                    alias_tuple = (
                        advisory_id,
                        *[alias for alias in raw_aliases if isinstance(alias, str) and alias.strip()],
                    )
                upper_tuple = tuple(alias.upper() for alias in alias_tuple)
                lookup[advisory_id.upper()] = upper_tuple
                for alias in alias_tuple:
                    lookup.setdefault(alias.upper(), upper_tuple)

    def add_alias(value: str) -> None:
        trimmed = value.strip().upper()
        if not trimmed or trimmed in seen:
            return
        seen.add(trimmed)
        aliases.append(trimmed)

    for advisory_id in advisory_ids:
        add_alias(advisory_id)
        resolved = lookup.get(advisory_id.upper())
        if resolved is None:
            continue
        for alias in resolved:
            add_alias(alias)
    return aliases


def _enrich_package_with_advisory_aliases(
    package: dict[str, object],
    *,
    bundle: dict[str, object] | None,
) -> dict[str, object]:
    existing_aliases = package.get("advisoryAliases")
    if isinstance(existing_aliases, list) and existing_aliases:
        return package
    advisory_ids = _api._package_advisory_ids(package)
    if not advisory_ids:
        return package
    aliases = _api._resolve_advisory_aliases_from_bundle(bundle, advisory_ids)
    if not aliases:
        return package
    enriched = dict(package)
    enriched["advisoryAliases"] = aliases
    return enriched


def _enrich_evaluation_packages_with_advisory_aliases(
    evaluation: dict[str, object],
    store: _api.Any,
) -> dict[str, object]:
    packages = evaluation.get("packages")
    if not isinstance(packages, list):
        return evaluation
    bundle = _api._cached_supply_chain_bundle_payload(store)
    enriched_packages: list[dict[str, object]] = []
    for package in packages:
        if not isinstance(package, dict):
            continue
        enriched_packages.append(_api._enrich_package_with_advisory_aliases(package, bundle=bundle))
    return {**evaluation, "packages": enriched_packages}


def _package_reason_codes(item: dict[str, object]) -> frozenset[str]:
    reasons = item.get("reasons")
    if not isinstance(reasons, list):
        return frozenset()
    codes: set[str] = set()
    for reason in reasons:
        if not isinstance(reason, dict):
            continue
        code = str(reason.get("code") or "").strip()
        if code:
            codes.add(code)
    return frozenset(codes)


def _is_actionable_package_finding(item: dict[str, object]) -> bool:
    decision = str(item.get("decision") or "monitor")
    if decision in {"block", "ask", "warn"}:
        return True
    reason_codes = _api._package_reason_codes(item)
    if not reason_codes:
        return decision not in {"allow", "monitor"}
    return not reason_codes.issubset(_api._INFORMATIONAL_REASON_CODES)


# Bind after declarations so importing this owner directly preserves the facade cycle.
from . import local_supply_chain as _api  # noqa: E402
