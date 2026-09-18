"""Bundle loading keeps one validation pass and the existing duplicate contract."""

from __future__ import annotations

from dataclasses import replace

import pytest

from codex_plugin_scanner.guard.runtime import supply_chain_bundle_models as models
from codex_plugin_scanner.guard.runtime import supply_chain_bundle_package_identity as identity_projection
from tests.test_guard_supply_chain_bundle import _bundle_dict, _package_record


def test_unique_bundle_validates_each_canonical_identity_once(monkeypatch) -> None:
    payload = _bundle_dict()
    payload["packages"] = [_package_record(name="a", namespace=None), _package_record(name="b", namespace=None)]
    observations = []
    original = models.canonical_package_identity

    def observe(**kwargs):
        observations.append(kwargs)
        return original(**kwargs)

    monkeypatch.setattr(models, "canonical_package_identity", observe)
    monkeypatch.setattr(identity_projection, "canonical_package_identity", observe)
    bundle = models.SupplyChainBundle.from_dict(payload)
    assert [entry["name"] for entry in observations] == ["a", "b"]
    assert [package.name for package in bundle.packages] == ["a", "b"]


def test_parsed_duplicates_preserve_all_public_fields_and_compact_order() -> None:
    unique = _bundle_dict()
    a, b = _package_record(name="a", namespace=None), _package_record(name="b", namespace=None)
    unique["packages"] = [a, b]
    duplicate = {**unique, "packages": [a, dict(a), b, dict(b), dict(a)]}
    expected = models.SupplyChainBundle.from_dict(unique)
    actual = models.SupplyChainBundle.from_dict(duplicate)
    assert actual.to_dict() == expected.to_dict()
    assert actual.package_index == expected.package_index
    assert tuple(actual.package_index.positions.values()) == (0, 1)


def test_direct_construction_retains_duplicate_records_until_payload_parsing() -> None:
    bundle = models.SupplyChainBundle.from_dict(_bundle_dict())
    package = bundle.packages[0]
    direct = replace(bundle, packages=(package, package))
    assert direct.packages == (package, package)
    assert len(next(iter(direct.package_index.by_name.values()))) == 2
    reparsed = models.SupplyChainBundle.from_dict(direct.to_dict())
    assert reparsed.to_dict() == bundle.to_dict()
    assert reparsed.package_index == bundle.package_index


def test_multiple_malformed_fields_keep_error_family_and_complete_public_fallback(tmp_path, monkeypatch) -> None:
    from codex_plugin_scanner.guard.runtime import supply_chain_package_eval as evaluator
    from codex_plugin_scanner.guard.store import GuardStore
    from tests.test_guard_supply_chain_evaluator import (
        WORKSPACE_ID,
        _artifact_for_targets,
        _bundle_response,
        _cloud_response,
        _seed_guard_cloud,
    )

    package = _package_record(name="left-pad", namespace=None)
    conflict = {**package, "riskScore": package["riskScore"] + 1}
    response = _bundle_response(packages=[package, conflict])
    response["bundle"]["advisories"] = [{"exploitLevel": "invalid"}]
    parsed_packages = tuple(models.SupplyChainBundlePackage.from_dict(item) for item in (package, conflict))
    with pytest.raises(models.SupplyChainBundleMalformedError, match="Conflicting package records"):
        identity_projection._deduplicate_bundle_packages(parsed_packages)
    with pytest.raises(models.SupplyChainBundleMalformedError, match="Unsupported advisory exploitLevel"):
        models.SupplyChainBundle.from_dict(response["bundle"])

    # Earlier code encountered the canonical conflict before parsing advisories.
    # The evaluator intentionally catches the error family, never publishing its
    # detailed text. Compare every public result and persisted evidence field.
    original_loader = evaluator.load_supply_chain_bundle_response

    def legacy_validation_order(payload):
        identity_projection._deduplicate_bundle_packages(parsed_packages)
        return original_loader(payload)

    monkeypatch.setattr(
        evaluator,
        "_urlopen_json_with_timeout_retry",
        lambda *_args, **_kwargs: _cloud_response(
            decision="monitor", enforcement="premium_cloud", entitlement_state="active", package_name="left-pad"
        ),
    )
    outcomes = []
    for index, loader in enumerate((legacy_validation_order, original_loader)):
        store = GuardStore(tmp_path / str(index))
        _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
        monkeypatch.setattr(store, "get_cached_supply_chain_bundle", lambda _workspace_id: response)
        monkeypatch.setattr(evaluator, "load_supply_chain_bundle_response", loader)
        result = evaluator.evaluate_package_request_artifact(
            artifact=_artifact_for_targets("left-pad@1.0.0"),
            store=store,
            workspace_dir=tmp_path / "workspace",
            now="2026-05-19T00:00:00Z",
        )
        with store._connect() as connection:
            evidence = [dict(row) for row in connection.execute("select * from guard_evidence order by evidence_id")]
        outcomes.append((result.to_dict(), evidence))
    assert outcomes[0] == outcomes[1]
