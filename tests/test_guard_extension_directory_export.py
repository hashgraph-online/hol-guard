"""The public artifact describes native source, never changes its authority."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.extension_builder.errors import BuilderError
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_trust import trust_class_for
from tests.extension_builder_support import REPOSITORY

spec = importlib.util.spec_from_file_location(
    "guard_directory_export", REPOSITORY / "scripts/export_extension_directory.py"
)
assert spec and spec.loader
exporter = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = exporter
spec.loader.exec_module(exporter)


def test_export_is_deterministic_and_current() -> None:
    first = exporter.render_directory()
    assert first == exporter.render_directory()
    assert first == (REPOSITORY / "docs/guard/extensions/catalog.v1.json").read_text()
    payload = json.loads(first)
    assert payload["schemaVersion"] == "guard.extension-directory.v1"
    ids = [row["id"] for row in payload["entries"]]
    assert ids == sorted(set(ids))
    v2 = exporter.render_directory_v2()
    assert v2 == exporter.render_directory_v2()
    assert v2 == (REPOSITORY / "docs/guard/extensions/catalog.v2.json").read_text()
    assert json.loads(v2)["schemaVersion"] == "guard.extension-directory.v2"


def test_paired_directory_render_uses_one_validated_source_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    source_calls = 0
    listing_calls = 0
    original_sources = exporter._sources
    original_listings = exporter._listings

    def sources(root: Path) -> dict[str, tuple[str, dict[str, object], str]]:
        nonlocal source_calls
        source_calls += 1
        return original_sources(root)

    def listings(
        root: Path, sources: dict[str, tuple[str, dict[str, object], str]]
    ) -> dict[str, tuple[str, dict[str, object], str]]:
        nonlocal listing_calls
        listing_calls += 1
        return original_listings(root, sources)

    monkeypatch.setattr(exporter, "_sources", sources)
    monkeypatch.setattr(exporter, "_listings", listings)
    rendered = exporter.render_directories()
    assert (source_calls, listing_calls) == (1, 1)
    assert rendered[exporter.OUTPUT_V1] == (REPOSITORY / "docs/guard/extensions/catalog.v1.json").read_text()
    assert rendered[exporter.OUTPUT_V2] == (REPOSITORY / "docs/guard/extensions/catalog.v2.json").read_text()


def test_public_directory_bytes_use_lf_checkout_for_stable_public_digests() -> None:
    attributes = (REPOSITORY / ".gitattributes").read_text()
    assert "/contributions/command-sources/*.json text eol=lf" in attributes
    assert "/docs/guard/extensions/catalog.v1.json text eol=lf" in attributes
    assert "/docs/guard/extensions/catalog.v2.json text eol=lf" in attributes


def test_every_native_extension_appears_once_with_unchanged_authority() -> None:
    native = {row.extension_id: row for row in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions}
    entries = exporter.export_directory()["entries"]
    assert {row["runtimeExtensionId"] for row in entries} == set(native)
    for row in entries:
        extension = native[row["runtimeExtensionId"]]
        assert row["trustClass"] == trust_class_for(extension.extension_id)
        assert row["ruleCount"] == len(extension.rules)
        assert row["permissionCount"] == len(extension.permissions)
        assert len(row["operations"]) == len(extension.rules)
        assert (row["claimPolicy"] == "provenance") == (row["trustClass"] == "external")
        if row["claimPolicy"] == "provenance":
            assert row["protectionModel"] == "external-opt-in"
            assert row["sourcePath"].startswith("contributions/")
            assert row["contributionDigest"].startswith("sha256:")
        assert "enabled" not in row and "safe" not in row and "rating" not in row
    for row in exporter.export_directory_v2()["entries"]:
        assert "contributors" in row and "listing" in row and "authoringSource" in row
        if row["kind"] == "command":
            assert row["authoringSource"]["path"].endswith(f"/{row['id']}.json")
            assert row["authoringSource"]["byteDigest"].startswith("sha256:")
        else:
            assert row["authoringSource"] is None


def test_mcp_entry_preserves_contribution_identity_and_inheritance() -> None:
    entries = exporter.export_directory()["entries"]
    row = next(row for row in entries if row["id"] == "mcp.filesystem")
    assert row["runtimeExtensionId"] == "command.mcp-filesystem"
    assert row["kind"] == "mcp"
    assert row["toolStates"][-1] == {"name": "other", "state": "inherit"}
    assert "command.mcp-filesystem" not in {entry["id"] for entry in entries}


def copy_sources(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    for directory in ("extensions", "mcp-servers", "command-sources"):
        shutil.copytree(REPOSITORY / "contributions" / directory, root / "contributions" / directory)
    (root / "contributions/extension-listings").mkdir()
    return root


def test_orphan_or_authoritative_listing_is_rejected(tmp_path: Path) -> None:
    root = copy_sources(tmp_path)
    path = root / "contributions/extension-listings/command.orphan.json"
    path.write_text("{}")
    with pytest.raises(ValueError, match="existing external"):
        exporter.export_directory(root)
    path.unlink()
    path = root / "contributions/extension-listings/command.blitcp.json"
    path.write_text(json.dumps({"extensionId": "command.blitcp", "activation": "default-on"}))
    with pytest.raises(BuilderError):
        exporter.export_directory(root)


def test_source_identity_mismatch_is_rejected(tmp_path: Path) -> None:
    root = copy_sources(tmp_path)
    source = root / "contributions/extensions/command.blitcp.json"
    source.rename(source.with_name("command.wrong-name.json"))
    with pytest.raises(ValueError):
        exporter.export_directory(root)


def test_public_directory_matches_cross_repository_contract() -> None:
    from jsonschema import Draft202012Validator

    schema = json.loads((REPOSITORY / "contracts/extensions/directory.v1.schema.json").read_text())
    Draft202012Validator(schema).validate(exporter.export_directory())
    catalog = exporter.export_directory()
    entry = dict(catalog["entries"][0])
    entry.pop("operations", None)
    Draft202012Validator(schema).validate({"schemaVersion": catalog["schemaVersion"], "entries": [entry]})
    v2_schema = json.loads((REPOSITORY / "contracts/extensions/directory.v2.schema.json").read_text())
    Draft202012Validator(v2_schema).validate(exporter.export_directory_v2())


def test_v2_listing_metadata_has_separate_credit_and_claim_authority(tmp_path: Path) -> None:
    root = copy_sources(tmp_path)
    listing_path = root / "contributions/extension-listings/command.blitcp.json"
    listing_path.write_text(
        json.dumps(
            {
                "schemaVersion": "guard.extension-listing.v2",
                "extensionId": "command.blitcp",
                "tagline": "Reviewed file-transfer operation coverage for blitcp.",
                "summary": "Reviews destructive file-transfer operations through a bounded native command contract.",
                "category": "other",
                "limitations": ["Coverage is limited to reviewed operations and the surrounding Guard policy."],
                "contributors": [{"githubId": "123", "githubLogin": "example-author", "roles": ["author"]}],
                "originalContributions": [
                    {"kind": "pull-request", "url": "https://github.com/hashgraph-online/hol-guard/pull/3020"}
                ],
                "upstream": {"name": "Blitcp", "url": "https://github.com/example/blitcp"},
            }
        )
    )
    row = next(item for item in exporter.export_directory_v2(root)["entries"] if item["id"] == "command.blitcp")
    assert row["contributors"] == [{"githubId": "123", "githubLogin": "example-author", "roles": ["author"]}]
    assert row["maintainerGithubIds"] == []
    assert row["listing"]["path"] == "contributions/extension-listings/command.blitcp.json"


def test_v2_directory_supplies_a_valid_summary_for_a_short_legacy_description(tmp_path: Path) -> None:
    root = copy_sources(tmp_path)
    contribution = root / "contributions/extensions/command.blitcp.json"
    payload = json.loads(contribution.read_text())
    payload["description"] = "Short description"
    contribution.write_text(json.dumps(payload))
    row = next(item for item in exporter.export_directory_v2(root)["entries"] if item["id"] == "command.blitcp")
    assert row["summary"] == "Reviewed Guard coverage for command.blitcp."


def test_claim_readiness_report_matches_claim_policy_invariants() -> None:
    report = exporter.claim_readiness()
    assert report["schemaVersion"] == "guard.extension-claim-readiness.v1"
    rows = report["entries"]
    assert len(rows) == len(exporter.export_directory()["entries"])
    provenance = [row for row in rows if row["claimPolicy"] == "provenance"]
    assert provenance, "expected at least one provenance entry in the canonical directory"
    for row in provenance:
        expected_eligible = row["acceptedGithubIdCount"] > 0
        assert row["invitationEligible"] is expected_eligible
        assert row["reason"] == ("eligible" if expected_eligible else "empty_accepted_set")
    for row in rows:
        if row["claimPolicy"] != "provenance":
            assert row["invitationEligible"] is False
            assert row["reason"] == "project_policy"


def test_valid_contribution_with_empty_accepted_set_is_not_invitation_eligible(tmp_path: Path) -> None:
    root = copy_sources(tmp_path)
    listing_path = root / "contributions/extension-listings/command.blitcp.json"
    listing_path.write_text(
        json.dumps(
            {
                "schemaVersion": "guard.extension-listing.v1",
                "extensionId": "command.blitcp",
                "tagline": "Reviewed file-transfer operation coverage for blitcp.",
                "category": "other",
                "limitations": ["Coverage is limited to the reviewed operations and the surrounding Guard policy."],
            }
        )
    )
    report = exporter.claim_readiness(root)
    row = next(item for item in report["entries"] if item["id"] == "command.blitcp")
    assert row["claimPolicy"] == "provenance"
    assert row["acceptedGithubIdCount"] == 0
    assert row["invitationEligible"] is False
    assert row["reason"] == "empty_accepted_set"
