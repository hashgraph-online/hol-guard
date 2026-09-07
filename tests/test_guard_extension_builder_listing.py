"""Listing metadata must remain inert and old contribution kits must replay."""

from __future__ import annotations

import hashlib
import json
import socket
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from codex_plugin_scanner.guard.extension_builder.errors import BuilderError
from codex_plugin_scanner.guard.extension_builder.kit import build_kit, load_kit, write_kit
from codex_plugin_scanner.guard.extension_builder.listing import (
    CATEGORY_LABELS,
    category_for_extension,
    listing_schema,
    listing_template,
    load_listing,
    validate_listing,
)
from codex_plugin_scanner.guard.extension_builder.repository_plan import managed_files, ownership_record
from tests.extension_builder_support import REPOSITORY, make_kit, metadata


def listing() -> dict[str, object]:
    return json.loads(listing_template(metadata()))


def test_listing_contract_is_packaged_byte_for_byte() -> None:
    source = REPOSITORY / "contracts/extensions/listing.v1.schema.json"
    packaged = REPOSITORY / "src/codex_plugin_scanner/guard/extension_builder/listing.v1.schema.json"
    assert source.read_bytes() == packaged.read_bytes()
    assert Draft202012Validator(listing_schema()).is_valid(listing())


@pytest.mark.parametrize("kind", ["cli", "mcp"])
def test_template_has_no_inferred_claim_or_runtime_authority(kind: str) -> None:
    row = json.loads(listing_template(metadata(kind)))  # type: ignore[arg-type]
    assert validate_listing(row, expected_id=row["extensionId"]) == row
    assert "maintainerGithubIds" not in row
    assert "activation" not in row
    assert "trustClass" not in row
    assert row["limitations"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("activation", "default-on"),
        ("trustClass", "first-party"),
        ("detector", "evil.py"),
        ("policy", {}),
        ("email", "private@example.test"),
        ("script", "alert(1)"),
        ("tagline", "short"),
        ("tagline", "x" * 141),
        ("tagline", "  untrimmed line  "),
        ("tagline", "a newline\nis invalid"),
        ("limitations", []),
        ("limitations", ["short"]),
        ("limitations", ["x" * 401]),
        ("limitations", ["a long limitation"] * 2),
        ("category", "certified-safe"),
        ("extensionId", "../../escape"),
        ("extensionId", "command.UPPER"),
        ("maintainerGithubIds", [123]),
        ("maintainerGithubIds", ["0"]),
        ("maintainerGithubIds", ["01"]),
        ("maintainerGithubIds", ["123", "123"]),
        ("maintainerGithubIds", ["9" * 21]),
        ("tags", ["Some Tag"]),
        ("tags", ["valid", "valid"]),
    ],
)
def test_rejects_invalid_or_authoritative_metadata(field: str, value: object) -> None:
    row = listing()
    row[field] = value
    with pytest.raises(BuilderError):
        validate_listing(row)


@pytest.mark.parametrize(
    "url",
    [
        "http://example.test",
        "javascript:alert(1)",
        "https://user:secret@example.test",
        "https://localhost/path",
        "https://127.0.0.1/",
        "https://[::1]/",
        "https://169.254.169.254/latest",
        "https://example.internal/",
        "https://example.test:8443/",
        "https://example.test\\@attacker.test/",
        "https://example.test/\nsecret",
        "https://intranet/",
    ],
)
def test_rejects_private_or_unsafe_links(url: str) -> None:
    row = listing()
    row["documentationUrl"] = url
    with pytest.raises(BuilderError):
        validate_listing(row)


def test_numeric_maintainers_are_reviewed_data_not_implicit_authority() -> None:
    row = listing()
    row["maintainerGithubIds"] = ["123", "99999999999999999999"]
    assert validate_listing(row)["maintainerGithubIds"] == row["maintainerGithubIds"]
    with pytest.raises(BuilderError):
        validate_listing(row, expected_id="command.someone-else")


def test_rejects_duplicate_json_keys_and_filename_mismatch(tmp_path: Path) -> None:
    path = tmp_path / "command.builder-demo.json"
    path.write_text('{"schemaVersion":"guard.extension-listing.v1","schemaVersion":"other"}', encoding="utf-8")
    with pytest.raises(BuilderError):
        load_listing(path, expected_id="command.builder-demo")
    path.write_text(json.dumps(listing()), encoding="utf-8")
    with pytest.raises(BuilderError):
        load_listing(path, expected_id="command.other")


def test_rejects_symlink_and_excessive_bytes(tmp_path: Path) -> None:
    path = tmp_path / "command.builder-demo.json"
    path.write_text(" " * 16_385, encoding="utf-8")
    with pytest.raises(BuilderError):
        load_listing(path, expected_id="command.builder-demo")
    path.unlink()
    target = tmp_path / "target.json"
    target.write_text(json.dumps(listing()), encoding="utf-8")
    try:
        path.symlink_to(target)
    except OSError:
        pytest.skip("This host does not permit unprivileged symlink creation")
    with pytest.raises(BuilderError):
        load_listing(path, expected_id="command.builder-demo")


@pytest.mark.parametrize("kind", ["cli", "mcp"])
def test_current_kits_include_inert_listing_and_claim_guidance(tmp_path: Path, kind: str) -> None:
    kit = make_kit(tmp_path, kind)  # type: ignore[arg-type]
    files = dict(kit.files)
    assert kit.builder_version == "1.1.0"
    assert "extension-studio?extension=" + kit.discovery.metadata.contribution_id in files["README.md"]
    assert "listing-template.json" in files
    assert not any("extension-listings/" in key for key in kit.native_files())
    assert any(key.endswith("/listing-template.json") for key in managed_files(kit))
    write_kit(kit, tmp_path / "kit")
    assert load_kit(tmp_path / "kit").files == kit.files


def test_legacy_kits_remain_byte_reproducible_and_upgrade_without_native_change(tmp_path: Path) -> None:
    current = make_kit(tmp_path)
    legacy = build_kit(current.discovery, current.review, builder_version="1.0.0")
    assert legacy.builder_version == "1.0.0"
    assert "listing-template.json" not in dict(legacy.files)
    assert legacy.native_files() == current.native_files()
    assert legacy.revision == current.revision
    assert json.loads(ownership_record(legacy))["builderVersion"] == "1.0.0"
    write_kit(legacy, tmp_path / "old-kit")
    loaded = load_kit(tmp_path / "old-kit")
    assert loaded.files == legacy.files
    fixture = json.loads((REPOSITORY / "tests/fixtures/extension-listings/legacy-kit-files.json").read_text())
    assert {key: hashlib.sha256(value.encode()).hexdigest() for key, value in legacy.files} == fixture


def test_rejects_unknown_or_tampered_builder_versions(tmp_path: Path) -> None:
    kit = make_kit(tmp_path)
    with pytest.raises(BuilderError):
        build_kit(kit.discovery, kit.review, builder_version="999.0.0")
    write_kit(kit, tmp_path / "kit")
    manifest = tmp_path / "kit/manifest.json"
    row = json.loads(manifest.read_text())
    row["builderVersion"] = "999.0.0"
    manifest.write_text(json.dumps(row))
    with pytest.raises(BuilderError):
        load_kit(tmp_path / "kit")


def test_category_labels_are_total_for_supported_ids() -> None:
    for extension_id in [
        "command.git",
        "command.cloud.aws",
        "command.database.postgresql",
        "command.remote.essh",
        "command.email",
        "command.package.npm",
        "mcp.filesystem",
        "command.unknown",
    ]:
        assert category_for_extension(extension_id) in CATEGORY_LABELS


def test_validation_does_not_access_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("Listing validation must not access the network")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    assert validate_listing(listing())["extensionId"] == "command.builder-demo"


def test_installed_legacy_kit_upgrades_without_overwriting_native_edits(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.extension_builder.repository_write import apply_kit
    from tests.extension_builder_support import repository_fixture

    current = make_kit(tmp_path)
    legacy = build_kit(current.discovery, current.review, builder_version="1.0.0")
    repository = repository_fixture(tmp_path)
    apply_kit(legacy, repository, write=True)
    inspected = apply_kit(current, repository)
    assert all(item["action"] == "unchanged" for item in inspected["files"] if item["path"] in current.native_files())
    apply_kit(current, repository, write=True, expected_plan=inspected["planDigest"])
    assert all(item["action"] == "unchanged" for item in apply_kit(current, repository)["files"])
