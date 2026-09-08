"""Optional publisher metadata cannot alter native kits or runtime authority."""

from __future__ import annotations

import io
import json
import socket
from dataclasses import replace
from pathlib import Path
from typing import Literal

import pytest
from jsonschema import Draft202012Validator

from codex_plugin_scanner.guard.extension_builder.discover import discover
from codex_plugin_scanner.guard.extension_builder.errors import BuilderError
from codex_plugin_scanner.guard.extension_builder.io import canonical_json
from codex_plugin_scanner.guard.extension_builder.kit import build_kit, load_kit, write_kit
from codex_plugin_scanner.guard.extension_builder.listing import (
    CATEGORY_LABELS,
    MAX_TAGLINE_LENGTH,
    category_for_extension,
    listing_schema,
    listing_template,
    load_listing,
    validate_listing,
)
from codex_plugin_scanner.guard.extension_builder.listing_cli import main
from codex_plugin_scanner.guard.extension_builder.review import default_review
from tests.extension_builder_support import REPOSITORY, cli_document, make_kit, metadata


def listing() -> dict[str, object]:
    return json.loads(listing_template(metadata()))


def test_listing_contract_is_packaged_byte_for_byte() -> None:
    source = REPOSITORY / "contracts/extensions/listing.v1.schema.json"
    packaged = REPOSITORY / "src/codex_plugin_scanner/guard/extension_builder/listing.v1.schema.json"
    assert source.read_bytes() == packaged.read_bytes()
    Draft202012Validator(listing_schema()).validate(listing())
    assert json.loads(source.read_text())["properties"]["tagline"]["maxLength"] == MAX_TAGLINE_LENGTH


@pytest.mark.parametrize("kind", ["cli", "mcp"])
def test_template_has_no_inferred_claim_or_runtime_authority(kind: Literal["cli", "mcp"]) -> None:
    row = json.loads(listing_template(metadata(kind)))
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
        ("tagline", "a forbidden\x7f character"),
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
        "https://8.8.8.8/",
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


def test_numeric_maintainers_and_exact_identity() -> None:
    row = listing()
    row["maintainerGithubIds"] = ["123", "99999999999999999999"]
    assert validate_listing(row)["maintainerGithubIds"] == row["maintainerGithubIds"]
    with pytest.raises(BuilderError):
        validate_listing(row, expected_id="command.someone-else")


def test_rejects_duplicate_keys_filename_mismatch_and_byte_limit(tmp_path: Path) -> None:
    path = tmp_path / "command.builder-demo.json"
    path.write_text('{"schemaVersion":"guard.extension-listing.v1","schemaVersion":"other"}')
    with pytest.raises(BuilderError):
        load_listing(path, expected_id="command.builder-demo")
    path.write_text(json.dumps(listing()))
    with pytest.raises(BuilderError):
        load_listing(path, expected_id="command.other")
    path.write_text(" " * 16_385)
    with pytest.raises(BuilderError):
        load_listing(path, expected_id="command.builder-demo")


def test_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text(json.dumps(listing()))
    path = tmp_path / "command.builder-demo.json"
    try:
        path.symlink_to(target)
    except OSError:
        pytest.skip("This host does not permit unprivileged symlink creation")
    with pytest.raises(BuilderError):
        load_listing(path, expected_id="command.builder-demo")


@pytest.mark.parametrize("homepage", ["https://intranet/", "https://127.0.0.1/", "https://example.internal/"])
def test_optional_listing_does_not_invalidate_native_metadata(tmp_path: Path, homepage: str) -> None:
    source = tmp_path / "source.json"
    source.write_text(canonical_json(cli_document()), encoding="utf-8")
    discovery = discover("cli", source, replace(metadata(), homepage=homepage))
    kit = build_kit(discovery, default_review(discovery))
    write_kit(kit, tmp_path / "kit")
    assert load_kit(tmp_path / "kit").files == kit.files
    row = json.loads(listing_template(discovery.metadata))
    assert "documentationUrl" not in row
    assert validate_listing(row)["extensionId"] == discovery.metadata.contribution_id


@pytest.mark.parametrize("kind", ["cli", "mcp"])
def test_listing_command_is_explicit_and_never_modifies_a_kit(tmp_path: Path, kind: Literal["cli", "mcp"]) -> None:
    kit = make_kit(tmp_path, kind)
    target = tmp_path / "kit"
    write_kit(kit, target)
    before = {p.relative_to(target): p.read_bytes() for p in target.rglob("*") if p.is_file()}
    output = io.StringIO()
    assert main([str(target)], output=output) == 0
    assert validate_listing(json.loads(output.getvalue()))["extensionId"] == kit.discovery.metadata.contribution_id
    assert {p.relative_to(target): p.read_bytes() for p in target.rglob("*") if p.is_file()} == before
    assert "listing-template.json" not in dict(kit.files)


def test_listing_command_rejects_an_invalid_kit_without_output(tmp_path: Path) -> None:
    output = io.StringIO()
    assert main([str(tmp_path / "missing")], output=output) != 0
    assert output.getvalue() == ""


def test_category_labels_are_total_for_supported_ids() -> None:
    for extension_id in [
        "command.git",
        "command.cloud.aws",
        "command.database.postgresql",
        "command.remote.essh",
        "command.email",
        "command.package.node",
        "mcp.filesystem",
        "command.unknown",
    ]:
        assert category_for_extension(extension_id) in CATEGORY_LABELS


def test_validation_does_not_access_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("Listing validation must not access the network")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    assert validate_listing(listing())["extensionId"] == "command.builder-demo"
