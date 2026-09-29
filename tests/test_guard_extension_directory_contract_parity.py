"""Public metadata preserves native identity bounds and explicit claim authority."""

from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path
from typing import Literal

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from codex_plugin_scanner.guard.extension_builder.errors import BuilderError
from codex_plugin_scanner.guard.extension_builder.listing import (
    LISTING_SCHEMA_V1,
    LISTING_SCHEMA_V2,
    listing_schema,
    listing_template,
    validate_listing,
)
from codex_plugin_scanner.guard.runtime.mcp_server_contribution import catalog_id_for_mcp_id
from tests.extension_builder_support import REPOSITORY, metadata


def directory_schema() -> dict[str, object]:
    return json.loads((REPOSITORY / "contracts/extensions/directory.v1.schema.json").read_text())


@pytest.mark.parametrize("kind", ["cli", "mcp"])
@pytest.mark.parametrize("length", [129, 240, 256])
def test_listing_and_directory_preserve_native_schema_bounds(kind: Literal["cli", "mcp"], length: int) -> None:
    prefix = "command." if kind == "cli" else "mcp."
    extension_id = prefix + "x" * (length - len(prefix))
    listing = json.loads(listing_template(metadata(kind)))
    listing["extensionId"] = extension_id
    assert validate_listing(listing, expected_id=extension_id)["extensionId"] == extension_id

    directory = "extensions" if kind == "cli" else "mcp-servers"
    example = "command.blitcp" if kind == "cli" else "mcp.filesystem"
    payload = json.loads((REPOSITORY / "contributions" / directory / f"{example}.json").read_text())
    payload["id"] = extension_id
    schema_version = "contribution.v2.schema.json" if kind == "cli" else "contribution.v1.schema.json"
    native_schema = json.loads((REPOSITORY / "contracts" / directory / schema_version).read_text())
    Draft202012Validator(native_schema).validate(payload)

    catalog = json.loads((REPOSITORY / "docs/guard/extensions/catalog.v1.json").read_text())
    entry = next(row for row in catalog["entries"] if row["id"] == example)
    entry.update(
        {
            "id": extension_id,
            "sourcePath": f"contributions/{directory}/{extension_id}.json",
            "runtimeExtensionId": extension_id if kind == "cli" else catalog_id_for_mcp_id(extension_id),
        }
    )
    Draft202012Validator(directory_schema()).validate({"schemaVersion": catalog["schemaVersion"], "entries": [entry]})


@pytest.mark.parametrize("prefix", ["command.", "mcp."])
def test_listing_rejects_identity_beyond_native_bound(prefix: str) -> None:
    row = json.loads(listing_template(metadata()))
    row["extensionId"] = prefix + "x" * (257 - len(prefix))
    with pytest.raises(BuilderError):
        validate_listing(row)


def test_directory_rejects_unbounded_dependent_fields() -> None:
    catalog = json.loads((REPOSITORY / "docs/guard/extensions/catalog.v1.json").read_text())
    entry = next(row for row in catalog["entries"] if row["id"] == "mcp.filesystem")
    for field, value in [
        ("id", "mcp." + "x" * 253),
        ("runtimeExtensionId", "command.mcp-" + "x" * 253),
        ("sourcePath", "contributions/mcp-servers/mcp." + "x" * 260 + ".json"),
    ]:
        with pytest.raises(ValidationError):
            Draft202012Validator(directory_schema()).validate(
                {
                    "schemaVersion": catalog["schemaVersion"],
                    "entries": [{**entry, field: value}],
                }
            )


def test_listing_contract_distinguishes_presentation_from_claim_authority() -> None:
    v1 = listing_schema(LISTING_SCHEMA_V1)
    v2 = listing_schema(LISTING_SCHEMA_V2)
    assert v1["title"] == "HOL Guard extension publisher listing metadata"
    assert "maintainerGithubIds is reviewed claim-authority input" in v1["description"]
    assert "Validation does not itself grant authority" in v1["description"]
    assert v2["title"] == "HOL Guard extension contributor listing metadata"
    assert "contributors is attribution only" in v2["description"]
    assert "maintainerGithubIds remains separately reviewed claim-authority input" in v2["description"]
    for version, schema in (("v1", v1), ("v2", v2)):
        packaged = json.loads(
            (REPOSITORY / f"src/codex_plugin_scanner/guard/extension_builder/listing.{version}.schema.json").read_text()
        )
        public = json.loads((REPOSITORY / f"contracts/extensions/listing.{version}.schema.json").read_text())
        assert schema == public
        assert packaged == public


def test_exporter_never_infers_claim_authority_when_ids_are_omitted(tmp_path: Path) -> None:
    specification = importlib.util.spec_from_file_location(
        "publisher_contract_export", REPOSITORY / "scripts/export_extension_directory.py"
    )
    assert specification and specification.loader
    exporter = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(exporter)
    for directory in ("extensions", "mcp-servers"):
        shutil.copytree(REPOSITORY / "contributions" / directory, tmp_path / "contributions" / directory)
    listings = tmp_path / "contributions/extension-listings"
    listings.mkdir()
    path = listings / "command.blitcp.json"
    base = json.loads(listing_template(metadata()))
    base["extensionId"] = "command.blitcp"
    for claimants in (None, [], ["6068672"]):
        row = dict(base)
        if claimants is not None:
            row["maintainerGithubIds"] = claimants
        path.write_text(json.dumps(row))
        payload = exporter.export_directory(tmp_path)
        entry = next(item for item in payload["entries"] if item["id"] == "command.blitcp")
        assert entry["claimPolicy"] == "provenance"
        assert entry["maintainerGithubIds"] == (claimants or [])
        assert entry["trustClass"] == "external"
        assert entry["protectionModel"] == "external-opt-in"

    entry_properties = directory_schema()["properties"]["entries"]["items"]["properties"]
    description = entry_properties["maintainerGithubIds"]["description"]
    assert "only IDs in this accepted array" in description
    assert "Pull-request authorship is attribution evidence only" in description
