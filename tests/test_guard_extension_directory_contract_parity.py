"""Public metadata preserves native identity bounds and supplemental delegation."""

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
from codex_plugin_scanner.guard.extension_builder.listing import listing_template, validate_listing
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
    native_schema = json.loads((REPOSITORY / "contracts" / directory / "contribution.v1.schema.json").read_text())
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


def test_omitted_and_empty_delegates_preserve_automatic_provenance(tmp_path: Path) -> None:
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
    row = json.loads(listing_template(metadata()))
    row["extensionId"] = "command.blitcp"
    for delegates in (None, [], ["6068672"]):
        if delegates is not None:
            row["maintainerGithubIds"] = delegates
        path.write_text(json.dumps(row))
        payload = exporter.export_directory(tmp_path)
        entry = next(item for item in payload["entries"] if item["id"] == "command.blitcp")
        assert entry["claimPolicy"] == "provenance"
        assert entry["maintainerGithubIds"] == (delegates or [])
        assert entry["trustClass"] == "external"
        assert entry["protectionModel"] == "external-opt-in"
