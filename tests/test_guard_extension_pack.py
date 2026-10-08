"""Proposed extension packs group catalog permissions without granting anything."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass

import pytest

from codex_plugin_scanner.guard.extension_builder.errors import BuilderError
from codex_plugin_scanner.guard.extension_builder.pack import load_pack, plan_pack_selection, validate_pack
from codex_plugin_scanner.guard.runtime.generated_command_catalog_loader import load_generated_command_catalog
from tests.extension_builder_support import REPOSITORY

PACK = REPOSITORY / "contributions/extension-packs/business.google-workspace.json"


@dataclass(frozen=True)
class FakePermission:
    permission_id: str
    extension_id: str
    baseline_floor: str


@dataclass(frozen=True)
class FakeExtension:
    version: str
    enabled: bool
    permissions: tuple[FakePermission, ...]


class FakeCatalog:
    def __init__(self, *extensions: tuple[str, FakeExtension]) -> None:
        self._extensions = dict(extensions)
        self._permissions = {
            permission.permission_id: permission for _, item in extensions for permission in item.permissions
        }

    def get(self, extension_id: str) -> FakeExtension | None:
        return self._extensions.get(extension_id)

    def permission(self, permission_id: str) -> FakePermission | None:
        return self._permissions.get(permission_id)


def fake_catalog(floor: str = "review") -> FakeCatalog:
    permissions = (
        FakePermission("command.demo.permission.send", "command.demo", floor),
        FakePermission("command.demo.permission.delete", "command.demo", "block"),
    )
    return FakeCatalog(("command.demo", FakeExtension("1.0.0", False, permissions)))


def fake_pack() -> dict[str, object]:
    return {
        "schemaVersion": "guard.extension-pack.v1",
        "packId": "business.demo",
        "status": "proposed",
        "title": "Demo",
        "summary": "Groups demo rules.",
        "extensions": [{"extensionId": "command.demo", "version": "1.0.0"}],
        "operationFamilies": [
            {
                "familyId": "send",
                "title": "Send",
                "permissionIds": ["command.demo.permission.send"],
                "roleSuggestions": {"personal": "review", "managed-team": "block"},
            },
            {
                "familyId": "delete",
                "title": "Delete",
                "permissionIds": ["command.demo.permission.delete"],
                "roleSuggestions": {"personal": "block", "managed-team": "block"},
            },
        ],
        "notCovered": [],
        "setupRecipes": [
            {
                "recipeId": "demo",
                "title": "Demo CLI",
                "extensionIds": ["command.demo"],
                "documentationPath": "docs/guard/demo.md",
            }
        ],
        "limitations": ["Selecting the pack does not enable an extension."],
    }


@pytest.fixture
def docs(tmp_path):
    (tmp_path / "docs/guard").mkdir(parents=True)
    (tmp_path / "docs/guard/demo.md").write_text("# Demo\n")
    return tmp_path


def test_pack_contract_is_packaged_byte_for_byte() -> None:
    source = REPOSITORY / "contracts/extensions/pack.v1.schema.json"
    packaged = REPOSITORY / "src/codex_plugin_scanner/guard/extension_builder/pack.v1.schema.json"
    assert source.read_bytes() == packaged.read_bytes()


def test_google_workspace_pack_matches_the_generated_catalog() -> None:
    catalog = load_generated_command_catalog()
    pack = load_pack(PACK, catalog=catalog, repository=REPOSITORY)
    assert [item["extensionId"] for item in pack["extensions"]] == [
        "command.google-workspace.gws",
        "command.google-workspace.gog",
    ]
    for item in pack["extensions"]:
        extension = catalog.get(item["extensionId"])
        assert extension is not None
        assert extension.trust_class == "external"
        assert extension.activation == "opt-in"


def test_selecting_the_pack_leaves_disabled_external_extensions_inert() -> None:
    catalog = load_generated_command_catalog()
    pack = load_pack(PACK, catalog=catalog, repository=REPOSITORY)
    before = {item["extensionId"]: catalog.get(item["extensionId"]).enabled for item in pack["extensions"]}
    for role in ("personal", "managed-team"):
        plan = plan_pack_selection(pack, catalog=catalog, enabled_extension_ids=(), role=role)
        assert plan["grants"] == []
        assert plan["activatesExtensions"] is False
        assert {row["state"] for row in plan["extensions"]} == {"inert"}
        assert not any(row["applies"] for row in plan["suggestions"])
        assert all(row["suggestedAction"] != "allow" for row in plan["suggestions"])
    after = {item["extensionId"]: catalog.get(item["extensionId"]).enabled for item in pack["extensions"]}
    assert before == after == dict.fromkeys(before, False)


def test_only_locally_enabled_extensions_receive_suggestions() -> None:
    catalog = load_generated_command_catalog()
    pack = load_pack(PACK, catalog=catalog, repository=REPOSITORY)
    plan = plan_pack_selection(
        pack, catalog=catalog, enabled_extension_ids={"command.google-workspace.gws"}, role="managed-team"
    )
    states = {row["extensionId"]: row["state"] for row in plan["extensions"]}
    assert states == {"command.google-workspace.gws": "active", "command.google-workspace.gog": "inert"}
    for row in plan["suggestions"]:
        assert row["applies"] is str(row["permissionId"]).startswith("command.google-workspace.gws.")
    assert plan["grants"] == []


@pytest.mark.parametrize("suggestion", ["allow", "warn", "disabled", "off"])
def test_role_suggestions_cannot_relax_review(suggestion: str, docs) -> None:
    pack = fake_pack()
    pack["operationFamilies"][0]["roleSuggestions"]["personal"] = suggestion
    with pytest.raises(BuilderError) as error:
        validate_pack(pack, catalog=fake_catalog(), repository=docs)
    assert error.value.code == "pack_schema"


def test_role_suggestions_cannot_disable_a_block_floor(docs) -> None:
    with pytest.raises(BuilderError) as error:
        validate_pack(fake_pack(), catalog=fake_catalog(floor="block"), repository=docs)
    assert error.value.code == "pack_floor"


def test_selection_plan_keeps_the_floor_even_without_validation() -> None:
    plan = plan_pack_selection(
        fake_pack(), catalog=fake_catalog(floor="block"), enabled_extension_ids={"command.demo"}, role="personal"
    )
    assert {row["suggestedAction"] for row in plan["suggestions"]} == {"block"}


@pytest.mark.parametrize(
    "field,value",
    [
        ("grants", [{"permissionId": "command.demo.permission.send", "action": "allow"}]),
        ("enabled", True),
        ("activation", "default-on"),
        ("trustClass", "trusted-library"),
        ("policy", {"command.demo.permission.send": "allow"}),
    ],
)
def test_packs_cannot_carry_authority_fields(field: str, value: object, docs) -> None:
    pack = fake_pack()
    pack[field] = value
    with pytest.raises(BuilderError) as error:
        validate_pack(pack, catalog=fake_catalog(), repository=docs)
    assert error.value.code == "pack_schema"


def test_status_must_stay_proposed(docs) -> None:
    pack = fake_pack()
    pack["status"] = "qualified"
    with pytest.raises(BuilderError) as error:
        validate_pack(pack, catalog=fake_catalog(), repository=docs)
    assert error.value.code == "pack_schema"


def test_operation_families_must_cover_each_permission_once(docs) -> None:
    missing = fake_pack()
    del missing["operationFamilies"][1]
    duplicate = copy.deepcopy(fake_pack())
    duplicate["operationFamilies"][1]["permissionIds"].append("command.demo.permission.send")
    for pack in (missing, duplicate):
        with pytest.raises(BuilderError) as error:
            validate_pack(pack, catalog=fake_catalog(), repository=docs)
        assert error.value.code == "pack_coverage"


@pytest.mark.parametrize(
    "mutate,code",
    [
        (lambda pack: pack["extensions"][0].update(version="2.0.0"), "pack_version"),
        (lambda pack: pack["extensions"][0].update(extensionId="command.missing"), "pack_reference"),
        (lambda pack: pack["operationFamilies"][0].update(permissionIds=["command.other.x"]), "pack_reference"),
        (lambda pack: pack["setupRecipes"][0].update(extensionIds=["command.other"]), "pack_reference"),
        (lambda pack: pack.update(title=" Demo"), "pack_text"),
        (lambda pack: pack.update(summary="Demo\u202e rules."), "pack_text"),
        (lambda pack: pack["operationFamilies"][0].update(familyId="send\n"), "pack_identity"),
        (lambda pack: pack["setupRecipes"][0].update(recipeId="demo\n"), "pack_identity"),
        (lambda pack: pack.update(packId="business.demo\n"), "pack_identity"),
        (lambda pack: pack["extensions"][0].update(version="1.0.0\n"), "pack_identity"),
    ],
)
def test_pack_references_and_text_are_checked(mutate, code: str, docs) -> None:
    pack = fake_pack()
    mutate(pack)
    with pytest.raises(BuilderError) as error:
        validate_pack(pack, catalog=fake_catalog(), repository=docs)
    assert error.value.code == code


def test_setup_recipe_documentation_must_exist(tmp_path) -> None:
    with pytest.raises(BuilderError) as error:
        validate_pack(fake_pack(), catalog=fake_catalog(), repository=tmp_path)
    assert error.value.code == "pack_reference"
    (tmp_path / "docs/guard").mkdir(parents=True)
    (tmp_path / "docs/guard/demo.md").write_text("# Demo\n")
    assert validate_pack(fake_pack(), catalog=fake_catalog(), repository=tmp_path)["packId"] == "business.demo"


def test_pack_filename_must_match_its_id(tmp_path, docs) -> None:
    path = tmp_path / "business.other.json"
    path.write_text(json.dumps(fake_pack()))
    with pytest.raises(BuilderError) as error:
        load_pack(path, catalog=fake_catalog(), repository=tmp_path)
    assert error.value.code == "pack_identity"
