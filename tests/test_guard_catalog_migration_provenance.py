"""The catalog migration event has to say which install wrote it.

A store shared by several Guard installs records a digest that moves back and
forth as each one runs. Before provenance there was no way to attribute either
value, so these tests pin down what the event now carries, what it deliberately
does not carry, and the loud record a backwards migration leaves behind.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

import codex_plugin_scanner.version as version_module
from codex_plugin_scanner.guard.runtime import generated_command_catalog_loader as loader_module
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.runtime.generated_command_catalog import GeneratedCommandCatalog
from codex_plugin_scanner.guard.runtime.generated_command_catalog_provenance import (
    catalog_provenance,
    version_ordinal,
)
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_extension_control_authority_catalog_events import (
    MIGRATED_EVENT,
    REGRESSED_EVENT,
    build_catalog_migration_payload,
)
from tests.test_extension_control_clear_catalog_migration import (
    _activate_under_catalog,
    _description_only_catalog_variant,
)


@pytest.fixture(autouse=True)
def _allow_local_terminal_confirmation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.extension_control_proof._require_local_terminal_confirmation",
        lambda _enrollment: None,
    )


def _events(store: GuardStore, event_name: str) -> list[dict[str, object]]:
    with store._connect() as connection:  # pyright: ignore[reportPrivateUsage]
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            "select payload_json from guard_events where event_name = ? order by event_id",
            (event_name,),
        ).fetchall()
    return [json.loads(str(row["payload_json"])) for row in rows]


def _migrate_to_built_in(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> GuardStore:
    """Enrol under an older catalog, then let the packaged one take over."""

    store = GuardStore(tmp_path / "guard-home")
    legacy = _description_only_catalog_variant()
    assert legacy.catalog_digest != BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    _activate_under_catalog(store, legacy, monkeypatch, preserve_local_controls=True)
    migrated = store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    assert migrated.health is AuthorityHealth.PROTECTED
    assert migrated.catalog_digest == BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    return store


def test_the_migration_event_says_which_install_wrote_the_catalog(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _migrate_to_built_in(tmp_path, monkeypatch)

    migrations = _events(store, MIGRATED_EVENT)

    assert migrations
    provenance = migrations[-1]["provenance"]
    assert isinstance(provenance, dict)
    assert provenance["trigger"] == "catalog-migration"
    assert provenance["guard_version"] == version_module.__version__
    assert provenance["writer_version"] == version_module.__version__
    assert provenance["extension_count"] == len(BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions)
    assert provenance["program_digest"] == BUILT_IN_COMMAND_EXTENSION_REGISTRY.program_digest
    assert provenance["frozen"] is False
    assert provenance["install_kind"] != "unattributed"
    assert isinstance(provenance["resource_root_digest"], str)
    assert len(str(provenance["resource_root_digest"])) == 64


def test_provenance_records_no_path_and_no_home_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _migrate_to_built_in(tmp_path, monkeypatch)

    recorded = json.dumps(_events(store, MIGRATED_EVENT))

    assert str(Path.home()) not in recorded
    assert str(tmp_path) not in recorded
    assert "/" not in str(_events(store, MIGRATED_EVENT)[-1]["provenance"]["resource_root_digest"])  # pyright: ignore[reportIndexIssue]


def test_reading_the_authority_again_does_not_duplicate_the_event(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _migrate_to_built_in(tmp_path, monkeypatch)
    before = len(_events(store, MIGRATED_EVENT))

    store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)

    assert len(_events(store, MIGRATED_EVENT)) == before


def test_a_migration_back_to_an_older_guards_catalog_is_recorded_as_a_regression(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(version_module, "__version__", "3.46.0")
    store = _migrate_to_built_in(tmp_path, monkeypatch)
    assert _events(store, REGRESSED_EVENT) == []
    legacy = _description_only_catalog_variant()
    monkeypatch.setattr(version_module, "__version__", "3.36.0")

    store.read_extension_control_authority_for_registry(legacy)

    regressions = _events(store, REGRESSED_EVENT)
    assert len(regressions) == 1
    assert regressions[0]["previous_writer_version"] == "3.46.0"
    assert regressions[0]["writer_version"] == "3.36.0"
    assert regressions[0]["catalog_digest"] == legacy.catalog_digest
    assert regressions[0]["previous_catalog_digest"] == BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    migration = _events(store, MIGRATED_EVENT)[-1]
    assert migration["regression"] == {
        "previous_writer_version": "3.46.0",
        "writer_version": "3.36.0",
        "retired_target_count": migration["retired_target_count"],
        "retired_target_ids": migration["retired_target_ids"],
    }


def test_an_upgrade_is_not_recorded_as_a_regression(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(version_module, "__version__", "3.36.0")
    store = _migrate_to_built_in(tmp_path, monkeypatch)
    legacy = _description_only_catalog_variant()
    monkeypatch.setattr(version_module, "__version__", "3.47.0")

    store.read_extension_control_authority_for_registry(legacy)

    assert _events(store, REGRESSED_EVENT) == []


def test_a_catalog_this_process_did_not_load_is_reported_as_unattributed() -> None:
    provenance = catalog_provenance(catalog_digest="0" * 64, trigger="probe")

    assert provenance["install_kind"] == "unattributed"
    assert provenance["resource_root_digest"] is None
    assert "extension_count" not in provenance


def test_two_installs_of_one_version_get_different_resource_roots(monkeypatch: pytest.MonkeyPatch) -> None:
    digest = BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    resource = "contracts/data/extensions/command-catalog.v1.json"

    def provenance_for(root: str) -> dict[str, object]:
        monkeypatch.setattr(loader_module, "_resolved_catalog_resource_path", f"{root}/{resource}")
        return catalog_provenance(catalog_digest=digest, trigger="probe")

    pipx = provenance_for("/home/u/.local/pipx/venvs/hol-guard/lib/python3.14/site-packages/codex_plugin_scanner/guard")
    uv = provenance_for(
        "/home/u/.local/share/uv/tools/hol-guard/lib/python3.12/site-packages/codex_plugin_scanner/guard"
    )
    again = provenance_for(
        "/home/u/.local/pipx/venvs/hol-guard/lib/python3.14/site-packages/codex_plugin_scanner/guard"
    )

    assert pipx["resource_root_digest"] != uv["resource_root_digest"]
    assert pipx["resource_root_digest"] == again["resource_root_digest"]
    assert pipx["install_kind"] == "pipx"
    assert uv["install_kind"] == "uv-tool"


def test_a_frozen_bundle_is_named_as_one(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        loader_module,
        "_resolved_catalog_resource_path",
        "/Applications/x/org.hol.guard.desktop/core/versions/3.46.0/bundle/_internal/catalog.json",
    )
    monkeypatch.setattr("sys.frozen", True, raising=False)

    provenance = catalog_provenance(catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest, trigger="probe")

    assert provenance["frozen"] is True
    assert provenance["install_kind"] == "desktop-bundle"


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("3.46.0", (3, 46, 0)),
        ("3.47.0a2", (3, 47, 0)),
        ("3.8.0", (3, 8, 0)),
        ("", ()),
        ("not-a-version", ()),
    ],
)
def test_version_ordinal_reads_the_leading_numbers(version: str, expected: tuple[int, ...]) -> None:
    assert version_ordinal(version) == expected


def test_an_older_release_orders_below_a_newer_prerelease() -> None:
    assert version_ordinal("3.36.0") < version_ordinal("3.46.0")
    assert version_ordinal("3.47.0a2") > version_ordinal("3.46.0")


def test_a_backfilled_event_names_no_writer_and_judges_no_downgrade(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A reader that finds an unrecorded migration did not perform it.

    Stamping its own version as the writer makes an old revision look like the
    newest install's work: the next migration is then measured against a version
    that never wrote anything, which invents downgrades and hides real ones.
    """

    monkeypatch.setattr(version_module, "__version__", "3.36.0")
    store = _migrate_to_built_in(tmp_path, monkeypatch)
    with store._connect() as connection:  # pyright: ignore[reportPrivateUsage]
        connection.execute("delete from guard_events where event_name = ?", (MIGRATED_EVENT,))
    monkeypatch.setattr(version_module, "__version__", "3.46.0")

    store.read_extension_control_authority_for_registry(BUILT_IN_COMMAND_EXTENSION_REGISTRY)

    backfilled = _events(store, MIGRATED_EVENT)[-1]["provenance"]
    assert isinstance(backfilled, dict)
    assert backfilled["trigger"] == "authority-read-backfill"
    assert backfilled["guard_version"] == "3.46.0"
    assert "writer_version" not in backfilled
    # 3.40.0 is older than the reader and newer than the install that actually
    # migrated the store, so a writer version taken from the backfill would be
    # reported as a downgrade that never happened.
    monkeypatch.setattr(version_module, "__version__", "3.40.0")
    store.read_extension_control_authority_for_registry(_description_only_catalog_variant())
    assert _events(store, REGRESSED_EVENT) == []


def test_a_catalog_built_in_memory_is_not_attributed_to_the_packaged_resource() -> None:
    """Equal digests mean equal contents, not a shared origin.

    The resource root names the file this process loaded; a caller holding its
    own catalog object did not come from there, and recording that root would
    put another install's name on the revision.
    """

    built_in = BUILT_IN_COMMAND_EXTENSION_REGISTRY
    twin = GeneratedCommandCatalog(
        built_in.extensions,
        catalog_digest=built_in.catalog_digest,
        program_digest=built_in.program_digest,
        source_digest=built_in.source_digest,
        implementation_digest=built_in.implementation_digest,
    )
    assert twin.catalog_digest == built_in.catalog_digest

    provenance = catalog_provenance(catalog_digest=twin.catalog_digest, catalog=twin, trigger="probe")

    assert provenance["install_kind"] == "in-process"
    assert provenance["resource_root_digest"] is None
    assert catalog_provenance(catalog_digest=built_in.catalog_digest, catalog=built_in, trigger="probe")[
        "install_kind"
    ] not in {"in-process", "unattributed"}


def _store_with_events(records: list[dict[str, object]]) -> sqlite3.Connection:
    """A connection holding migration events in the order they were written."""

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(
        "create table guard_events (event_id integer primary key autoincrement, event_name text, payload_json text)"
    )
    for record in records:
        connection.execute(
            "insert into guard_events (event_name, payload_json) values (?, ?)",
            (MIGRATED_EVENT, json.dumps(record)),
        )
    return connection


def test_a_backfill_over_an_attributed_revision_does_not_hide_the_downgrade(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The writer is looked up by catalog, not by the last migration to it.

    A store can arrive at a catalog twice: 3.47 writes it, the store moves away
    and comes back through an event nobody could attribute. The catalog being
    retired is still the one 3.47 produced, so an older install replacing it
    still retires 3.47's controls. Keying the lookup on the revision instead
    would read the backfill, find no writer, and drop the record that exists to
    make that loss loud.
    """

    monkeypatch.setattr(version_module, "__version__", "3.45.0")
    connection = _store_with_events(
        [
            {"revision": 4, "catalog_digest": "catalog-x", "provenance": {"writer_version": "3.47.0"}},
            {"revision": 5, "catalog_digest": "catalog-y", "provenance": {"writer_version": "3.47.0"}},
            {"revision": 6, "catalog_digest": "catalog-x", "provenance": {"trigger": "authority-read-backfill"}},
        ]
    )

    _payload, regression = build_catalog_migration_payload(
        connection,
        previous_revision=6,
        revision=7,
        previous_catalog_digest="catalog-x",
        catalog_digest="catalog-z",
        layers=(),
        retired_targets=("control-a",),
        registry=None,
        trigger="catalog-migration",
        writer=True,
    )

    assert regression == {
        "previous_writer_version": "3.47.0",
        "writer_version": "3.45.0",
        "retired_target_count": 1,
        "retired_target_ids": ["control-a"],
    }
