from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.local_cli_commands import LocalCliCommand, slug_local_cli_command_id
from codex_plugin_scanner.guard.runtime.local_cli_identity import UnlistedCliIdentity
from codex_plugin_scanner.guard.runtime.local_mcp_stdio import McpCatalogResult
from codex_plugin_scanner.guard.store import GuardStore

from .local_cli_native_fixture import native_local_cli_grant_resident  # noqa: F401

_FIRST = "2026-09-27T12:00:00Z"
_SECOND = "2026-09-27T12:01:00Z"


def _tool_authority(store: GuardStore, identity: UnlistedCliIdentity, tool_name: str) -> dict[str, object] | None:
    with store._connect() as connection:
        catalog = connection.execute(
            "select revision from local_mcp_catalog where cli_id = ? and identity_hash = ?",
            (identity.cli_id, identity.identity_hash),
        ).fetchone()
        if catalog is None:
            return None
        rows = connection.execute(
            """select tool_name, authority_hash from local_mcp_tool_authority
               where cli_id = ? and identity_hash = ? and catalog_revision = ? and tool_name = ?""",
            (identity.cli_id, identity.identity_hash, catalog[0], tool_name),
        ).fetchall()
    return {"authority_hashes": dict(rows)}


def _grant_and_authority(store: GuardStore, identity: UnlistedCliIdentity) -> tuple[object, ...]:
    return (
        store.read_local_cli_grant(identity.cli_id),
        store.read_local_cli_command_states(identity.cli_id),
        _tool_authority(store, identity, "read"),
    )


def test_skill_metadata_is_origin_bound_and_partial_refresh_keeps_prior(tmp_path: Path):
    store, identity = _store(tmp_path)
    metadata = {
        "uri": "skill://report/SKILL.md",
        "connection_identity_hash": identity.identity_hash,
        "origin": "mcp-served-skill",
        "name": "report",
        "description": "Synthetic workflow",
        "activation_supported": False,
        "permissions_granted": False,
    }
    first = replace(_catalog("read"), skills=(metadata,), skills_complete=True)
    store.replace_local_cli_commands(
        identity.cli_id, _commands("read"), mcp_catalog=first, identity_hash=identity.identity_hash, seen_at=_FIRST
    )
    assert store.read_local_cli_revision() == 0
    partial = replace(_catalog("read"), skills_complete=False, skills_reason="skill_discovery_failed")
    store.replace_local_cli_commands(
        identity.cli_id, _commands("read"), mcp_catalog=partial, identity_hash=identity.identity_hash, seen_at=_SECOND
    )
    snapshot = store.list_local_cli_items()[0]["mcp_catalog"]["skills_catalog"]
    assert snapshot["entries"] == [metadata]
    assert snapshot["stale"] is True and snapshot["complete"] is False
    foreign = replace(first, skills=({**metadata, "connection_identity_hash": "f" * 64},))
    store.replace_local_cli_commands(
        identity.cli_id, _commands("read"), mcp_catalog=foreign, identity_hash=identity.identity_hash, seen_at=_SECOND
    )
    snapshot = store.list_local_cli_items()[0]["mcp_catalog"]["skills_catalog"]
    assert snapshot["entries"] == [metadata]
    assert snapshot["reason"] == "skill_origin_changed"
    assert snapshot["complete"] is False


def _store(tmp_path: Path) -> tuple[GuardStore, UnlistedCliIdentity]:
    home = tmp_path / "home"
    home.mkdir()
    store = GuardStore(home)
    identity = UnlistedCliIdentity(
        cli_id="local-cli.mcp-fixture",
        name="Fixture connector",
        kind="executable",
        identity_hash="1" * 64,
        example_label="fixture-mcp",
        interpreter_name=None,
    )
    store.record_local_cli_observation(identity, seen_at=_FIRST, surface="mcp")
    return store, identity


def test_skill_pages_are_bounded_revision_fenced_and_keep_private_catalogs(tmp_path: Path):
    from codex_plugin_scanner.guard.runtime.package_json_script_memory import public_local_cli_item

    store, identity = _store(tmp_path)
    entries = tuple(
        {
            "uri": f"skill://report-{index:03}/SKILL.md",
            "name": f"report-{index:03}",
            "description": "Synthetic workflow",
            "origin": "mcp-served-skill",
            "connection_identity_hash": identity.identity_hash,
            "activation_supported": False,
            "permissions_granted": False,
        }
        for index in range(51)
    )
    catalog = replace(_catalog("read"), skills=entries, skills_complete=True)
    store.replace_local_cli_commands(
        identity.cli_id, _commands("read"), mcp_catalog=catalog, identity_hash=identity.identity_hash, seen_at=_FIRST
    )
    first = store.read_local_mcp_skills(identity.cli_id, offset=0, search="", expected_revision=None)
    assert len(first["entries"]) == 50 and first["next_offset"] == 50
    second = store.read_local_mcp_skills(identity.cli_id, offset=50, search="", expected_revision=first["revision"])
    assert len(second["entries"]) == 1 and second["next_offset"] is None
    matched = store.read_local_mcp_skills(identity.cli_id, offset=0, search="REPORT-050", expected_revision=None)
    assert matched["entries"] == [entries[50]]
    for offset in (-1, True, 1001):
        with pytest.raises(ValueError, match="invalid_mcp_skill_page"):
            store.read_local_mcp_skills(identity.cli_id, offset=offset, search="", expected_revision=None)
    private = store.list_local_cli_items()[0]
    public = public_local_cli_item(private)
    assert "tools" not in public["mcp_catalog"]
    assert "entries" not in public["mcp_catalog"]["skills_catalog"]
    assert len(private["mcp_catalog"]["skills_catalog"]["entries"]) == 51
    store.replace_local_cli_commands(
        identity.cli_id, _commands("read"), mcp_catalog=catalog, identity_hash=identity.identity_hash, seen_at=_SECOND
    )
    with pytest.raises(ValueError, match="mcp_skill_catalog_changed"):
        store.read_local_mcp_skills(identity.cli_id, offset=50, search="", expected_revision=first["revision"])
    store.record_local_cli_observation(replace(identity, identity_hash="2" * 64), seen_at=_SECOND, surface="mcp")
    with pytest.raises(ValueError):
        store.read_local_mcp_skills(identity.cli_id, offset=0, search="", expected_revision=None)


def _commands(*names: str) -> tuple[LocalCliCommand, ...]:
    return tuple(LocalCliCommand(name, name, name, "Fixture tool") for name in names)


def _catalog(*names: str, complete: bool = True) -> McpCatalogResult:
    return McpCatalogResult(
        tuple({"name": name, "inputSchema": {"type": "object"}} for name in names),
        complete=complete,
        reason=None if complete else "list_failed",
        pages=1,
        protocol_version="2026-07-28",
    )


def _publish(store: GuardStore, identity: UnlistedCliIdentity, *names: str) -> None:
    store.replace_local_cli_commands(
        identity.cli_id,
        _commands(*names),
        mcp_catalog=_catalog(*names),
        identity_hash=identity.identity_hash,
        seen_at=_FIRST,
    )


@pytest.mark.parametrize(
    ("ttl_ms", "deadline"),
    [(0, None), (30_000, "2026-09-27T12:00:30+00:00")],
)
def test_catalog_freshness_deadline_requires_a_positive_cache_window(tmp_path: Path, ttl_ms: int, deadline: str | None):
    store, identity = _store(tmp_path)
    catalog = replace(_catalog("read"), cache_ttl_ms=ttl_ms)
    store.replace_local_cli_commands(
        identity.cli_id,
        _commands("read"),
        mcp_catalog=catalog,
        identity_hash=identity.identity_hash,
        seen_at=_FIRST,
    )
    item = store.list_local_cli_items()[0]
    assert item["mcp_catalog"]["complete"] is True
    assert item["mcp_catalog"]["fresh_until"] == deadline
    assert item["mcp_catalog"]["cache_ttl_ms"] == ttl_ms
    assert item["mcp_catalog"]["updated_at"] == _FIRST
    assert store.read_local_cli_revision() == 0


def test_partial_refresh_preserves_known_tools_and_choices(tmp_path: Path) -> None:
    store, identity = _store(tmp_path)
    _publish(store, identity, "read", "delete")
    store.upsert_local_cli_grant(identity=identity, state="allowed", expected_revision=0, updated_at=_FIRST)
    store.upsert_local_cli_command_states(identity.cli_id, {"read": "allow", "delete": "block"})
    before = store.list_local_cli_items()[0]
    store.merge_local_cli_commands(
        identity.cli_id,
        _commands("search"),
        limit=80,
        mcp_catalog=_catalog("search", complete=False),
        identity_hash=identity.identity_hash,
        seen_at=_SECOND,
    )
    item = store.list_local_cli_items()[0]
    commands = {command["command_id"]: command["state"] for command in item["commands"]}
    assert commands == {"read": "allow", "delete": "block", "search": "review"}
    assert item["authority_revision"] == before["authority_revision"] + 1
    assert item["grant_revision"] == item["authority_revision"]
    catalog = item["mcp_catalog"]
    assert catalog["known_count"] == 3
    assert catalog["listed_count"] == 1
    assert not catalog["complete"]
    assert catalog["stale"]
    assert catalog["reason"] == "list_failed"
    assert catalog["last_complete_at"] == _FIRST
    assert catalog["updated_at"] == _SECOND
    assert catalog["revision"] == 2


def test_failed_refresh_keeps_the_last_catalog(tmp_path: Path) -> None:
    store, identity = _store(tmp_path)
    _publish(store, identity, "read")
    store.merge_local_cli_commands(
        identity.cli_id,
        (),
        limit=80,
        mcp_catalog=McpCatalogResult(reason="refresh_failed"),
        identity_hash=identity.identity_hash,
        seen_at=_SECOND,
    )
    item = store.list_local_cli_items()[0]
    assert [command["command_id"] for command in item["commands"]] == ["read"]
    assert item["mcp_catalog"]["known_count"] == 1
    assert item["mcp_catalog"]["protocol_version"] == "2026-07-28"
    assert item["mcp_catalog"]["reason"] == "refresh_failed"
    assert not item["mcp_catalog"]["complete"]


def test_partial_refresh_limit_fails_atomically_instead_of_dropping_tools(tmp_path: Path) -> None:
    store, identity = _store(tmp_path)
    _publish(store, identity, "read", "delete")
    before = store.list_local_cli_items()[0]
    with pytest.raises(ValueError, match="local_cli_catalog_limit"):
        store.merge_local_cli_commands(
            identity.cli_id,
            _commands("search"),
            limit=2,
            mcp_catalog=_catalog("search", complete=False),
            identity_hash=identity.identity_hash,
            seen_at=_SECOND,
        )
    after = store.list_local_cli_items()[0]
    assert after["commands"] == before["commands"]
    assert after["mcp_catalog"] == before["mcp_catalog"]


def test_removed_tools_revoke_allow_and_preserve_deny_when_they_return(tmp_path: Path) -> None:
    store, identity = _store(tmp_path)
    _publish(store, identity, "read", "delete")
    store.upsert_local_cli_grant(identity=identity, state="allowed", expected_revision=0, updated_at=_FIRST)
    store.upsert_local_cli_command_states(identity.cli_id, {"read": "allow", "delete": "block"})
    revision = store.read_local_cli_revision()
    _publish(store, identity)
    assert store.read_local_cli_command_catalog(identity.cli_id) == []
    assert store.read_local_cli_command_states(identity.cli_id) == {"read": "review", "delete": "block"}
    assert store.read_local_cli_revision() == revision + 1
    assert store.list_local_cli_items()[0]["mcp_catalog"]["changes"]["removed"] == ["delete", "read"]
    _publish(store, identity, "read", "delete")
    assert store.read_local_cli_command_states(identity.cli_id) == {"read": "review", "delete": "block"}


def test_partial_catalog_marks_missing_tools_stale_without_removing_them(tmp_path: Path) -> None:
    store, identity = _store(tmp_path)
    _publish(store, identity, "read", "delete")
    store.merge_local_cli_commands(
        identity.cli_id,
        _commands("read", "search"),
        limit=80,
        mcp_catalog=_catalog("read", "search", complete=False),
        identity_hash=identity.identity_hash,
        seen_at=_SECOND,
    )
    changes = store.list_local_cli_items()[0]["mcp_catalog"]["changes"]
    assert changes == {"added": ["search"], "changed": [], "removed": [], "stale": ["delete"]}


def test_saving_current_choices_preserves_retired_mcp_denies(tmp_path: Path) -> None:
    store, identity = _store(tmp_path)
    _publish(store, identity, "read", "delete")
    store.upsert_local_cli_grant(
        identity=identity,
        state="allowed",
        expected_revision=0,
        updated_at=_FIRST,
        command_states={"read": "allow", "delete": "block"},
    )
    _publish(store, identity, "read")
    store.upsert_local_cli_grant(
        identity=identity,
        state="allowed",
        expected_revision=store.read_local_cli_revision(),
        updated_at=_SECOND,
        command_states={"read": "review"},
    )
    assert store.read_local_cli_command_states(identity.cli_id) == {"read": "review", "delete": "block"}
    _publish(store, identity, "read", "delete")
    assert store.read_local_cli_command_states(identity.cli_id)["delete"] == "block"


def _catalog_view(store: GuardStore) -> dict[str, object]:
    return store.list_local_cli_items()[0]["mcp_catalog"]


def test_saving_choices_reviews_the_new_tools_they_cover(tmp_path: Path) -> None:
    store, identity = _store(tmp_path)
    _publish(store, identity, "read", "delete")
    assert _catalog_view(store)["changes"]["added"] == ["delete", "read"]
    revision = _catalog_view(store)["revision"]
    authority = _tool_authority(store, identity, "read")

    # A save that names no catalog revision reviews nothing.
    store.upsert_local_cli_grant(
        identity=identity,
        state="allowed",
        expected_revision=store.read_local_cli_revision(),
        updated_at=_SECOND,
        command_states={"read": "allow"},
    )
    assert _catalog_view(store)["changes"]["added"] == ["delete", "read"]
    # A tool whose choice was saved is reviewed; one left out still needs a look.
    store.upsert_local_cli_grant(
        identity=identity,
        state="allowed",
        expected_revision=store.read_local_cli_revision(),
        updated_at=_SECOND,
        command_states={"read": "allow"},
        reviewed_catalog_revision=revision,
    )
    assert _catalog_view(store)["changes"]["added"] == ["delete"]
    store.upsert_local_cli_grant(
        identity=identity,
        state="allowed",
        expected_revision=store.read_local_cli_revision(),
        updated_at=_SECOND,
        command_states={"read": "allow", "delete": "review"},
        reviewed_catalog_revision=revision,
    )
    view = _catalog_view(store)
    assert view["changes"] == {"added": [], "changed": [], "removed": [], "stale": []}
    # Reviewing changes nothing the catalog proves about the tools.
    assert view["revision"] == revision
    assert _tool_authority(store, identity, "read") == authority

    # A later listing still flags a tool that is new since then, and a save
    # made against the older catalog cannot clear it.
    _publish(store, identity, "read", "delete", "write")
    assert _catalog_view(store)["changes"]["added"] == ["write"]
    store.upsert_local_cli_grant(
        identity=identity,
        state="allowed",
        expected_revision=store.read_local_cli_revision(),
        updated_at=_SECOND,
        command_states={"read": "allow", "delete": "review", "write": "review"},
        reviewed_catalog_revision=revision,
    )
    assert _catalog_view(store)["changes"]["added"] == ["write"]


def test_the_other_tools_choice_reviews_only_the_tools_folded_into_it(tmp_path: Path) -> None:
    store, identity = _store(tmp_path)
    # "Résumé" has no valid id, so it is folded into the Other-tools choice; a
    # real tool named "other" has its own id and is not.
    store.replace_local_cli_commands(
        identity.cli_id,
        (
            *_commands("read", "other"),
            LocalCliCommand(slug_local_cli_command_id("other"), "other", "other", "Fixture tool"),
        ),
        mcp_catalog=_catalog("read", "Résumé", "other"),
        identity_hash=identity.identity_hash,
        seen_at=_FIRST,
    )
    store.upsert_local_cli_grant(
        identity=identity,
        state="allowed",
        expected_revision=store.read_local_cli_revision(),
        updated_at=_SECOND,
        command_states={"other": "review", "read": "allow"},
        reviewed_catalog_revision=_catalog_view(store)["revision"],
    )
    assert _catalog_view(store)["changes"]["added"] == ["other"]


def test_saving_choices_reviews_a_changed_tool(tmp_path: Path) -> None:
    store, identity = _store(tmp_path)
    _publish(store, identity, "read")
    store.upsert_local_cli_grant(
        identity=identity,
        state="allowed",
        expected_revision=store.read_local_cli_revision(),
        updated_at=_FIRST,
        command_states={"read": "allow"},
    )
    changed = replace(
        _catalog("read"),
        tools=({"name": "read", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}},),
    )
    store.replace_local_cli_commands(
        identity.cli_id,
        _commands("read"),
        mcp_catalog=changed,
        identity_hash=identity.identity_hash,
        seen_at=_SECOND,
    )
    assert _catalog_view(store)["changes"]["changed"] == ["read"]
    store.upsert_local_cli_grant(
        identity=identity,
        state="allowed",
        expected_revision=store.read_local_cli_revision(),
        updated_at=_SECOND,
        command_states={"read": "allow"},
        reviewed_catalog_revision=_catalog_view(store)["revision"],
    )
    assert _catalog_view(store)["changes"]["changed"] == []


def test_schema_changes_require_review_and_preserve_deny(tmp_path: Path) -> None:
    store, identity = _store(tmp_path)
    _publish(store, identity, "read", "delete")
    store.upsert_local_cli_grant(identity=identity, state="allowed", expected_revision=0, updated_at=_FIRST)
    store.upsert_local_cli_command_states(identity.cli_id, {"read": "allow", "delete": "block"})
    revision = store.read_local_cli_revision()
    changed = replace(
        _catalog("read", "delete"),
        tools=tuple(
            {"name": name, "inputSchema": {"type": "object", "properties": {"destination": {"type": "string"}}}}
            for name in ("read", "delete")
        ),
    )
    store.replace_local_cli_commands(
        identity.cli_id,
        _commands("read", "delete"),
        mcp_catalog=changed,
        identity_hash=identity.identity_hash,
        seen_at=_SECOND,
    )
    assert store.read_local_cli_command_states(identity.cli_id) == {"read": "review", "delete": "block"}
    assert store.read_local_cli_revision() == revision + 1


def test_cosmetic_description_does_not_reset_choices(tmp_path: Path) -> None:
    store, identity = _store(tmp_path)
    _publish(store, identity, "read")
    store.upsert_local_cli_grant(identity=identity, state="allowed", expected_revision=0, updated_at=_FIRST)
    store.upsert_local_cli_command_states(identity.cli_id, {"read": "allow"})
    revision = store.read_local_cli_revision()
    changed = replace(
        _catalog("read"),
        tools=(
            {
                "name": "read",
                "inputSchema": {"type": "object"},
                "description": "Updated presentation text",
            },
        ),
    )
    store.replace_local_cli_commands(
        identity.cli_id,
        _commands("read"),
        mcp_catalog=changed,
        identity_hash=identity.identity_hash,
        seen_at=_SECOND,
    )
    assert store.read_local_cli_command_states(identity.cli_id)["read"] == "allow"
    assert store.read_local_cli_revision() == revision


def test_stale_refresh_cannot_overwrite_newer_catalog(tmp_path: Path) -> None:
    store, identity = _store(tmp_path)
    _publish(store, identity, "read")
    store.replace_local_cli_commands(
        identity.cli_id,
        _commands("read", "search"),
        mcp_catalog=_catalog("read", "search"),
        identity_hash=identity.identity_hash,
        seen_at=_SECOND,
        expected_catalog_revision=1,
    )
    with pytest.raises(ValueError, match="mcp_catalog_revision_conflict"):
        store.replace_local_cli_commands(
            identity.cli_id,
            _commands("delete"),
            mcp_catalog=_catalog("delete"),
            identity_hash=identity.identity_hash,
            seen_at=_FIRST,
            expected_catalog_revision=1,
        )
    item = store.list_local_cli_items()[0]
    assert item["mcp_catalog"]["revision"] == 2
    assert [tool["name"] for tool in item["mcp_catalog"]["tools"]] == ["read", "search"]
    assert [command["command_id"] for command in item["commands"]] == ["read", "search"]


def test_catalog_is_hidden_after_identity_changes(tmp_path: Path) -> None:
    store, identity = _store(tmp_path)
    _publish(store, identity, "read")
    store.record_local_cli_observation(replace(identity, identity_hash="2" * 64), seen_at=_SECOND, surface="mcp")
    assert "mcp_catalog" not in store.list_local_cli_items()[0]
    with pytest.raises(ValueError, match="identity changed"):
        store.replace_local_cli_commands(
            identity.cli_id,
            _commands("delete"),
            mcp_catalog=_catalog("delete"),
            identity_hash=identity.identity_hash,
            seen_at=_SECOND,
        )
    assert [command.command_id for command in store.read_local_cli_command_catalog(identity.cli_id)] == ["read"]


def test_command_failure_rolls_back_catalog_evidence(tmp_path: Path) -> None:
    store, identity = _store(tmp_path)
    _publish(store, identity, "read")
    with pytest.raises(ValueError, match="command id"):
        store.replace_local_cli_commands(
            identity.cli_id,
            _commands("invalid command id"),
            mcp_catalog=_catalog("delete"),
            identity_hash=identity.identity_hash,
            seen_at=_SECOND,
        )
    item = store.list_local_cli_items()[0]
    assert item["mcp_catalog"]["revision"] == 1
    assert [tool["name"] for tool in item["mcp_catalog"]["tools"]] == ["read"]
    assert [command["command_id"] for command in item["commands"]] == ["read"]


def test_v10_migration_rebuilds_tool_hashes_without_changing_grants(tmp_path: Path):
    import sqlite3

    from codex_plugin_scanner.guard.store_local_cli_schema import _V10_CHECKSUM, ensure_local_cli_schema

    store, identity = _store(tmp_path)
    _publish(store, identity, "read")
    store.upsert_local_cli_grant(
        identity=identity, state="allowed", expected_revision=0, updated_at=_FIRST, command_states={"read": "block"}
    )
    before = _grant_and_authority(store, identity)
    with sqlite3.connect(store.path) as connection:
        connection.execute("drop table local_mcp_tool_authority")
        connection.execute("update local_cli_schema_migration set version = 10, checksum = ?", (_V10_CHECKSUM,))
        ensure_local_cli_schema(connection)
    assert _grant_and_authority(store, identity) == before


def test_a_save_names_its_catalog_revision_as_a_plain_count() -> None:
    from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiService
    from codex_plugin_scanner.guard.daemon.local_cli_api_contract import LocalCliApiError

    service = object.__new__(LocalCliApiService)
    assert service._optional_revision({}, "mcp_catalog_revision") is None
    assert service._optional_revision({"mcp_catalog_revision": 3}, "mcp_catalog_revision") == 3
    for invalid in (-1, True, "3", 3.0):
        with pytest.raises(LocalCliApiError) as raised:
            service._optional_revision({"mcp_catalog_revision": invalid}, "mcp_catalog_revision")
        assert raised.value.code == "invalid_mcp_catalog_revision"


def test_a_paged_mcp_read_migrates_an_older_store_before_the_native_read(tmp_path: Path):
    """The resident reads only the current schema; it never migrates one.

    Every paged read used to run the migration itself before touching these
    tables. An install that has not opened Guard since the provider tables
    landed still carries an older marker, so the migration has to happen on
    this side of the round trip or each page fails as an unreadable store.
    """

    import sqlite3

    from codex_plugin_scanner.guard.store_local_cli_schema import _V10_CHECKSUM, LOCAL_CLI_SCHEMA_VERSION

    store, identity = _store(tmp_path)
    _publish(store, identity, "read")
    with sqlite3.connect(store.path) as connection:
        connection.execute("update local_cli_schema_migration set version = 10, checksum = ?", (_V10_CHECKSUM,))

    skills = store.read_local_mcp_skills(identity.cli_id, offset=0, search="", expected_revision=None)
    assert skills["entries"] == []
    workflows = store.read_local_mcp_workflows(identity.cli_id)
    assert isinstance(workflows, dict)

    with store._connect() as connection:
        version = connection.execute("select version from local_cli_schema_migration").fetchone()[0]
    assert version == LOCAL_CLI_SCHEMA_VERSION
