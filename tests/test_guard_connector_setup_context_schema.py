"""Schema v14: the setup context columns, the derived resolution state and the regroup of pending reviews."""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.store_local_cli_context import (
    CONTEXT_COLUMNS,
    FIRST_BLOCKED_CAUSES,
    connector_resolution_state,
    validated_first_blocked_cause,
)
from codex_plugin_scanner.guard.store_local_cli_regroup import (
    NON_RECOGNITION_RISK_SUMMARIES,
    connector_program_name,
    connector_program_path,
    connector_queue_group_id,
    regroup_pending_connector_reviews,
)
from codex_plugin_scanner.guard.store_local_cli_schema import (
    _SCHEMA_CHECKSUM,
    _V13_CHECKSUM,
    LOCAL_CLI_SCHEMA_VERSION,
    ensure_local_cli_schema,
)

_ROOT = Path(__file__).resolve().parents[1]
_VECTORS = _ROOT / "rust/crates/guard-runtime/testdata/connector_setup/connector_group_vectors.json"
_UNRECOGNISED, _OUTSIDE_ROOTS = NON_RECOGNITION_RISK_SUMMARIES
_HASH = "a" * 64
_OTHER_HASH = "b" * 64


def _columns(connection: sqlite3.Connection, table: str) -> list[str]:
    return [str(row[1]) for row in connection.execute(f"pragma table_info({table})").fetchall()]


def _marker(connection: sqlite3.Connection) -> tuple[int, str]:
    row = connection.execute("select version, checksum from local_cli_schema_migration where singleton = 1").fetchone()
    return int(row[0]), str(row[1])


def _observe(
    connection: sqlite3.Connection,
    name: str,
    identity_hash: str = _HASH,
    *,
    suffix: str = "1",
    source_path: str | None = None,
) -> str:
    cli_id = f"local-cli.{name}-{suffix}"
    connection.execute(
        "insert into local_cli_observation (cli_id, identity_hash, kind, name, example_label, observed_count, "
        "last_seen_at, source_path) values (?, ?, 'executable', ?, ?, 1, '2026-01-01T00:00:00Z', ?)",
        (cli_id, identity_hash, name, name, source_path),
    )
    return cli_id


_WORKSPACE = "/work/project"


def _approvals(connection: sqlite3.Connection) -> None:
    connection.execute(
        "create table approval_requests (request_id text primary key, status text not null, risk_summary text, "
        "raw_command_text text, queue_group_id text, workspace text, "
        "created_at text not null default '2026-01-01T00:00:00Z')"
    )


def _queue(
    connection: sqlite3.Connection,
    request_id: str,
    command: str | None,
    *,
    status: str = "pending",
    reason: str = _UNRECOGNISED,
    group: str = "action:old",
    workspace: str | None = _WORKSPACE,
) -> None:
    connection.execute(
        "insert into approval_requests (request_id, status, risk_summary, raw_command_text, queue_group_id, workspace) "
        "values (?, ?, ?, ?, ?, ?)",
        (request_id, status, reason, command, group, workspace),
    )


def _groups(connection: sqlite3.Connection) -> dict[str, str]:
    return {row[0]: row[1] for row in connection.execute("select request_id, queue_group_id from approval_requests")}


def _v13_store(tmp_path: Path) -> sqlite3.Connection:
    """A store as the previous release left it: no context columns, marker at v13."""

    connection = sqlite3.connect(tmp_path / "guard.db")
    ensure_local_cli_schema(connection)
    for column in CONTEXT_COLUMNS:
        connection.execute(f"alter table local_cli_observation drop column {column}")
    connection.execute(
        "update local_cli_schema_migration set version = 13, checksum = ? where singleton = 1", (_V13_CHECKSUM,)
    )
    connection.commit()
    return connection


def test_a_fresh_store_has_the_nullable_context_columns(tmp_path: Path) -> None:
    with sqlite3.connect(tmp_path / "guard.db") as connection:
        ensure_local_cli_schema(connection)

        assert _marker(connection) == (14, _SCHEMA_CHECKSUM)
        assert LOCAL_CLI_SCHEMA_VERSION == 14
        columns = _columns(connection, "local_cli_observation")
        assert all(column in columns for column in CONTEXT_COLUMNS)
        _observe(connection, "lanectl")
        row = connection.execute(f"select {', '.join(CONTEXT_COLUMNS)} from local_cli_observation").fetchone()
        assert tuple(row) == (None,) * len(CONTEXT_COLUMNS)


def test_no_resolution_state_is_stored(tmp_path: Path) -> None:
    with sqlite3.connect(tmp_path / "guard.db") as connection:
        ensure_local_cli_schema(connection)

        columns = _columns(connection, "local_cli_observation")
        assert not [column for column in columns if "resolution" in column or column.endswith("_state")]


def test_v13_migrates_to_v14_and_keeps_every_decision(tmp_path: Path) -> None:
    connection = _v13_store(tmp_path)
    cli_id = _observe(connection, "lanectl")
    connection.execute(
        "insert into local_cli_grant values (?, ?, 'allowed', 3, '2026-01-02T00:00:00Z')", (cli_id, _HASH)
    )
    before = connection.execute("select * from local_cli_grant").fetchall()
    before_observation = connection.execute("select cli_id, identity_hash, name from local_cli_observation").fetchall()

    ensure_local_cli_schema(connection)

    assert _marker(connection) == (14, _SCHEMA_CHECKSUM)
    assert all(column in _columns(connection, "local_cli_observation") for column in CONTEXT_COLUMNS)
    assert connection.execute("select * from local_cli_grant").fetchall() == before
    after = connection.execute("select cli_id, identity_hash, name from local_cli_observation").fetchall()
    assert after == before_observation
    row = connection.execute(f"select {', '.join(CONTEXT_COLUMNS)} from local_cli_observation").fetchone()
    assert tuple(row) == (None,) * len(CONTEXT_COLUMNS)
    connection.close()


def test_migrating_twice_changes_nothing(tmp_path: Path) -> None:
    connection = _v13_store(tmp_path)
    ensure_local_cli_schema(connection)
    columns = _columns(connection, "local_cli_observation")

    ensure_local_cli_schema(connection)

    assert _columns(connection, "local_cli_observation") == columns
    assert _marker(connection) == (14, _SCHEMA_CHECKSUM)
    connection.close()


def test_a_store_without_an_approval_table_still_migrates(tmp_path: Path) -> None:
    connection = _v13_store(tmp_path)

    ensure_local_cli_schema(connection)

    assert _marker(connection) == (14, _SCHEMA_CHECKSUM)
    connection.close()


@pytest.mark.parametrize("cause", FIRST_BLOCKED_CAUSES)
def test_every_known_first_blocked_cause_is_accepted(cause: str) -> None:
    assert validated_first_blocked_cause(cause) == cause


@pytest.mark.parametrize("cause", ["", "Exec_Outside_Roots", "exec_outside_roots ", "network", 7, b"x"])
def test_an_unknown_first_blocked_cause_is_refused(cause: object) -> None:
    with pytest.raises(ValueError, match="invalid_first_blocked_cause"):
        validated_first_blocked_cause(cause)


def test_the_absent_cause_is_none() -> None:
    assert validated_first_blocked_cause(None) is None
    assert len(FIRST_BLOCKED_CAUSES) == 5


def test_resolution_state_is_read_from_the_grant(tmp_path: Path) -> None:
    with sqlite3.connect(tmp_path / "guard.db") as connection:
        ensure_local_cli_schema(connection)
        cli_id = _observe(connection, "lanectl")

        assert connector_resolution_state(connection, cli_id, _HASH) == "unset"
        connection.execute(
            "insert into local_cli_grant values (?, ?, 'allowed', 1, '2026-01-02T00:00:00Z')", (cli_id, _HASH)
        )
        assert connector_resolution_state(connection, cli_id, _HASH) == "allowed"
        # A grant made for another identity of this CLI does not apply.
        assert connector_resolution_state(connection, cli_id, _OTHER_HASH) == "unset"
        connection.execute("update local_cli_grant set state = 'blocked', revision = 2")
        assert connector_resolution_state(connection, cli_id, _HASH) == "blocked"
        connection.execute("delete from local_cli_grant")
        assert connector_resolution_state(connection, cli_id, _HASH) == "unset"


def test_resolution_state_without_a_grant_table_is_unset() -> None:
    with sqlite3.connect(":memory:") as connection:
        assert connector_resolution_state(connection, "local-cli.lanectl-1", _HASH) == "unset"


def test_pending_unrecognised_reviews_regroup_under_the_connector(tmp_path: Path) -> None:
    connection = _v13_store(tmp_path)
    _approvals(connection)
    _observe(connection, "lanectl", source_path="/usr/local/bin/lanectl")
    _queue(connection, "r1", "lanectl status")
    _queue(connection, "r2", "/usr/local/bin/lanectl ping --verbose", reason=_OUTSIDE_ROOTS)
    connection.commit()

    ensure_local_cli_schema(connection)

    groups = _groups(connection)
    assert groups["r1"] == connector_queue_group_id(_HASH, _WORKSPACE, "lanectl status")
    assert groups["r2"] == connector_queue_group_id(_HASH, _WORKSPACE, "/usr/local/bin/lanectl ping --verbose")
    assert groups["r1"].startswith(f"connector:{_HASH}:")
    assert len(groups["r1"].rsplit(":", 1)[1]) == 16
    connection.close()


def test_regroup_changes_only_the_group_and_creates_nothing(tmp_path: Path) -> None:
    connection = _v13_store(tmp_path)
    _approvals(connection)
    _observe(connection, "lanectl")
    _queue(connection, "r1", "lanectl status")
    connection.commit()
    before = connection.execute(
        "select request_id, status, risk_summary, raw_command_text from approval_requests"
    ).fetchall()
    tables = connection.execute("select count(*) from sqlite_master where type = 'table'").fetchone()[0]

    ensure_local_cli_schema(connection)

    after = connection.execute(
        "select request_id, status, risk_summary, raw_command_text from approval_requests"
    ).fetchall()
    assert after == before
    # Only the context columns were added; no table and no row was created or removed.
    assert connection.execute("select count(*) from sqlite_master where type = 'table'").fetchone()[0] == tables
    assert connection.execute("select count(*) from approval_requests").fetchone()[0] == 1
    connection.close()


def test_regroup_skips_what_it_cannot_tie_to_one_undecided_cli(tmp_path: Path) -> None:
    connection = _v13_store(tmp_path)
    _approvals(connection)
    _observe(connection, "lanectl")
    _observe(connection, "twinctl", _HASH, suffix="1")
    _observe(connection, "twinctl", _OTHER_HASH, suffix="2")
    decided = _observe(connection, "decidedctl")
    connection.execute(
        "insert into local_cli_grant values (?, ?, 'blocked', 1, '2026-01-02T00:00:00Z')", (decided, _HASH)
    )
    skipped = {
        "compound": "lanectl status && echo done",
        "pipe": "lanectl status | cat",
        "redirect": "lanectl status > out.txt",
        "quoted": "lanectl 'status now'",
        "expansion": "lanectl $HOME",
        "substitution": "lanectl $(whoami)",
        "env-prefix": "TOKEN=abc lanectl status",
        "runner": "npx lanectl status",
        "unobserved": "otherctl status",
        "ambiguous": "twinctl status",
        "decided": "decidedctl status",
        "non-ascii": "lanectl status é",
        "empty": "",
    }
    for key, command in skipped.items():
        _queue(connection, key, command)
    _queue(connection, "decided-by-status", "lanectl status", status="approved")
    _queue(connection, "other-reason", "lanectl status", reason="HOL Guard found a network request.")
    _queue(connection, "no-command", None)
    connection.commit()

    ensure_local_cli_schema(connection)

    assert set(_groups(connection).values()) == {"action:old"}
    connection.close()


@pytest.mark.parametrize(
    ("source_path", "command", "moves"),
    [
        ("/opt/tools/lanectl", "lanectl status", True),
        ("/opt/tools/lanectl", "/opt/tools/lanectl status", True),
        ("/opt/tools/lanectl", "/elsewhere/lanectl status", False),
        ("/opt/tools/lanectl", "./lanectl status", False),
        (None, "lanectl status", True),
        (None, "/opt/tools/lanectl status", False),
    ],
)
def test_a_program_written_with_a_path_must_be_the_observed_executable(
    tmp_path: Path, source_path: str | None, command: str, moves: bool
) -> None:
    connection = _v13_store(tmp_path)
    _approvals(connection)
    _observe(connection, "lanectl", source_path=source_path)
    _queue(connection, "r1", command)
    connection.commit()

    ensure_local_cli_schema(connection)

    expected = connector_queue_group_id(_HASH, _WORKSPACE, command) if moves else "action:old"
    assert _groups(connection) == {"r1": expected}
    connection.close()


def test_regroup_leaves_the_rows_of_a_non_plain_observation(tmp_path: Path) -> None:
    connection = _v13_store(tmp_path)
    _approvals(connection)
    connection.execute(
        "insert into local_cli_observation (cli_id, identity_hash, kind, name, interpreter_name, example_label, "
        "observed_count, last_seen_at) values ('local-cli.lanectl-script', ?, 'script', 'lanectl', 'node', "
        "'lanectl.js', 1, '2026-01-01T00:00:00Z')",
        (_HASH,),
    )
    _queue(connection, "r1", "lanectl status")
    connection.commit()

    ensure_local_cli_schema(connection)

    assert _groups(connection) == {"r1": "action:old"}
    connection.close()


def test_a_regroup_failure_never_blocks_the_schema_bump(tmp_path: Path) -> None:
    connection = _v13_store(tmp_path)
    _approvals(connection)
    _observe(connection, "lanectl")
    _queue(connection, "r1", "lanectl status")
    connection.execute(
        "create trigger refuse_regroup before update of queue_group_id on approval_requests "
        "begin select raise(abort, 'refused'); end"
    )
    connection.commit()

    ensure_local_cli_schema(connection)

    assert _marker(connection) == (14, _SCHEMA_CHECKSUM)
    assert _groups(connection) == {"r1": "action:old"}
    connection.close()


def test_a_regroup_on_a_malformed_approval_table_moves_nothing() -> None:
    with sqlite3.connect(":memory:") as connection:
        connection.execute("create table approval_requests (request_id text, status text)")
        connection.execute(
            "create table local_cli_observation (cli_id text, identity_hash text, name text, kind text, surface text)"
        )

        assert regroup_pending_connector_reviews(connection) == 0


def test_the_regroup_is_idempotent(tmp_path: Path) -> None:
    connection = _v13_store(tmp_path)
    _approvals(connection)
    _observe(connection, "lanectl")
    _queue(connection, "r1", "lanectl status")
    connection.commit()
    ensure_local_cli_schema(connection)
    groups = _groups(connection)

    assert regroup_pending_connector_reviews(connection) == 0
    assert _groups(connection) == groups
    connection.close()


def test_program_paths() -> None:
    assert connector_program_path("lanectl status") is None
    assert connector_program_path("/opt/tools/lanectl --json") == "/opt/tools/lanectl"
    assert connector_program_path("./lanectl") == "./lanectl"
    assert connector_program_path("") is None


def test_plain_program_names() -> None:
    assert connector_program_name("lanectl status") == "lanectl"
    assert connector_program_name("/opt/tools/lanectl --json") == "lanectl"
    assert connector_program_name("./lanectl status") == "lanectl"
    for command in ["", "lanectl 'a b'", "pnpm lanectl", "FOO=1 lanectl", "lanectl;ls", "bin/ status", "x" * 5000]:
        assert connector_program_name(command) is None, command


def test_group_ids_match_the_resident_vectors() -> None:
    payload = json.loads(_VECTORS.read_text(encoding="utf-8"))
    assert payload["schema"] == "hol-guard.connector-group-vectors.v1"
    assert len(payload["vectors"]) >= 10
    for vector in payload["vectors"]:
        group = connector_queue_group_id(vector["identity_hash"], vector["cwd"], vector["command"])
        assert group == vector["queue_group_id"], vector


def test_the_regroup_reasons_are_the_texts_the_resident_stores() -> None:
    pretool = (_ROOT / "rust/crates/guard-command/src/pretool.rs").read_text(encoding="utf-8")
    contained = (_ROOT / "rust/crates/guard-command/src/pretool/workspace_contained.rs").read_text(encoding="utf-8")
    fragments = re.findall(r'"([^"\n]*)"', contained[contained.index("concat!(") :][:200])

    assert _UNRECOGNISED in pretool
    assert "".join(fragments[:2]).replace("\\'", "'") == _OUTSIDE_ROOTS


def test_a_review_without_a_workspace_keeps_its_group(tmp_path: Path) -> None:
    connection = _v13_store(tmp_path)
    _approvals(connection)
    _observe(connection, "lanectl", source_path="/usr/local/bin/lanectl")
    _queue(connection, "r1", "lanectl status", workspace=None)
    _queue(connection, "r2", "lanectl status", workspace="/work/other")
    connection.commit()

    ensure_local_cli_schema(connection)

    groups = _groups(connection)
    assert groups["r1"] == "action:old"
    assert groups["r2"] == connector_queue_group_id(_HASH, "/work/other", "lanectl status")
    assert groups["r2"] != connector_queue_group_id(_HASH, _WORKSPACE, "lanectl status")
    connection.close()
