"""Actual frozen v4 schema code must reject the pack-activation writer floor."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.extension_control_authority import ExtensionControlAuthorityError
from codex_plugin_scanner.guard.store_extension_control_authority_schema import (
    ensure_extension_control_authority_schema,
)


def old_schema():
    # Frozen from public19f6969; CI does not need Git history or a download.
    fixture = Path(__file__).parent / "fixtures/extension-control-schema-v4.py.txt"
    scope = {"__name__": "codex_plugin_scanner.guard._v4_schema_fixture", "__package__": "codex_plugin_scanner.guard"}
    # The scope above makes coverage trace this as package code, so give
    # `compile` the fixture's real path: a bare name matches no `omit`
    # pattern and leaves `coverage report` looking for a file that is not
    # there.
    exec(compile(fixture.read_text(), str(fixture), "exec"), scope)
    return scope["ensure_extension_control_authority_schema"]


def test_pack_floor_is_explicit_and_old_writer_cannot_downgrade_it():
    connection = sqlite3.connect(":memory:")
    ensure_extension_control_authority_schema(connection)
    connection.commit()
    old = old_schema()
    assert old(connection)
    assert connection.execute("select version from extension_control_schema_migration").fetchone()[0] == 4
    with connection:
        ensure_extension_control_authority_schema(connection, activate_packs=True)
    assert not old(connection, require_compatible=False)
    with pytest.raises(ExtensionControlAuthorityError, match="unsupported"):
        old(connection)
    ensure_extension_control_authority_schema(connection)
    assert connection.execute("select version from extension_control_schema_migration").fetchone()[0] == 5


def test_failed_activation_transaction_rolls_back_the_new_writer_floor():
    connection = sqlite3.connect(":memory:")
    ensure_extension_control_authority_schema(connection)
    connection.commit()
    with pytest.raises(RuntimeError, match="interrupted"), connection:
        ensure_extension_control_authority_schema(connection, activate_packs=True)
        raise RuntimeError("interrupted activation")
    assert connection.execute("select version from extension_control_schema_migration").fetchone()[0] == 4
    assert old_schema()(connection)


def test_activation_v2_fences_the_actual_schema5_writer_without_hiding_v1():
    fixture = Path(__file__).parent / "fixtures/extension-control-schema-v5.py.txt"
    scope = {"__name__": "codex_plugin_scanner.guard._v5_schema_fixture", "__package__": "codex_plugin_scanner.guard"}
    exec(compile(fixture.read_text(), str(fixture), "exec"), scope)
    old = scope["ensure_extension_control_authority_schema"]
    connection = sqlite3.connect(":memory:")
    old(connection, activate_packs=True)
    assert connection.execute("select version from extension_control_schema_migration").fetchone()[0] == 5
    ensure_extension_control_authority_schema(connection)
    assert connection.execute("select version from extension_control_schema_migration").fetchone()[0] == 5
    ensure_extension_control_authority_schema(connection, activation_format_v2=True)
    assert not old(connection, require_compatible=False)
    with pytest.raises(ExtensionControlAuthorityError, match="unsupported"):
        old(connection)
    ensure_extension_control_authority_schema(connection)
    assert connection.execute("select version from extension_control_schema_migration").fetchone()[0] == 6
