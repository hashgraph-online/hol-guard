"""Regression tests for advisories CLI parsing and the threat-intel cache schema."""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.store_threat_intel import (
    threat_intel_bundle_schema_statement,
    threat_intel_index_statements,
    threat_intel_matches_schema_statement,
)


def _in_memory_db() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.execute(threat_intel_bundle_schema_statement())
    conn.execute(threat_intel_matches_schema_statement())
    for stmt in threat_intel_index_statements():
        conn.execute(stmt)
    return conn


class TestCacheMigration:
    """T541 — cache tables created in existing database (migration test)."""

    def test_tables_created_in_new_db(self) -> None:
        conn = _in_memory_db()
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='guard_threat_intel_bundles'"
        ).fetchone()
        assert row is not None

    def test_indexes_created(self) -> None:
        conn = _in_memory_db()
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='guard_threat_intel_bundles'"
        ).fetchall()
        index_names = {r[0] for r in rows}
        assert "idx_ti_bundle_version" in index_names

    def test_idempotent_on_existing_table(self) -> None:
        conn = _in_memory_db()
        conn.execute(threat_intel_bundle_schema_statement())
        conn.execute(threat_intel_matches_schema_statement())
        for stmt in threat_intel_index_statements():
            conn.execute(stmt)


class TestAdvisoriesSubcommandArgParsing:
    """Regression — advisory subcommands must not overwrite parent --home value."""

    def test_home_flag_preserved_on_list_subcommand(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.cli.commands import add_guard_root_parser

        parser = argparse.ArgumentParser()
        add_guard_root_parser(parser)
        args = parser.parse_args(["advisories", "--home", str(tmp_path), "list"])
        assert str(args.home) == str(tmp_path)

    def test_home_flag_preserved_on_explain_subcommand(self, tmp_path: Path) -> None:
        from codex_plugin_scanner.guard.cli.commands import add_guard_root_parser

        parser = argparse.ArgumentParser()
        add_guard_root_parser(parser)
        args = parser.parse_args(["advisories", "--home", str(tmp_path), "explain", "ADV-001"])
        assert str(args.home) == str(tmp_path)

    def test_explain_searches_all_advisories_not_just_first_100(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """advisories explain must call list_cached_advisories with limit=None."""
        import codex_plugin_scanner.guard.store as store_mod
        from codex_plugin_scanner.guard.cli.commands import add_guard_root_parser, run_guard_command

        limit_captured: list[int | None] = []

        def spy(self: object, limit: int | None = 100) -> list[dict[str, object]]:
            limit_captured.append(limit)
            return [{"advisory_id": "ADV-999", "title": "Old advisory", "severity": "low"}]

        monkeypatch.setattr(store_mod.GuardStore, "list_cached_advisories", spy)

        parser = argparse.ArgumentParser()
        add_guard_root_parser(parser)
        args = parser.parse_args(["advisories", "--home", str(tmp_path), "explain", "ADV-999"])

        try:
            run_guard_command(args)
        except SystemExit:
            pass
        except Exception:
            pass

        explain_calls = [lim for lim in limit_captured if lim is None]
        assert explain_calls, f"explain did not call list_cached_advisories(limit=None), got: {limit_captured}"
