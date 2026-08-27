from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.local_cli_hook import observe_unlisted_cli
from codex_plugin_scanner.guard.local_cli_trust import matching_local_cli_grant, utc_now
from codex_plugin_scanner.guard.runtime.local_cli_identity import identify_unlisted_cli
from codex_plugin_scanner.guard.store import GuardStore


def test_grant_allows_matching_args_and_not_changed_script(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    store = GuardStore(home)
    script = tmp_path / "cwv.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    identity = identify_unlisted_cli(f"python3 {script} --by url", cwd=tmp_path, home_dir=tmp_path)
    assert identity is not None
    store.record_local_cli_observation(identity, seen_at=utc_now())
    revision = store.upsert_local_cli_grant(
        identity=identity,
        state="allowed",
        expected_revision=0,
        updated_at=utc_now(),
    )
    assert revision == 1
    matched = matching_local_cli_grant(
        store=store,
        command=f"python3 {script} --by deviceType --days 3",
        cwd=tmp_path,
        home_dir=tmp_path,
        current_action="review",
    )
    assert matched is not None
    assert matched[1] == "allowed"
    script.write_text("print('changed')\n", encoding="utf-8")
    stale = matching_local_cli_grant(
        store=store,
        command=f"python3 {script} --by url",
        cwd=tmp_path,
        home_dir=tmp_path,
        current_action="review",
    )
    assert stale is None


def test_grant_does_not_override_block(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    store = GuardStore(home)
    script = tmp_path / "cwv.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    identity = identify_unlisted_cli(f"python3 {script}", cwd=tmp_path, home_dir=tmp_path)
    assert identity is not None
    store.upsert_local_cli_grant(
        identity=identity,
        state="allowed",
        expected_revision=0,
        updated_at=utc_now(),
    )
    assert (
        matching_local_cli_grant(
            store=store,
            command=f"python3 {script}",
            cwd=tmp_path,
            home_dir=tmp_path,
            current_action="block",
        )
        is None
    )


def test_blocked_grant_applies_to_review(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    store = GuardStore(home)
    script = tmp_path / "cwv.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    identity = identify_unlisted_cli(f"python3 {script}", cwd=tmp_path, home_dir=tmp_path)
    assert identity is not None
    store.upsert_local_cli_grant(
        identity=identity,
        state="blocked",
        expected_revision=0,
        updated_at=utc_now(),
    )
    matched = matching_local_cli_grant(
        store=store,
        command=f"python3 {script}",
        cwd=tmp_path,
        home_dir=tmp_path,
        current_action="review",
    )
    assert matched is not None
    assert matched[1] == "blocked"


def test_list_merges_observation_and_grant(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    store = GuardStore(home)
    script = tmp_path / "cwv.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    identity = identify_unlisted_cli(f"python3 {script}", cwd=tmp_path, home_dir=tmp_path)
    assert identity is not None
    store.record_local_cli_observation(identity, seen_at=utc_now())
    store.upsert_local_cli_grant(
        identity=identity,
        state="allowed",
        expected_revision=0,
        updated_at=utc_now(),
    )
    items = store.list_local_cli_items()
    assert len(items) == 1
    assert items[0]["cli_id"] == identity.cli_id
    assert items[0]["state"] == "allowed"
    assert items[0]["stale"] is False
    assert items[0]["observed_count"] == 1
    assert items[0]["suggestable"] is True


def test_grant_does_not_allow_compound_source_and_ssh(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    store = GuardStore(home)
    helper = tmp_path / "server-access.sh"
    helper.write_text("#!/bin/sh\necho access\n", encoding="utf-8")
    helper.chmod(0o755)
    command = f"source {helper} && ssh -o BatchMode=yes host 'echo ok'"
    observe_unlisted_cli(store=store, command=command, cwd=tmp_path, home_dir=tmp_path)
    identity = identify_unlisted_cli(f"bash {helper}", cwd=tmp_path, home_dir=tmp_path)
    assert identity is not None
    store.upsert_local_cli_grant(
        identity=identity,
        state="allowed",
        expected_revision=0,
        updated_at=utc_now(),
    )
    matched = matching_local_cli_grant(
        store=store,
        command=command,
        cwd=tmp_path,
        home_dir=tmp_path,
        current_action="review",
    )
    assert matched is None
    direct = matching_local_cli_grant(
        store=store,
        command=f"bash {helper} ssh 1",
        cwd=tmp_path,
        home_dir=tmp_path,
        current_action="review",
    )
    assert direct is not None
    assert direct[1] == "allowed"
