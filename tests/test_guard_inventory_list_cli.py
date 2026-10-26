"""``hol-guard extensions list`` reads the local inventory fleet posture reports from."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import _build_parser, main
from codex_plugin_scanner.guard.cli import run_guard_command
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.runtime.fleet_posture_inventory import inventory_items
from codex_plugin_scanner.guard.store import GuardStore

pytestmark = [pytest.mark.usefixtures("native_hook_force")]

_NOW = "2026-10-16T12:00:00+00:00"
_LATER = "2026-10-17T12:00:00+00:00"


def _run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    rc = main(["guard", *argv])
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


def _record(
    store: GuardStore,
    *,
    harness: str,
    artifact_type: str,
    name: str,
    scope: str = "global",
    now: str = _NOW,
) -> None:
    store.record_inventory_artifact(
        artifact=GuardArtifact(
            artifact_id=f"{harness}:{scope}:{artifact_type}:{name}",
            name=name,
            harness=harness,
            artifact_type=artifact_type,
            source_scope=scope,
            config_path=f"/home/user/.config/{harness}/{name}.json",
        ),
        artifact_hash="a" * 64,
        policy_action="allow",
        changed=False,
        now=now,
        approved=True,
    )


def _seed(home: Path) -> None:
    store = GuardStore(home)
    _record(store, harness="opencode", artifact_type="mcp_server", name="filesystem")
    _record(store, harness="codex", artifact_type="mcp_server", name="github", scope="project")
    _record(store, harness="opencode", artifact_type="plugin", name="notify")
    _record(store, harness="opencode", artifact_type="plugin-file", name="local-plugin")
    _record(store, harness="gemini", artifact_type="extension", name="gemini-ext")
    _record(store, harness="codex", artifact_type="skill", name="review-skill")


def test_list_with_an_empty_inventory(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "home"
    command = "extensions"

    rc, out, _ = _run(capsys, command, "list", "--home", str(home), "--json")
    payload = json.loads(out)

    assert rc == 0
    assert payload["kind"] == command
    assert payload["count"] == 0
    assert payload["items"] == []

    rc, out, _ = _run(capsys, command, "list", "--home", str(home))
    assert rc == 0
    assert "0 in the local Guard inventory" in out
    assert "Guard has not recorded any yet." in out


def test_extensions_list_shows_plugins_and_extensions_only(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "home"
    _seed(home)

    rc, out, _ = _run(capsys, "extensions", "list", "--home", str(home), "--json")
    payload = json.loads(out)

    assert rc == 0
    assert payload["kind"] == "extensions"
    assert payload["count"] == 3
    assert [(item["harness"], item["name"], item["artifact_type"]) for item in payload["items"]] == [
        ("gemini", "gemini-ext", "extension"),
        ("opencode", "local-plugin", "plugin-file"),
        ("opencode", "notify", "plugin"),
    ]


def test_json_items_have_a_stable_shape(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "home"
    _seed(home)

    _, out, _ = _run(capsys, "extensions", "list", "--home", str(home), "--json")
    payload = json.loads(out)
    item = payload["items"][0]

    assert set(payload) == {"generated_at", "kind", "count", "items"}
    assert set(item) == {
        "name",
        "harness",
        "artifact_type",
        "source_scope",
        "config_path",
        "artifact_hash",
        "policy_action",
        "first_seen_at",
        "last_seen_at",
    }
    assert item["source_scope"] == "global"
    assert item["policy_action"] == "allow"
    assert item["first_seen_at"] == "2026-10-16T12:00:00Z"


def test_table_output_lists_each_item(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "home"
    _seed(home)

    rc, out, _ = _run(capsys, "extensions", "list", "--home", str(home))
    assert rc == 0
    assert "Plugins and extensions" in out
    assert "3 in the local Guard inventory" in out
    assert "gemini-ext" in out
    assert "filesystem" not in out


def test_list_hides_artifacts_marked_removed(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "home"
    _seed(home)
    GuardStore(home).mark_inventory_removed(
        harness="opencode",
        artifact_id="opencode:global:plugin:notify",
        policy_action="allow",
        artifact_hash="a" * 64,
        now=_LATER,
    )

    _, out, _ = _run(capsys, "extensions", "list", "--home", str(home), "--json")

    assert [item["name"] for item in json.loads(out)["items"]] == ["gemini-ext", "local-plugin"]


def test_list_is_read_only_and_leaves_fleet_posture_state_alone(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from codex_plugin_scanner.guard.runtime import fleet_posture as fp

    home = tmp_path / "home"
    _seed(home)

    for command in ("extensions", "mcp"):
        rc, _, _ = _run(capsys, command, "list", "--home", str(home), "--json")
        assert rc == 0

    assert not fp.full_inventory_requested(GuardStore(home))
    assert len(GuardStore(home).list_inventory()) == 6


def test_extension_authoring_and_mcp_serve_parsers_are_unchanged(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["guard", "mcp", "--help"])
    assert exit_info.value.code == 0
    help_text = capsys.readouterr().out
    assert "serve" in help_text
    assert "list" in help_text

    with pytest.raises(SystemExit) as exit_info:
        main(["guard", "extensions", "--help"])
    assert exit_info.value.code == 0
    help_text = capsys.readouterr().out
    for subcommand in ("generate", "validate", "diff", "apply", "handoff", "list"):
        assert subcommand in help_text


def test_list_selection_matches_what_fleet_posture_reports(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "home"
    store = GuardStore(home)
    _seed(home)
    # Same kind, harness, name and path as the plugin above: fleet posture reports it once.
    _record(store, harness="opencode", artifact_type="extension", name="notify")
    # Not a harness fleet posture reports on, and a row with an unreadable timestamp.
    _record(store, harness="not-a-harness", artifact_type="mcp_server", name="stray")
    _record(store, harness="codex", artifact_type="mcp_server", name="bad-time", now="not-a-time")

    reported = [
        (item["harness"], item["name"], item["kind"])
        for item in inventory_items(GuardStore(home), hash_key=b"k" * 32)
        if item["kind"] in {"plugin", "mcp_server"}
    ]

    _, ext_out, _ = _run(capsys, "extensions", "list", "--home", str(home), "--json")
    extensions = json.loads(ext_out)
    listed = [(item["harness"], item["name"]) for item in extensions["items"]]

    assert sorted(listed) == sorted((harness, name) for harness, name, kind in reported if kind == "plugin")
    assert extensions["count"] == 3


def test_table_shows_markup_in_names_literally(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "home"
    store = GuardStore(home)
    _record(store, harness="opencode", artifact_type="plugin", name="[bold red]loud[/bold red]")

    rc, out, _ = _run(capsys, "extensions", "list", "--home", str(home))

    assert rc == 0
    assert "[bold" in out  # the cell may wrap, but the brackets must survive
    assert "[/bold" in out


def test_output_goes_to_the_callers_stream(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "home"
    _seed(home)
    args = _build_parser("hol-guard", program_mode="guard").parse_args(
        ["extensions", "list", "--home", str(home), "--json"]
    )
    stream = io.StringIO()

    assert run_guard_command(args, output_stream=stream) == 0

    assert json.loads(stream.getvalue())["count"] == 3
    assert capsys.readouterr().out == ""
