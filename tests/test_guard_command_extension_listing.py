"""``command extensions`` reports every extension Guard delivers, not just core.

The wheel packages the core catalog only, so before this the inspection the
contributing guide points at called every merged community extension unknown.
"""

from __future__ import annotations

import io
from argparse import Namespace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import command_extension_listing as listing
from codex_plugin_scanner.guard.cli import commands_dispatch_local as dispatch
from codex_plugin_scanner.guard.cli import extension_controls_commands as controls
from codex_plugin_scanner.guard.cli import render
from codex_plugin_scanner.guard.cli.command_extension_listing import command_extensions_title
from codex_plugin_scanner.guard.cli.extension_catalog_reads import CATALOG_LIST_SCHEMA
from codex_plugin_scanner.guard.daemon.client import GuardDaemonRequestError, GuardDaemonResponseSchemaError
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY

DELIVERED_ONLY_ID = "command.master-of"
_CORE_ID = "command.git"


def _delivered_entry(extension_id: str) -> dict[str, object]:
    return {
        "extension_id": extension_id,
        "name": "master-of command protection",
        "version": "1.0.0",
        "description": "Reviews bulk mutation commands from the master-of CLI.",
        "action_classes": ["master-of bulk skill-gate mutation command"],
        "rule_count": 4,
        "permission_count": 4,
        "trust_class": "external",
        "catalog_defaults": {"activation": "opt-in", "enabled": False},
    }


class _DeliveredClient:
    """Stands in for a daemon serving the full delivered catalog."""

    def __init__(self, extension_ids: tuple[str, ...]) -> None:
        self.extension_ids = extension_ids
        self.calls = 0

    def extension_control_catalog(self) -> dict[str, object]:
        self.calls += 1
        return {
            "schema_version": "guard.extension-control-catalog.v1",
            "native_catalog_digest": "sha256:delivered",
            "snapshot_id": "snapshot-1",
            "extensions": [_delivered_entry(identifier) for identifier in self.extension_ids],
        }


def _run(args: Namespace, monkeypatch: pytest.MonkeyPatch) -> tuple[int, dict[str, object]]:
    emitted: list[tuple[object, ...]] = []
    monkeypatch.setattr(dispatch, "_emit", lambda *call: emitted.append(call), raising=False)
    exit_code = dispatch._run_guard_command_inspection_command(args)
    return exit_code, dict(emitted[0][1]) if emitted else {}


def _extensions_args(tmp_path: Path, extension_id: str | None) -> Namespace:
    return Namespace(command_command="extensions", extension_id=extension_id, guard_home=str(tmp_path), json=True)


def test_merged_community_extension_resolves_through_the_delivered_catalog(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    client = _DeliveredClient((DELIVERED_ONLY_ID,))
    monkeypatch.setattr(controls, "_client", lambda _: client)

    exit_code, payload = _run(_extensions_args(tmp_path, DELIVERED_ONLY_ID), monkeypatch)

    assert exit_code == 0
    assert payload["source"] == "delivered"
    assert payload["count"] == 1
    assert payload["extensions"][0]["extension_id"] == DELIVERED_ONLY_ID
    assert client.calls == 1


def test_core_extension_stays_offline_and_keeps_its_packaged_payload(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def forbidden_client(_: Path) -> object:
        pytest.fail("a packaged core extension must resolve without the daemon")

    monkeypatch.setattr(controls, "_client", forbidden_client)

    exit_code, payload = _run(_extensions_args(tmp_path, _CORE_ID), monkeypatch)

    assert exit_code == 0
    assert payload["source"] == "built-in"
    assert payload["extensions"][0]["extension_id"] == _CORE_ID


def test_full_listing_prefers_the_delivered_catalog(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    client = _DeliveredClient((_CORE_ID, DELIVERED_ONLY_ID))
    monkeypatch.setattr(controls, "_client", lambda _: client)

    exit_code, payload = _run(_extensions_args(tmp_path, None), monkeypatch)

    assert exit_code == 0
    assert payload["source"] == "delivered"
    assert payload["schema_version"] == "guard.extension-control-catalog.v1"
    assert payload["native_catalog_digest"] == "sha256:delivered"
    assert payload["snapshot_id"] == "snapshot-1"
    assert [item["extension_id"] for item in payload["extensions"]] == [_CORE_ID, DELIVERED_ONLY_ID]


def test_an_index_listing_keeps_the_index_schema_it_was_served(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A v2 daemon answers with index summaries, and the envelope says so."""

    index = {
        "schema_version": CATALOG_LIST_SCHEMA,
        "native_catalog_digest": "sha256:delivered",
        "snapshot_id": "snapshot-1",
        "extensions": [_delivered_entry(DELIVERED_ONLY_ID)],
    }
    monkeypatch.setattr(controls, "_client", lambda _: _DeliveredClient((DELIVERED_ONLY_ID,)))
    monkeypatch.setattr(listing, "catalog_list", lambda _: index)

    exit_code, payload = _run(_extensions_args(tmp_path, None), monkeypatch)

    assert exit_code == 0
    assert payload["source"] == "delivered"
    assert payload["schema_version"] == CATALOG_LIST_SCHEMA
    assert payload["snapshot_id"] == "snapshot-1"


def test_a_malformed_older_catalog_is_a_fault_not_a_missing_extension(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Reading one extension from a broken catalog reports the fault, not an unknown id."""

    class _MalformedClient:
        def extension_control_catalog(self) -> dict[str, object]:
            return {"schema_version": "guard.extension-control-catalog.v1", "extensions": "not-a-list"}

    monkeypatch.setattr(controls, "_client", lambda _: _MalformedClient())

    with pytest.raises(GuardDaemonResponseSchemaError):
        _run(_extensions_args(tmp_path, DELIVERED_ONLY_ID), monkeypatch)


def test_full_listing_falls_back_to_the_packaged_catalog_without_a_daemon(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def refuse(_: Path) -> object:
        raise GuardDaemonRequestError("Guard daemon is not running")

    monkeypatch.setattr(controls, "_client", refuse)

    exit_code, payload = _run(_extensions_args(tmp_path, None), monkeypatch)

    assert exit_code == 0
    assert payload["source"] == "built-in"
    assert payload["count"] == len(BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions)


def test_unreachable_daemon_says_only_the_packaged_catalog_was_searched(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def refuse(_: Path) -> object:
        raise GuardDaemonRequestError("Guard daemon is not running")

    monkeypatch.setattr(controls, "_client", refuse)

    exit_code, _ = _run(_extensions_args(tmp_path, DELIVERED_ONLY_ID), monkeypatch)
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "no running daemon could serve the delivered one" in captured.err


def test_an_extension_missing_from_both_catalogs_stays_unknown(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(controls, "_client", lambda _: _DeliveredClient((DELIVERED_ONLY_ID,)))

    exit_code, _ = _run(_extensions_args(tmp_path, "command.never-contributed"), monkeypatch)
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "Unknown command safety extension: command.never-contributed" in captured.err
    assert "no running daemon" not in captured.err


@pytest.mark.parametrize(
    ("source", "expected"),
    [("delivered", "Delivered command safety extensions"), ("built-in", "Built-in command safety extensions")],
)
def test_rendered_title_names_the_catalog_the_payload_came_from(source: str, expected: str) -> None:
    payload = {"source": source, "extensions": [_delivered_entry(DELIVERED_ONLY_ID)]}

    assert command_extensions_title(payload) == expected
    assert render._plain_text_command_extensions(payload).startswith(f"{expected} (1)")


def test_discovery_never_writes_the_guard_home_the_listing_reports_on(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Real endpoint discovery runs, and the inspected home comes back untouched.

    Deciding whether a live daemon matches this runtime can refresh Guard's
    private runtime fingerprint cache under the invoking user's own home. That
    cache is runtime bookkeeping; the home the listing reports on stays as the
    inspection found it, cache file present or missing.
    """

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    state_path = guard_home / "daemon-state.json"
    state_path.write_text('{"compatibility_version": "guard.daemon.v0", "port": 1, "pid": 1}\n', encoding="utf-8")
    before = sorted(entry.name for entry in guard_home.iterdir())

    private_home = tmp_path / "private-home"
    private_home.mkdir()
    monkeypatch.setenv("HOME", str(private_home))
    monkeypatch.setenv("USERPROFILE", str(private_home))
    monkeypatch.setattr(Path, "home", classmethod(lambda _: private_home))

    exit_code, payload = _run(_extensions_args(guard_home, None), monkeypatch)

    assert exit_code == 0
    assert payload["source"] == "built-in"
    assert sorted(entry.name for entry in guard_home.iterdir()) == before


def test_a_daemon_that_answers_badly_is_reported_rather_than_quietly_shortened(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A schema fault is a fault; only an absent daemon falls back to the packaged catalog."""

    class _BrokenClient:
        def extension_control_catalog(self) -> dict[str, object]:
            raise GuardDaemonResponseSchemaError("daemon returned a malformed catalog", status=500)

    monkeypatch.setattr(controls, "_client", lambda _: _BrokenClient())

    with pytest.raises(GuardDaemonResponseSchemaError):
        _run(_extensions_args(tmp_path, None), monkeypatch)


def test_a_daemon_error_carrying_a_status_keeps_its_own_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class _ServerErrorClient:
        def extension_control_catalog(self) -> dict[str, object]:
            raise GuardDaemonRequestError("catalog traversal is incomplete", status=503, code="catalog_incomplete")

    monkeypatch.setattr(controls, "_client", lambda _: _ServerErrorClient())

    with pytest.raises(GuardDaemonRequestError) as raised:
        _run(_extensions_args(tmp_path, DELIVERED_ONLY_ID), monkeypatch)

    assert raised.value.code == "catalog_incomplete"


def test_contributor_text_cannot_colour_or_steer_the_terminal() -> None:
    hostile = {
        "extension_id": "command.master-of",
        "version": "1.0.0",
        "description": "[bold red]owned[/] \x1b[2Jcleared\r\nsecond line",
        "action_classes": [],
        "rule_count": 0,
    }
    payload = {"source": "delivered", "extensions": [hostile]}

    plain = render._plain_text_command_extensions(payload)

    assert "\x1b" not in plain
    assert "\r" not in plain and plain.count("\n") == 1
    assert "[bold red]owned[/]" in plain

    console = render.Console(file=io.StringIO(), width=200, force_terminal=True, no_color=False)
    render._render_command_extensions(console, payload)
    rendered = console.file.getvalue()

    assert "\x1b[2J" not in rendered
    assert "[bold red]" in rendered
