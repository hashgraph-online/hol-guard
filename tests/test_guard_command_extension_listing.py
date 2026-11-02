"""``command extensions`` reports every extension Guard delivers, not just core.

The wheel packages the core catalog only, so before this the inspection the
contributing guide points at called every merged community extension unknown.
"""

from __future__ import annotations

from argparse import Namespace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import commands_dispatch_local as dispatch
from codex_plugin_scanner.guard.cli import extension_controls_commands as controls
from codex_plugin_scanner.guard.cli import render
from codex_plugin_scanner.guard.daemon.client import GuardDaemonRequestError
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
    assert payload["native_catalog_digest"] == "sha256:delivered"
    assert payload["snapshot_id"] == "snapshot-1"
    assert [item["extension_id"] for item in payload["extensions"]] == [_CORE_ID, DELIVERED_ONLY_ID]


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

    assert render._command_extensions_title(payload) == expected
    assert render._plain_text_command_extensions(payload).startswith(f"{expected} (1)")
