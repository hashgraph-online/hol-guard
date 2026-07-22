from __future__ import annotations

import argparse
import io
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli import extension_controls_commands
from codex_plugin_scanner.guard.cli.extension_controls_commands import (
    _mutation_payload,
    run_extension_controls_command,
)


def _effective() -> dict[str, object]:
    return {
        "revision": 4,
        "catalog_digest": "a" * 64,
        "layers": [
            {
                "schema_version": "1.0.0",
                "kind": "local-admin",
                "catalog_digest": "a" * 64,
                "global_lockdown": False,
                "controls": [{"target_kind": "extension", "target_id": "existing", "state": "disabled"}],
            }
        ],
    }


def test_control_mutation_preserves_existing_local_controls() -> None:
    payload = _mutation_payload(
        _effective(),
        argparse.Namespace(
            controls_command="apply",
            target_kind="extension",
            target_id="new-target",
            state="disabled",
        ),
    )

    layers = payload["layers"]
    assert isinstance(layers, list)
    controls = layers[0]["controls"]
    assert [control["target_id"] for control in controls] == ["existing", "new-target"]


def test_global_lockdown_state_maps_without_changing_controls() -> None:
    payload = _mutation_payload(
        _effective(),
        argparse.Namespace(controls_command="global-apply", state="enabled"),
    )

    layers = payload["layers"]
    assert isinstance(layers, list)
    assert layers[0]["global_lockdown"] is True
    assert layers[0]["controls"][0]["target_id"] == "existing"


def test_status_without_daemon_is_read_only(tmp_path: Path) -> None:
    guard_home = tmp_path / "absent"
    output = io.StringIO()

    result = run_extension_controls_command(
        argparse.Namespace(controls_command="status"),
        guard_home=guard_home,
        output_stream=output,
    )

    assert result == 2
    assert not guard_home.exists()


@pytest.mark.parametrize("program_name", ["hol-guard", "plugin-scanner", "plugin-guard", "plugin-ecosystem-scanner"])
def test_controls_help_is_available_from_every_installed_alias(
    program_name: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", [program_name])
    with pytest.raises(SystemExit) as exit_info:
        main(["guard", "command", "controls", "--help"])

    assert exit_info.value.code == 0
    assert (
        "{status,list,show,preview,apply,global-preview,global-apply,enroll,recover-authority,acknowledge-degraded}"
    ) in capsys.readouterr().out


@pytest.mark.parametrize(
    ("command", "expected_calls"),
    (
        ("recover-authority", ("prompt", "require", "consume", "recover", "refresh")),
        ("acknowledge-degraded", ("prompt", "acknowledge")),
    ),
)
def test_authority_recovery_requires_and_consumes_fresh_local_approval(
    command: str,
    expected_calls: tuple[str, ...],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    view = SimpleNamespace(
        health=SimpleNamespace(value="tampered"),
        revision=7,
        catalog_digest="catalog",
    )

    class FakeStore:
        def __init__(self, guard_home: Path) -> None:
            assert guard_home == tmp_path

        def read_extension_control_authority(self, *, catalog_digest: str) -> object:
            assert catalog_digest
            return view

        def recover_extension_control_authority(self, *, catalog_digest: str) -> object:
            assert catalog_digest
            calls.append("recover")
            return view

    class FakeClient:
        def refresh_extension_controls(self) -> dict[str, object]:
            calls.append("refresh")
            return {"health": "protected", "revision": 7}

        def acknowledge_degraded_extension_controls(
            self,
            payload: dict[str, object],
        ) -> dict[str, object]:
            assert payload["approval_password"] == "password"
            assert payload["approval_totp_code"] == "123456"
            assert isinstance(payload["session_nonce"], str)
            calls.append("acknowledge")
            return {"health": "degraded-acknowledged", "revision": 0}

    monkeypatch.setattr(extension_controls_commands, "GuardStore", FakeStore)
    monkeypatch.setattr(extension_controls_commands, "_client", lambda _guard_home: FakeClient())
    monkeypatch.setattr(
        extension_controls_commands,
        "prompt_for_approval_gate",
        lambda *_args, **_kwargs: calls.append("prompt") or SimpleNamespace(password="password", totp_code="123456"),
    )
    monkeypatch.setattr(
        extension_controls_commands,
        "require_extension_control",
        lambda *_args, **_kwargs: calls.append("require") or object(),
    )
    monkeypatch.setattr(
        extension_controls_commands,
        "consume_extension_control_grant",
        lambda *_args, **_kwargs: calls.append("consume"),
    )
    output = io.StringIO()

    exit_code = extension_controls_commands._recover_authority(
        tmp_path,
        command=command,
        output_stream=output,
    )

    assert exit_code == 0
    assert calls == list(expected_calls)
