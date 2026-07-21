from __future__ import annotations

import argparse
import io
from pathlib import Path

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
                "controls": [
                    {"target_kind": "extension", "target_id": "existing", "state": "disabled"}
                ],
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
