from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.trust_install_surface import _installed_trust_cli_payload


class BuildDistribution:
    version = "9.9.9"

    def read_text(self, _filename: str) -> str:
        return json.dumps({"dir_info": {"editable": True}})

    def locate_file(self, _path: str) -> Path:
        return Path("/synthetic/source-build")


@pytest.mark.parametrize(
    ("installer", "path_status", "mode", "editable"),
    [
        ("desktop", "bundled", "desktop-managed", False),
        ("pip", "path_mismatch", "editable", True),
        ("desktop", "path_mismatch", "editable", True),
        ("pip", "bundled", "editable", True),
    ],
)
def test_running_install_surface_takes_precedence_over_embedded_build_metadata(
    installer: str, path_status: str, mode: str, editable: bool
) -> None:
    payload = _installed_trust_cli_payload(
        install_surface={"installer": installer, "binary_diagnostics": {"path_status": path_status}},
        resolve_distribution=lambda _name: BuildDistribution(),
    )
    assert payload["version"] == "9.9.9"
    assert payload["installation_mode"] == mode
    assert payload["editable_install"] is editable
    assert payload["official_install"] is False
    assert payload["official_install_verified"] is False
    assert payload["active_command_verified"] is False


def test_desktop_managed_doctor_does_not_recommend_pipx_reinstallation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.cli import commands_dispatch_trust as module

    monkeypatch.setattr(module.importlib.metadata, "distribution", lambda _name: BuildDistribution())
    monkeypatch.setattr(
        module,
        "build_guard_install_surface_payload",
        lambda: {"installer": "desktop", "binary_diagnostics": {"path_status": "bundled"}},
    )
    monkeypatch.setattr(
        module, "_approval_center_status_payload", lambda _home: {"active": True, "snapshot_fresh": True}
    )
    payload = module.build_trust_doctor_payload_from_status(
        {"runtime_protection": "protected", "remembered_rules": "enforced"}, guard_home=tmp_path
    )
    assert payload["official_install"]["installation_mode"] == "desktop-managed"
    assert not any("pipx" in action for action in payload["recommended_actions"])
    assert payload["checks"]["official_install_verified"] is False
