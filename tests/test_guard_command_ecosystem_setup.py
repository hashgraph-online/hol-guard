"""Package command extension metadata and setup detection tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.runtime import command_ecosystem_detection
from codex_plugin_scanner.guard.runtime.command_ecosystem_detection import (
    command_setup_detection_payload,
    detect_command_ecosystems,
)
from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY,
    CommandSafetyExtension,
    CommandSafetyExtensionRegistry,
)


def test_package_extensions_delegate_to_existing_package_firewall() -> None:
    package_extensions = tuple(
        extension
        for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
        if extension.extension_id.startswith("command.package.")
    )

    assert len(package_extensions) == 8
    assert {extension.extension_id for extension in package_extensions} == {
        "command.package.go",
        "command.package.jvm",
        "command.package.node",
        "command.package.php",
        "command.package.python",
        "command.package.ruby",
        "command.package.rust",
        "command.package.system",
    }
    assert all(extension.delegated_protection == "package-firewall" for extension in package_extensions)
    assert all(extension.ecosystem_ids for extension in package_extensions)
    assert all(extension.executables for extension in package_extensions)
    assert all(extension.reference_urls for extension in package_extensions)
    assert all(
        reference.startswith("https://") for extension in package_extensions for reference in extension.reference_urls
    )
    assert all(not extension.rules for extension in package_extensions)


def test_registry_rejects_incomplete_or_rule_owning_delegated_extensions() -> None:
    incomplete = CommandSafetyExtension(
        extension_id="command.package.incomplete",
        version="1.0.0",
        name="Incomplete",
        description="Missing delegated setup metadata.",
        action_classes=(),
        risk_classes=("supply_chain",),
        safer_alternatives=("Use a lockfile.",),
        delegated_protection="package-firewall",
    )
    with pytest.raises(ValueError, match="requires ecosystem and executable metadata"):
        _ = CommandSafetyExtensionRegistry((incomplete,))

    owning = CommandSafetyExtension(
        extension_id="command.package.owning",
        version="1.0.0",
        name="Owning",
        description="Incorrectly owns a compatibility action.",
        action_classes=("package command",),
        risk_classes=("supply_chain",),
        safer_alternatives=("Use a lockfile.",),
        delegated_protection="package-firewall",
        ecosystem_ids=("example",),
        executables=("example",),
    )
    with pytest.raises(ValueError, match="cannot own command rules"):
        _ = CommandSafetyExtensionRegistry((owning,))


@pytest.mark.parametrize(
    ("executables", "project_markers", "message"),
    (
        (("../bin/tool",), ("manifest.json",), "basenames"),
        (("tool",), ("../manifest.json",), "unsafe project marker"),
        (("tool",), ("folder\\manifest.json",), "unsafe project marker"),
    ),
)
def test_registry_rejects_path_bearing_detection_metadata(
    executables: tuple[str, ...],
    project_markers: tuple[str, ...],
    message: str,
) -> None:
    extension = CommandSafetyExtension(
        extension_id="command.package.unsafe",
        version="1.0.0",
        name="Unsafe",
        description="Contains path-bearing detection metadata.",
        action_classes=(),
        risk_classes=("supply_chain",),
        safer_alternatives=("Use safe metadata.",),
        delegated_protection="package-firewall",
        ecosystem_ids=("example",),
        executables=executables,
        project_markers=project_markers,
        reference_urls=("https://example.invalid/reference",),
    )

    with pytest.raises(ValueError, match=message):
        _ = CommandSafetyExtensionRegistry((extension,))


def test_detect_command_ecosystems_uses_only_marker_names_and_command_availability(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "package.json").write_text('{"scripts":{"test":"vitest"}}\n', encoding="utf-8")
    (tmp_path / "Cargo.toml").write_text("[package]\nname='demo'\n", encoding="utf-8")
    (tmp_path / ".npmrc").write_text("//registry.example.test/:_authToken=secret\n", encoding="utf-8")
    available = {"npm", "npx", "cargo"}
    monkeypatch.setattr(
        command_ecosystem_detection.shutil,
        "which",
        lambda executable: f"/managed/bin/{executable}" if executable in available else None,
    )

    detections = detect_command_ecosystems(tmp_path)
    detected = {item.extension.extension_id: item for item in detections if item.detected}
    recommended = {item.extension.extension_id for item in detections if item.recommended}

    assert set(detected) == {"command.package.node", "command.package.rust"}
    assert recommended == {"command.package.node", "command.package.rust"}
    assert detected["command.package.node"].project_markers == ("package.json",)
    assert detected["command.package.node"].available_executables == ("npm", "npx")
    payload_text = json.dumps(command_setup_detection_payload(tmp_path), sort_keys=True)
    assert "secret" not in payload_text
    assert str(tmp_path) not in payload_text
    assert ".npmrc" not in payload_text


def test_command_setup_detect_json_is_deterministic_and_side_effect_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
    monkeypatch.setattr(command_ecosystem_detection.shutil, "which", lambda _executable: None)

    rc = main(["guard", "command", "setup", "--detect", "--workspace", str(tmp_path), "--json"])

    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == 2
    assert payload["mode"] == "detect"
    assert payload["side_effects"] == "none"
    assert payload["recommended_extension_ids"] == ["command.package.python"]
    assert payload["recommended_count"] == 1
    assert payload["detected_count"] == 1


def test_command_setup_detect_rejects_missing_workspace(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(
        [
            "guard",
            "command",
            "setup",
            "--detect",
            "--workspace",
            str(tmp_path / "missing"),
            "--json",
        ]
    )

    assert rc == 2
    assert "existing directory" in capsys.readouterr().err
