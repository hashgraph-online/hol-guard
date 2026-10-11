"""The workspace inventory bridge sends absolute paths and walks every page."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from codex_plugin_scanner.guard import native_workspace_inventory as bridge


def _page(items: list[dict[str, object]], next_offset: int | None) -> dict[str, object]:
    return {
        "manifest_paths": ["package.json"],
        "lockfile_paths": [],
        "sbom_paths": [],
        "inventory": items,
        "inventory_digest": "sha256:" + "ab" * 32,
        "next_offset": next_offset,
        "diff": None,
        "lockfile_warnings": [],
        "scan_targets": [],
        "package_target": None,
    }


def _item(name: str) -> dict[str, object]:
    return {
        "ecosystem": "npm",
        "namespace": None,
        "name": name,
        "direct": True,
        "range": "1.0.0",
        "version": None,
    }


def test_relative_workspaces_are_sent_absolute_and_pages_are_joined(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.chdir(tmp_path)
    sent: list[dict[str, object]] = []

    def transport(request: dict[str, object], _guard_home: Path, **_kwargs: object) -> dict[str, object]:
        sent.append(dict(request))
        offset = request["inventory_offset"]
        if offset == 0:
            return _page([_item("left-pad")], 1)
        return _page([_item("react")], None)

    monkeypatch.setattr(bridge, "_transport", transport)
    inventory = bridge.native_workspace_inventory(
        SimpleNamespace(guard_home=str(tmp_path)),
        Path("rel-workspace"),
        before_workspace_dir=Path("rel-before"),
    )
    assert Path(str(sent[0]["workspace_dir"])).is_absolute()
    assert str(sent[0]["workspace_dir"]).endswith("/rel-workspace")
    assert Path(str(sent[0]["before_workspace_dir"])).is_absolute()
    assert str(sent[0]["before_workspace_dir"]).endswith("/rel-before")
    assert [item["name"] for item in inventory.inventory] == ["left-pad", "react"]
    assert sent[1]["inventory_offset"] == 1


def test_targets_only_pages_are_joined(monkeypatch, tmp_path: Path) -> None:
    def target(name: str) -> dict[str, object]:
        return {
            "ecosystem": "npm",
            "raw_spec": name,
            "extras": [],
            "editable": False,
            **{key: None for key in bridge._TARGET_OPTIONAL_STRINGS},
            "package_name": name,
        }

    def transport(request: dict[str, object], _guard_home: Path, **_kwargs: object) -> dict[str, object]:
        first = request["inventory_offset"] == 0
        payload = _page([], 1 if first else None)
        payload["scan_targets"] = [target("left-pad" if first else "react")]
        return payload

    monkeypatch.setattr(bridge, "_transport", transport)
    result = bridge.native_workspace_inventory(SimpleNamespace(guard_home=str(tmp_path)), tmp_path, targets_only=True)
    assert result.inventory == ()
    assert [item.package_name for item in result.scan_targets] == ["left-pad", "react"]
    assert sent[1]["inventory_digest"] == "sha256:" + "ab" * 32
    assert "inventory_digest" not in sent[0]
