"""The Cloud audit payload query must match the resident's canonical request."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from codex_plugin_scanner.guard import native_package_audit_projection as projection


def _capture(monkeypatch, machine: str | None) -> dict[str, object]:
    captured: dict[str, object] = {}

    def fake_send(query: dict[str, object], store: object) -> dict[str, object]:
        captured.update(query)
        return {"packages": [], "workspaceFingerprint": "sha256:x"}

    monkeypatch.setattr(projection, "_send", fake_send)
    monkeypatch.setattr(projection, "_machine_name", lambda: machine)
    projection.native_cloud_audit_payload(
        SimpleNamespace(path=Path("/guard-home")),
        workspace_dir=Path("/workspace"),
        workspace_id="workspace",
        inventory_digest="sha256:inventory",
    )
    return captured


def test_unknown_machine_is_omitted_rather_than_sent_as_null(monkeypatch) -> None:
    assert "machine" not in _capture(monkeypatch, None)


def test_known_machine_is_sent(monkeypatch) -> None:
    assert _capture(monkeypatch, "host")["machine"] == "host"
