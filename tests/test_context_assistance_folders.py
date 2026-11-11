from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_context_assistance as native
from codex_plugin_scanner.guard.routes import context_assistance_http as http


class _Handler:
    def __init__(self, home: Path) -> None:
        self.server = SimpleNamespace(store=SimpleNamespace(guard_home=home))
        self.calls: list[tuple[dict[str, object], int]] = []

    def _write_json(self, data: dict[str, object], status: int = 200, extra_headers: object = None) -> None:
        assert extra_headers == {"Cache-Control": "no-store"}
        self.calls.append((data, status))


def test_http_route_frames_the_native_listing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert http.WRITE_PATHS["/v1/context-assistance/folders"] == "folders"
    seen: list[tuple[Path, dict[str, object]]] = []

    def listing(*, guard_home: Path, payload: dict[str, object]) -> dict[str, object]:
        seen.append((guard_home, payload))
        return {"schema": "guard-context-folders.v1", "mode": "folders"}

    monkeypatch.setattr(http, "folders", listing)
    handler = _Handler(tmp_path)
    http.respond(handler, "folders", {"path": str(tmp_path)})
    assert handler.calls == [({"schema": "guard-context-folders.v1", "mode": "folders"}, 200)]
    assert seen == [(tmp_path, {"path": str(tmp_path)})]


def _folder(code: str) -> dict[str, object]:
    return {"error": "folder_unavailable", "code": code}


@pytest.mark.parametrize(
    ("code", "expected", "status"),
    [
        ("native_context_assistance_folder_not_found", _folder("folder_not_found"), 404),
        ("native_context_assistance_folder_denied", _folder("folder_denied"), 403),
        ("native_context_assistance_folder_input_invalid", _folder("folder_input_invalid"), 400),
        (
            "native_context_assistance_busy",
            {"error": "context_assistance_unavailable", "code": "native_context_assistance_busy"},
            409,
        ),
    ],
)
def test_http_route_maps_native_refusals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: str, expected: dict[str, object], status: int
) -> None:
    def refuse(**_: object) -> dict[str, object]:
        raise native.ContextAssistanceError(code)

    monkeypatch.setattr(http, "folders", refuse)
    handler = _Handler(tmp_path)
    http.respond(handler, "folders", {})
    assert handler.calls == [(expected, status)]


def test_native_listing_is_unwrapped_from_the_workspace_envelope(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, object]] = []

    def workspace(kind: str, **kwargs: object) -> dict[str, object]:
        calls.append((kind, kwargs["operation"]))
        return {"schema": "guard-cigar-workspace-result.v1", "data_role": True, "result": {"mode": "files"}}

    monkeypatch.setattr(native, "workspace", workspace)
    assert native.folders(guard_home=Path("/home"), payload={"mode": "files"}) == {"mode": "files"}
    assert calls[0][0] == "folders"
    assert calls[0][1].feature == "context-assistance-folders-v1"
