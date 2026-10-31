"""Daemon route for the local source export preview: auth, validation, worktree binding, redaction."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_workspace_export_preview as export_preview
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon.workspace_assessment_api import handle_workspace_assessment_post
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.workspace_assessment_worker import admit_workspace
from tests.test_guard_headless_daemon_api import _dashboard_token_for, _read_json_response, _request
from tests.workspace_fix_support import KEYS, digest, native_binary, seeded_store  # noqa: F401

PATH = "/v1/supply-chain/workspace-export-preview"
BODY: dict[str, object] = {"codebase_key": KEYS.codebase_key, "worktree_key": KEYS.worktree_key, "paths": ["app.py"]}


# The value is split so repository secret scanners do not read this file as
# holding a credential.
def _github_token() -> str:
    return "".join(["ghp_", "AbCdEfGhIjKlMnOpQrStUvWxYz", "012345"])


class _Handler:
    """The two members the route uses from the daemon's request handler."""

    def __init__(self, store: GuardStore) -> None:
        self.server = SimpleNamespace(store=store)
        self.responses: list[tuple[int, dict[str, object]]] = []

    def _write_json(self, payload: dict[str, object], *, status: int = 200) -> None:
        self.responses.append((status, payload))


def _post(store: GuardStore, payload: dict[str, object]) -> tuple[int, dict[str, object]]:
    handler = _Handler(store)
    assert handle_workspace_assessment_post(handler, PATH, payload) is True
    [response] = handler.responses
    return response


def _reply(**result: object) -> dict[str, object]:
    return {
        "ok": True,
        "result": {
            "schema": "guard.workspace-export-preview.v1",
            "status": "ready",
            "worktree_key": KEYS.worktree_key,
            "codebase_key": KEYS.codebase_key,
            "bundle_digest": digest("bundle"),
            "files": [],
            "excluded": [],
            **result,
        },
    }


def test_malformed_requests_and_untracked_worktrees_never_reach_the_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(export_preview, "_native_request", lambda request: calls.append(request) or _reply())
    store = seeded_store(tmp_path, tmp_path / "work")
    responses = [
        _post(store, payload)
        for payload in (
            {"paths": ["app.py"]},
            {**BODY, "paths": "app.py"},
            {**BODY, "paths": [""]},
            {**BODY, "paths": [7]},
            {**BODY, "paths": ["a" * 4097]},
            {**BODY, "paths": [f"f{index}" for index in range(201)]},
            {**BODY, "worktree_key": digest("other")},
        )
    ]
    assert responses == [
        (400, {"error": "invalid_worktree"}),
        *[(400, {"error": "invalid_paths"})] * 5,
        (404, {"error": "worktree_not_found"}),
    ]
    assert calls == []


def test_the_tracked_root_is_previewed_and_a_root_that_now_keys_elsewhere_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "work"
    calls: list[dict[str, object]] = []
    replies = [_reply(), _reply(worktree_key=digest("moved")), _reply(codebase_key=digest("other repository"))]
    monkeypatch.setattr(export_preview, "_native_request", lambda request: calls.append(request) or replies.pop(0))
    store = seeded_store(tmp_path, root)
    ready = _post(store, BODY)
    moved = _post(store, BODY)
    repointed = _post(store, BODY)
    assert ready[0] == 200 and ready[1]["status"] == "ready"
    assert moved == (409, {"error": "worktree_moved"})
    assert repointed == (409, {"error": "worktree_moved"})
    assert calls == [{"root": str(root), "paths": ["app.py"]}] * 3


@pytest.mark.parametrize(
    ("reply", "expected"),
    [
        (
            {"ok": False, "error": "workspace_export_preview_root_missing"},
            "workspace_export_preview_root_missing",
        ),
        ({"ok": False}, "workspace_export_preview_failed"),
        (_reply(status="uploaded"), "workspace_export_preview_failed"),
        (_reply(bundle_digest="nope"), "workspace_export_preview_failed"),
        ({"ok": True, "result": {"schema": "other"}}, "workspace_export_preview_failed"),
    ],
)
def test_native_refusals_and_unusable_replies_are_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reply: dict[str, object], expected: str
) -> None:
    monkeypatch.setattr(export_preview, "_native_request", lambda _request: reply)
    store = seeded_store(tmp_path, tmp_path / "work")
    assert _post(store, BODY) == (422, {"error": expected})


def test_a_runtime_without_the_preview_is_reported_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import native_runtime

    unavailable = SimpleNamespace(available=False, compatible=False, identity=None, capabilities=None)
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda: unavailable)
    store = seeded_store(tmp_path, tmp_path / "work")
    assert _post(store, BODY) == (503, {"error": "workspace_export_preview_native_unavailable"})


@pytest.mark.usefixtures("native_binary")
def test_native_preview_over_the_daemon_redacts_secrets_and_keeps_excluded_files_out(tmp_path: Path) -> None:
    root = tmp_path / "work"
    (root / "config").mkdir(parents=True)
    source = f"import os\nGH_TOKEN = {_github_token()}\n"
    (root / "app.py").write_text(source, encoding="utf-8")
    (root / "config" / ".env").write_text("TOKEN=value\n", encoding="utf-8")
    store = GuardStore(tmp_path / "home")
    admitted = admit_workspace(store, str(root))
    payload: dict[str, object] = {
        "codebase_key": admitted["codebase_key"],
        "worktree_key": admitted["worktree_key"],
        "paths": ["app.py", "config/.env", "../outside.txt", "missing.txt"],
    }
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        anonymous = _read_json_response(_request(daemon.port, PATH, payload=payload))[0]
        foreign = _read_json_response(
            _request(daemon.port, PATH, payload=payload, token=token, origin="https://x.test")
        )
        status, preview = _read_json_response(_request(daemon.port, PATH, token=token, payload=payload))
    finally:
        daemon.stop()

    assert anonymous in {401, 403}
    assert foreign == (403, {"error": "forbidden_origin"})
    assert status == 200
    assert preview["status"] == "ready"
    assert preview["worktree_key"] == admitted["worktree_key"]
    [file] = preview["files"]
    assert file["path"] == "app.py" and file["redactions"] == 1
    assert {item["path"]: item["reason"] for item in preview["excluded"]} == {
        "config/.env": "sensitive",
        "../outside.txt": "invalid_path",
        "missing.txt": "not_found",
    }
    assert _github_token() not in str(preview)
    assert (root / "app.py").read_text(encoding="utf-8") == source, "a preview never edits the worktree"
