from __future__ import annotations

import copy
import hashlib
import json
import os
import stat
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard.runtime import native_workspace_review_staging as staging
from tests.native_workspace_review_test_support import _request, _staged_digest, _Store


def test_staging_uses_only_persisted_request_material(tmp_path: Path) -> None:
    store = _Store(_request())
    staged = staging.stage_workspace_review_request(store, tmp_path, "request-1")
    assert staged["action_identity"] == "action-1"
    path = tmp_path / "native-runtime" / "workspace-review-requests" / "request-1.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["action"]["action_identity"] == "action-1"
    assert "decision" not in payload
    assert "dpop" not in json.dumps(payload).lower()
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_uploaded_snapshot_only_survives_scope_narrowing() -> None:
    current = _request()
    current["decision_v2_json"] = {"action": "review", "approval_scopes": ["artifact"]}
    uploaded = copy.deepcopy(current)
    cast(dict[str, object], uploaded["decision_v2_json"])["approval_scopes"] = ["artifact", "task"]
    assert staging._compatible_uploaded_snapshot("request-1", current, uploaded)

    altered = copy.deepcopy(uploaded)
    altered["raw_command_text"] = "git push"
    assert not staging._compatible_uploaded_snapshot("request-1", current, altered)
    altered = copy.deepcopy(uploaded)
    cast(dict[str, object], altered["decision_v2_json"])["action"] = "allow"
    assert not staging._compatible_uploaded_snapshot("request-1", current, altered)
    altered = copy.deepcopy(uploaded)
    cast(dict[str, object], altered["decision_v2_json"])["approval_scopes"] = ["task"]
    assert not staging._compatible_uploaded_snapshot("request-1", current, altered)


def test_native_delivery_selects_matching_authenticated_upload(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    current = _request()
    current["decision_v2_json"] = {"action": "review", "approval_scopes": ["artifact"]}
    uploaded = copy.deepcopy(current)
    cast(dict[str, object], uploaded["decision_v2_json"])["approval_scopes"] = ["artifact", "task"]
    unrelated = copy.deepcopy(uploaded)
    unrelated["raw_command_text"] = "git push"

    class StoreWithSnapshots(_Store):
        def list_review_event_snapshots(self, request_id: str) -> list[dict[str, object]]:
            assert request_id == "request-1"
            return [unrelated, uploaded, copy.deepcopy(uploaded)]

    probes: list[dict[str, object]] = []

    def context_probe(_store: object, _home: Path, _request_id: str, snapshot: object) -> dict[str, object]:
        assert isinstance(snapshot, dict)
        probes.append(snapshot)
        marker = "a" if snapshot == uploaded else "b"
        return {
            field: marker
            for field in (
                "request_binding",
                "action_binding",
                "intent_binding",
                "revision_binding",
                "policy_binding",
                "retry_scope_binding",
            )
        }

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.runtime.native_workspace_review_context.build_native_workspace_review_context",
        context_probe,
    )
    decision = {
        field: "a"
        for field in (
            "request_binding",
            "action_binding",
            "intent_binding",
            "revision_binding",
            "policy_binding",
            "retry_scope_binding",
        )
    }
    store = StoreWithSnapshots(current)
    assert staging.matching_workspace_review_snapshot(store, tmp_path, "request-1", decision, current) == uploaded
    assert probes == [current, uploaded]
    with pytest.raises(staging.NativeWorkspaceReviewError, match="native_workspace_review_decision_binding_mismatch"):
        staging.matching_workspace_review_snapshot(
            store, tmp_path, "request-1", {**decision, "policy_binding": "wrong"}, current
        )


def test_windows_staging_uses_acl_bound_atomic_writer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _Store(_request())
    ensured: list[Path] = []
    bindings: list[Path] = []

    @contextmanager
    def bind_directory(path: Path):
        path.mkdir(parents=True, exist_ok=True)
        bindings.append(path)
        yield SimpleNamespace(path=path, handle=object(), handles=[])

    def ensure_private_directory(path: Path) -> None:
        ensured.append(path)
        path.mkdir(parents=True, exist_ok=True)

    def write_atomic(**kwargs: object) -> None:
        assert kwargs["maximum_bytes"] == staging._MAX_REQUEST_STATE_BYTES
        assert kwargs["kind"] == "workspace_review_request"
        destination = cast(Path, kwargs["parent_path"]) / cast(str, kwargs["destination_name"])
        destination.write_bytes(cast(bytes, kwargs["payload"]))

    monkeypatch.setattr(
        staging,
        "_native_policy_snapshot",
        SimpleNamespace(
            _windows_ensure_private_directory=ensure_private_directory,
            _windows_private_directory_binding=bind_directory,
            _windows_write_private_file_atomic=write_atomic,
        ),
    )
    monkeypatch.setattr(staging.os, "name", "nt")
    for function_name in ("fchmod", "open", "fsync"):
        monkeypatch.setattr(
            staging.os,
            function_name,
            lambda *args, _function_name=function_name, **kwargs: pytest.fail(_function_name),
        )

    staging.stage_workspace_review_request(store, tmp_path, "request-1")
    path = tmp_path / "native-runtime" / "workspace-review-requests" / "request-1.json"
    expected = staging._canonical_json_bytes(staging._request_state("request-1", _request()))
    assert path.read_bytes() == expected
    assert _staged_digest(tmp_path, "request-1") == hashlib.sha256(expected).hexdigest()
    assert ensured == [tmp_path, tmp_path / "native-runtime", path.parent]
    assert bindings == [path.parent]
