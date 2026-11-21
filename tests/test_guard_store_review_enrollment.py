"""The native store owns the workspace enrollment schedule row."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import native_workspace_review_enrollment as enrollment
from codex_plugin_scanner.guard.store import GuardStore

_NOW = "2026-09-28T00:00:00+00:00"
_SOON = "2026-09-28T00:01:00+00:00"
_LATER = "2026-09-28T00:05:00+00:00"
_AUTH: dict[str, object] = {
    "workspace_id": "workspace-1",
    "machine_installation_id": "installation-1",
    "sync_url": "https://guard.example.test",
}
_BINDING = ["workspace-1", "installation-1", "https://guard.example.test"]


def test_a_recorded_check_holds_the_next_one_for_an_interval(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    assert store.workspace_review_enrollment_due(_AUTH, now=_NOW) == _BINDING

    state = store.record_workspace_review_enrollment(_BINDING, outcome="enrolled", now=_NOW, record='{"v":1}')

    assert state == {
        "binding": _BINDING,
        "next_check_at": _LATER,
        "record_digest": hashlib.sha256(b'{"v":1}').hexdigest(),
        "status": "enrolled",
    }
    assert store.get_sync_payload(enrollment._STATE_KEY) == state
    assert store.workspace_review_enrollment_due(_AUTH, now=_SOON) is None
    assert store.workspace_review_enrollment_due(_AUTH, now=_LATER) == _BINDING
    assert store.workspace_review_enrollment_due({**_AUTH, "workspace_id": "workspace-2"}, now=_SOON) == [
        "workspace-2",
        *_BINDING[1:],
    ]


def test_an_incomplete_connection_is_never_due(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    assert store.workspace_review_enrollment_due({**_AUTH, "sync_url": ""}, now=_NOW) is None
    assert store.workspace_review_enrollment_due({**_AUTH, "oauth_subject_hash": ""}, now=_NOW) is None
    assert store.workspace_review_enrollment_due({**_AUTH, "oauth_subject_hash": "s"}, now=_NOW) == [*_BINDING, "s"]


def test_a_failed_check_keeps_only_a_workspace_review_code(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    coded = store.record_workspace_review_enrollment(
        _BINDING,
        outcome="unavailable",
        now=_NOW,
        error_type="ValueError",
        error_code="native_workspace_review_runtime_unavailable",
    )
    assert coded["error_code"] == "native_workspace_review_runtime_unavailable"
    typed = store.record_workspace_review_enrollment(
        _BINDING, outcome="unavailable", now=_NOW, error_type="ValueError", error_code="bad value"
    )
    assert typed["error_code"] == "ValueError"
    assert typed["status"] == "unavailable"


def test_a_bad_record_is_refused_without_a_write(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    with pytest.raises(ValueError, match="invalid_outcome"):
        store.record_workspace_review_enrollment(_BINDING, outcome="maybe", now=_NOW)
    with pytest.raises(ValueError, match="invalid_binding"):
        store.record_workspace_review_enrollment(["only-one"], outcome="enrolled", now=_NOW, record="{}")
    assert store.get_sync_payload(enrollment._STATE_KEY) is None


def test_a_failed_refresh_records_its_type_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from tests.guard_exact_cloud_review_support import connected_exact_review_store

    store = connected_exact_review_store(tmp_path)
    state_base = store.guard_home / "native-runtime"
    state_base.mkdir(mode=0o700, parents=True, exist_ok=True)
    (state_base / "approval-authority.v1.json").write_text("{}", encoding="utf-8")

    def broken(_auth: dict[str, object]) -> bytes:
        raise OSError("connection reset")

    monkeypatch.setattr(enrollment, "_fetch_authority", broken)
    assert not enrollment.refresh_native_workspace_review_authority(store, _AUTH)
    state = store.get_sync_payload(enrollment._STATE_KEY)
    assert isinstance(state, dict)
    assert state["status"] == "unavailable"
    assert state["error_code"] == "OSError"
    assert state["binding"] == _BINDING
