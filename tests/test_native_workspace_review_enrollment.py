from __future__ import annotations

import json
import stat
from datetime import datetime, timedelta, timezone
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError

import pytest

from codex_plugin_scanner.guard.runtime import native_workspace_review_enrollment as enrollment
from tests.guard_exact_cloud_review_support import connected_exact_review_store

NOW = datetime(2026, 9, 28, tzinfo=timezone.utc)
AUTH: dict[str, object] = {
    "workspace_id": "workspace-1",
    "machine_installation_id": "installation-1",
    "sync_url": "https://guard.example.test",
}
RECORD = {"schema": "guard-native-workspace-review-authority.v1", "version": 1}
ENCODED = json.dumps(RECORD, sort_keys=True, separators=(",", ":")).encode()


def _store(tmp_path: Path):
    store = connected_exact_review_store(tmp_path)
    state_base = store.guard_home / "native-runtime"
    state_base.mkdir(mode=0o700, parents=True, exist_ok=True)
    (state_base / "approval-authority.v1.json").write_text("{}", encoding="utf-8")
    return store


def test_background_enrollment_rechecks_on_binding_change_and_cooldown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    fetched: list[str] = []
    installed: list[bytes] = []
    monkeypatch.setattr(
        enrollment, "_fetch_authority", lambda auth: fetched.append(str(auth["workspace_id"])) or ENCODED
    )
    monkeypatch.setattr(enrollment, "_install_authority", lambda _base, record: installed.append(record))
    assert enrollment.refresh_native_workspace_review_authority(store, AUTH, now=NOW)
    assert not enrollment.refresh_native_workspace_review_authority(store, AUTH, now=NOW + timedelta(minutes=1))
    assert fetched == ["workspace-1"]
    assert installed == [ENCODED]
    assert enrollment.refresh_native_workspace_review_authority(
        store, {**AUTH, "workspace_id": "workspace-2"}, now=NOW + timedelta(minutes=1)
    )
    assert fetched == ["workspace-1", "workspace-2"]


def test_unavailable_authority_does_not_block_event_delivery_or_replace_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    target = store.guard_home / "native-runtime" / "workspace-review-authority.v1.json"
    target.write_bytes(b"existing-root-signed-record")

    def unavailable(_auth: dict[str, object]) -> bytes:
        raise HTTPError("https://guard.example.test", 503, "unavailable", Message(), None)

    monkeypatch.setattr(enrollment, "_fetch_authority", unavailable)
    monkeypatch.setattr(enrollment, "_install_authority", lambda *_: pytest.fail("installer must not run"))
    assert not enrollment.refresh_native_workspace_review_authority(store, AUTH, now=NOW)
    assert target.read_bytes() == b"existing-root-signed-record"
    state = store.get_sync_payload(enrollment._STATE_KEY)
    assert isinstance(state, dict)
    assert state["status"] == "unavailable"
    assert state["http_status"] == 503


def test_missing_base_enrollment_or_local_consent_makes_no_network_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    monkeypatch.setattr(enrollment, "_fetch_authority", lambda _: pytest.fail("unexpected network request"))
    (store.guard_home / "native-runtime" / "approval-authority.v1.json").unlink()
    assert not enrollment.refresh_native_workspace_review_authority(store, AUTH, now=NOW)
    (store.guard_home / "native-runtime" / "approval-authority.v1.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(enrollment, "exact_cloud_review_operations", lambda _: ())
    assert not enrollment.refresh_native_workspace_review_authority(store, AUTH, now=NOW)


def test_authority_response_accepts_only_exact_v2_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(enrollment, "_guard_sync_request", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(
        enrollment,
        "_urlopen_json_with_timeout_retry",
        lambda **_kwargs: {"authority": RECORD, "protocolVersion": 2},
    )
    assert enrollment._fetch_authority(AUTH) == ENCODED
    monkeypatch.setattr(
        enrollment,
        "_urlopen_json_with_timeout_retry",
        lambda **_kwargs: {"authority": RECORD, "protocolVersion": 2, "privateKey": "never"},
    )
    with pytest.raises(ValueError, match="native_workspace_review_authority_response_invalid"):
        enrollment._fetch_authority(AUTH)


def test_native_installer_verifies_private_candidate_and_removes_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state_base = tmp_path / "native-runtime"
    state_base.mkdir(mode=0o700)
    monkeypatch.setattr(
        enrollment,
        "native_runtime_status",
        lambda: SimpleNamespace(
            available=True,
            compatible=True,
            identity=SimpleNamespace(path=tmp_path / "native"),
            capabilities=SimpleNamespace(features={enrollment._RESIDENT_ENROLLMENT_FEATURE}),
        ),
    )
    candidate_paths: list[Path] = []

    def accept(_binary: Path, args: tuple[str, ...], **_kwargs: object) -> str:
        candidate = Path(args[-1])
        candidate_paths.append(candidate)
        assert candidate.read_bytes() == ENCODED
        assert stat.S_IMODE(candidate.stat().st_mode) == 0o600
        return ""

    monkeypatch.setattr(enrollment, "_run_native_process", accept)
    monkeypatch.setattr(
        enrollment,
        "native_resident_client_request",
        lambda **_kwargs: pytest.fail("resident must not run after direct enrollment"),
    )
    enrollment._install_authority(state_base, ENCODED)
    assert len(candidate_paths) == 1
    assert not candidate_paths[0].exists()

    def accept_resident(**kwargs: object) -> bytes:
        request_bytes = kwargs["payload"]
        assert isinstance(request_bytes, bytes)
        payload = json.loads(request_bytes)
        candidate = Path(payload["request"]["record_path"])
        assert payload["operation"] == "workspace_review_authority_enroll"
        assert kwargs["guard_home"] == tmp_path
        assert candidate.read_bytes() == ENCODED
        assert stat.S_IMODE(candidate.stat().st_mode) == 0o600
        candidate_paths.append(candidate)
        return b'{"status":"enrolled"}'

    monkeypatch.setattr(enrollment, "_run_native_process", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(enrollment, "native_resident_client_request", accept_resident)
    enrollment._install_authority(state_base, ENCODED)
    assert len(candidate_paths) == 2
    assert not candidate_paths[-1].exists()

    monkeypatch.setattr(enrollment, "native_resident_client_request", lambda **_kwargs: b'{"status":"ignored"}')
    with pytest.raises(ValueError, match="native_workspace_review_authority_install_failed"):
        enrollment._install_authority(state_base, ENCODED)
    assert not list(state_base.glob(".workspace-review-authority-*.json"))
