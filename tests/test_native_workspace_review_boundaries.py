from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.runtime import native_workspace_review as native
from tests.test_native_workspace_review import _request, _status, _Store


def _native_response_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    encoded: bytes,
) -> dict[str, object]:
    monkeypatch.setattr(native, "native_runtime_status", _status)
    monkeypatch.setattr(native, "native_resident_client_request", lambda **_: encoded)
    return native._native_response(
        guard_home=tmp_path,
        request_id="request-1",
        decision={"decision": "allow"},
        request_snapshot_digest="snapshot",
    )


@pytest.mark.parametrize("value", [b"bytes", float("nan"), {"value": "\ud800"}])
def test_decision_canonicalization_rejects_unrepresentable_values(value: object) -> None:
    with pytest.raises(native.NativeWorkspaceReviewError) as error:
        native.canonical_workspace_review_decision_bytes(value)
    assert error.value.code == "native_workspace_review_decision_invalid"


def test_request_state_rejects_malformed_json_and_non_pending_rows(tmp_path: Path) -> None:
    malformed = _request()
    malformed["action_envelope_json"] = "{"  # exercise the persisted JSON boundary
    with pytest.raises(native.NativeWorkspaceReviewError) as error:
        native.stage_workspace_review_request(_Store(malformed), tmp_path, "request-1")
    assert error.value.code == "native_workspace_review_request_invalid"

    resolved = _request()
    resolved["status"] = "resolved"
    with pytest.raises(native.NativeWorkspaceReviewError) as error:
        native.stage_workspace_review_request(_Store(resolved), tmp_path, "request-1")
    assert error.value.code == "native_workspace_review_request_not_pending"


def test_staging_rejects_missing_and_oversized_state(tmp_path: Path) -> None:
    with pytest.raises(native.NativeWorkspaceReviewError) as error:
        native.stage_workspace_review_request(_Store(_request()), tmp_path, "missing")
    assert error.value.code == "native_workspace_review_request_missing"

    oversized = _request()
    oversized["raw_command_text"] = "x" * (native._MAX_REQUEST_STATE_BYTES + 1)
    with pytest.raises(native.NativeWorkspaceReviewError) as error:
        native.stage_workspace_review_request(_Store(oversized), tmp_path / "oversized", "request-1")
    assert error.value.code == "native_workspace_review_request_invalid"


@pytest.mark.skipif(os.name == "nt", reason="POSIX symlink fixture requires Windows privilege not assumed by CI")
def test_staging_rejects_symlinked_state(tmp_path: Path) -> None:
    request_directory = tmp_path / "symlink" / "native-runtime" / "workspace-review-requests"
    request_directory.mkdir(parents=True)
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    (request_directory / "request-1.json").symlink_to(target)
    with pytest.raises(native.NativeWorkspaceReviewError) as error:
        native.stage_workspace_review_request(_Store(_request()), tmp_path / "symlink", "request-1")
    assert error.value.code == "native_workspace_review_request_invalid"


def test_staging_maps_directory_and_atomic_write_failures_to_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_mkdir(*_args: object, **_kwargs: object) -> None:
        raise OSError("directory unavailable")

    monkeypatch.setattr(native.Path, "mkdir", fail_mkdir)
    with pytest.raises(native.NativeWorkspaceReviewError) as error:
        native.stage_workspace_review_request(_Store(_request()), tmp_path / "mkdir", "request-1")
    assert error.value.code == "native_workspace_review_request_unavailable"

    monkeypatch.undo()

    def fail_replace(*_args: object, **_kwargs: object) -> None:
        raise OSError("replace unavailable")

    monkeypatch.setattr(native.os, "replace", fail_replace)
    with pytest.raises(native.NativeWorkspaceReviewError) as error:
        native.stage_workspace_review_request(_Store(_request()), tmp_path / "replace", "request-1")
    assert error.value.code == "native_workspace_review_request_unavailable"


def test_windows_directory_security_failure_is_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_ensure(_path: Path) -> None:
        raise OSError("ACL unavailable")

    monkeypatch.setattr(native.os, "name", "nt")
    monkeypatch.setattr(
        native,
        "_native_policy_snapshot",
        SimpleNamespace(_windows_ensure_private_directory=fail_ensure),
    )
    with pytest.raises(native.NativeWorkspaceReviewError) as error:
        native.stage_workspace_review_request(_Store(_request()), tmp_path, "request-1")
    assert error.value.code == "native_workspace_review_request_unavailable"


def test_native_response_rejects_unavailable_unsupported_and_oversized_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        native,
        "native_runtime_status",
        lambda: SimpleNamespace(available=False, compatible=False, identity=None, capabilities=None),
    )
    with pytest.raises(native.NativeWorkspaceReviewError, match="native_workspace_review_unavailable"):
        native._native_response(
            guard_home=tmp_path,
            request_id="request-1",
            decision={},
            request_snapshot_digest="snapshot",
        )

    monkeypatch.setattr(
        native,
        "native_runtime_status",
        lambda: SimpleNamespace(
            available=True,
            compatible=True,
            identity=SimpleNamespace(path=Path("/native")),
            capabilities=SimpleNamespace(features=("resident-protocol-v2",)),
        ),
    )
    with pytest.raises(native.NativeWorkspaceReviewError, match="native_workspace_review_unsupported"):
        native._native_response(
            guard_home=tmp_path,
            request_id="request-1",
            decision={},
            request_snapshot_digest="snapshot",
        )

    monkeypatch.setattr(native, "native_runtime_status", _status)
    with pytest.raises(native.NativeWorkspaceReviewError, match="native_workspace_review_decision_invalid"):
        native._native_response(
            guard_home=tmp_path,
            request_id="request-1",
            decision={"value": "x" * native._MAX_DECISION_BYTES},
            request_snapshot_digest="snapshot",
        )


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        ({"error": "resident_rejected"}, "resident_rejected"),
        ({"status": "verified", "replayed": False}, "native_workspace_review_response_invalid"),
        ({"status": "verified", "replayed": False, "request_id": "other"}, "native_workspace_review_response_invalid"),
        (
            {"status": "replayed", "replayed": False, "request_id": "request-1"},
            "native_workspace_review_response_invalid",
        ),
        (
            {"status": "verified", "replayed": False, "request_id": "request-1", "decision": "maybe"},
            "native_workspace_review_response_invalid",
        ),
        (
            {
                "status": "verified",
                "replayed": False,
                "request_id": "request-1",
                "decision": "allow",
                "request_snapshot_digest": "other",
            },
            "native_workspace_review_response_invalid",
        ),
    ],
)
def test_native_response_rejects_bad_receipts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    response: dict[str, object],
    expected: str,
) -> None:
    encoded = json.dumps(response).encode("utf-8")
    with pytest.raises(native.NativeWorkspaceReviewError) as error:
        _native_response_call(tmp_path, monkeypatch, encoded)
    assert error.value.code == expected


@pytest.mark.parametrize("encoded", [b"\xff", b"[]"])
def test_native_response_rejects_non_json_objects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    encoded: bytes,
) -> None:
    with pytest.raises(native.NativeWorkspaceReviewError, match="native_workspace_review_response_invalid"):
        _native_response_call(tmp_path, monkeypatch, encoded)


def test_native_response_reports_transport_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native, "native_runtime_status", _status)
    monkeypatch.setattr(native, "native_resident_client_request", lambda **_: None)
    monkeypatch.setattr(native, "native_resident_client_failure_code", lambda: "resident_timeout")
    with pytest.raises(native.NativeWorkspaceReviewError, match="resident_timeout"):
        native._native_response(
            guard_home=tmp_path,
            request_id="request-1",
            decision={},
            request_snapshot_digest="snapshot",
        )


def test_apply_handles_resolved_invalid_and_failed_local_transactions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolved = _request()
    resolved["status"] = "resolved"
    with pytest.raises(native.NativeWorkspaceReviewError, match="native_workspace_review_decision_invalid"):
        native.apply_native_workspace_review_decision(_Store(resolved), tmp_path, "request-1", object())
    with pytest.raises(native.NativeWorkspaceReviewError, match="native_workspace_review_request_resolved"):
        native.apply_native_workspace_review_decision(_Store(resolved), tmp_path, "request-1", {})

    with pytest.raises(native.NativeWorkspaceReviewError, match="native_workspace_review_decision_invalid"):
        native.apply_native_workspace_review_decision(_Store(_request()), tmp_path / "nonmapping", "request-1", [])

    invalid_response_home = tmp_path / "invalid-response"
    invalid_response_home.mkdir()
    store = _Store(_request())
    monkeypatch.setattr(native, "_native_response", lambda **_: {"decision": None})
    with pytest.raises(native.NativeWorkspaceReviewError, match="native_workspace_review_response_invalid"):
        native.apply_native_workspace_review_decision(store, invalid_response_home, "request-1", {})

    failed_transaction_home = tmp_path / "failed-transaction"
    failed_transaction_home.mkdir()
    store = _Store(_request())
    monkeypatch.setattr(
        native,
        "_native_response",
        lambda **_: {"decision": "allow", "replayed": False},
    )
    monkeypatch.setattr(
        store,
        "resolve_native_workspace_review_request",
        lambda *_args, **_kwargs: {"resolved": False, "error": "transaction_conflict"},
    )
    with pytest.raises(native.NativeWorkspaceReviewError, match="transaction_conflict"):
        native.apply_native_workspace_review_decision(store, failed_transaction_home, "request-1", {})
