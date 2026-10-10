"""The approval-queue identity bridge returns a bound resident reply and fails closed."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_approval_queue_identity as identity_module
from codex_plugin_scanner.guard import native_execution, native_store_policy
from codex_plugin_scanner.guard.native_approval_queue_identity import (
    APPROVAL_QUEUE_IDENTITY_FEATURE,
    ApprovalQueueIdentityUnavailableError,
    QueueIdentity,
    native_approval_queue_identities,
    queue_identity_item,
)
from codex_plugin_scanner.guard.native_context import _canonical_request_sha256

_FEATURES = ("resident-protocol-v2", APPROVAL_QUEUE_IDENTITY_FEATURE)
_RESULT_SCHEMA = "guard-approval-queue-identity-result.v1"


def _home(tmp_path: Path) -> Path:
    home = tmp_path / "guard-home"
    key = home / "native-runtime" / "policy-verifier.key"
    key.parent.mkdir(parents=True)
    key.write_bytes(b"verifier")
    return home


def _item() -> dict[str, object]:
    return queue_identity_item(
        launch_target=None,
        harness="codex",
        workspace="/repo",
        artifact_id="artifact-1",
        envelope={"tool_name": "Bash", "command": "ls"},
        browser_intent=None,
    )


def _install(monkeypatch: pytest.MonkeyPatch, answer) -> None:
    status = SimpleNamespace(
        mode="force",
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=Path("/native"), sha256="sha"),
        capabilities=SimpleNamespace(features=_FEATURES),
    )
    monkeypatch.setattr(native_execution, "native_runtime_status", lambda: status)
    monkeypatch.setattr(native_store_policy, "native_runtime_status", lambda: status)

    def respond(**kwargs: object) -> bytes:
        body = kwargs["payload"]
        assert isinstance(body, bytes)
        request = json.loads(body)["request"]
        assert isinstance(request, dict)
        return answer(request)

    monkeypatch.setattr(native_execution, "native_resident_client_request", respond)
    for module in (native_execution, native_store_policy):
        monkeypatch.setattr(module, "native_record_resident_failure", lambda *_args, **_kwargs: None)
        monkeypatch.setattr(module, "native_record_resident_success", lambda *_args, **_kwargs: None)


def _bound(items: object):
    def answer(request: dict[str, object]) -> bytes:
        return json.dumps(
            {
                "schema": _RESULT_SCHEMA,
                "request_id": request["request_id"],
                "request_sha256": "sha256:" + _canonical_request_sha256(request),
                "status": "ok",
                "code": "ok",
                "payload": {"items": items},
            }
        ).encode()

    return answer


def test_bound_reply_returns_the_resident_identity(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    seen: dict[str, object] = {}

    def answer(request: dict[str, object]) -> bytes:
        seen["items"] = request["items"]
        return _bound([{"identity_key": "", "action_identity": "action-1", "queue_group_id": "queue-1"}])(request)

    _install(monkeypatch, answer)
    identities = native_approval_queue_identities([_item()], guard_home=_home(tmp_path))

    assert seen["items"] == [_item()]
    assert identities == [QueueIdentity("", "action-1", "queue-1")]


@pytest.mark.parametrize(
    "entry",
    [
        {"identity_key": "key", "action_identity": None, "queue_group_id": "queue-1"},
        {"identity_key": "key", "action_identity": "", "queue_group_id": "queue-1"},
        {"identity_key": "key", "action_identity": "action-1", "queue_group_id": None},
        {"identity_key": "key", "action_identity": "action-1", "queue_group_id": ""},
        {"identity_key": None, "action_identity": "action-1", "queue_group_id": "queue-1"},
        {"identity_key": 1, "action_identity": "action-1", "queue_group_id": "queue-1"},
        "not-a-dict",
    ],
)
def test_malformed_identity_reply_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, entry: object) -> None:
    _install(monkeypatch, _bound([entry]))
    with pytest.raises(ApprovalQueueIdentityUnavailableError) as caught:
        native_approval_queue_identities([_item()], guard_home=_home(tmp_path))
    assert caught.value.reason == "rejected"
    assert str(caught.value) == "native_approval_queue_identity_unavailable"


def test_reply_bound_to_another_request_fails_closed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def answer(request: dict[str, object]) -> bytes:
        return json.dumps(
            {
                "schema": _RESULT_SCHEMA,
                "request_id": request["request_id"],
                "request_sha256": "sha256:" + ("0" * 64),
                "status": "ok",
                "code": "ok",
                "payload": {
                    "items": [{"identity_key": "key", "action_identity": "action-1", "queue_group_id": "queue-1"}]
                },
            }
        ).encode()

    _install(monkeypatch, answer)
    with pytest.raises(ApprovalQueueIdentityUnavailableError) as caught:
        native_approval_queue_identities([_item()], guard_home=_home(tmp_path))
    assert caught.value.reason == "unavailable"


def test_oversize_batch_is_rejected_before_the_resident_is_called(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls = {"count": 0}

    def answer(request: dict[str, object]) -> bytes:
        calls["count"] += 1
        return _bound([{"identity_key": "", "action_identity": "action-1", "queue_group_id": "queue-1"}])(request)

    _install(monkeypatch, answer)
    monkeypatch.setattr(identity_module, "_MAX_REQUEST_BYTES", 1)
    with pytest.raises(ApprovalQueueIdentityUnavailableError) as caught:
        native_approval_queue_identities([_item()], guard_home=_home(tmp_path))

    assert caught.value.reason == "rejected"
    assert calls["count"] == 0


def test_missing_resident_reply_is_unavailable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def answer(request: dict[str, object]) -> None:
        del request
        return None

    _install(monkeypatch, answer)
    with pytest.raises(ApprovalQueueIdentityUnavailableError) as caught:
        native_approval_queue_identities([_item()], guard_home=_home(tmp_path))

    assert caught.value.reason == "unavailable"


def test_missing_verifier_is_unavailable(tmp_path: Path) -> None:
    home = tmp_path / "guard-home"
    home.mkdir()
    with pytest.raises(ApprovalQueueIdentityUnavailableError) as caught:
        native_approval_queue_identities([_item()], guard_home=home, provision=False)

    assert caught.value.reason == "unavailable"


def test_bound_error_reply_is_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def answer(request: dict[str, object]) -> bytes:
        return json.dumps(
            {
                "schema": _RESULT_SCHEMA,
                "request_id": request["request_id"],
                "request_sha256": "sha256:" + _canonical_request_sha256(request),
                "status": "error",
                "code": "rejected",
                "payload": {},
            }
        ).encode()

    _install(monkeypatch, answer)
    with pytest.raises(ApprovalQueueIdentityUnavailableError) as caught:
        native_approval_queue_identities([_item()], guard_home=_home(tmp_path))

    assert caught.value.reason == "rejected"
