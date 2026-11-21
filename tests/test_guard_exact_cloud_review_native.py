"""The native runtime signs and checks exact Cloud Review consent."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.mdm import runtime_request
from codex_plugin_scanner.guard.runtime import exact_cloud_review
from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    ExactCloudReviewError,
    _capability_digest,
    _exact_job_identity,
    enable_exact_cloud_review,
    exact_cloud_review_status,
)
from tests.guard_exact_cloud_review_support import connected_exact_review_store


def test_a_capability_issued_here_is_valid_until_it_expires(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    issued = enable_exact_cloud_review(store, ttl_seconds=3600, now="2026-08-24T12:00:00+00:00")

    assert issued["capability_valid"] is True
    later = exact_cloud_review_status(store, now="2026-08-24T13:00:00Z")
    assert later["capability_valid"] is False
    assert later["reason"] == "cloud_review_capability_expired"


def test_digests_cover_the_stable_json_bytes() -> None:
    # sha256 of `{"a":null,"b":[1,2.0,"é"]}`, as stable_json_serialize writes it.
    assert _capability_digest({"b": [1, 2.0, "é"], "a": None}) == (
        "878131cedddfbee4292f213fde5ba4bcba524ebb0d2702e17efbf25be41afbe4"
    )


def test_a_lease_longer_than_a_day_is_refused() -> None:
    job = {
        "operation": "guard.review.resolveExact",
        "protocolVersion": 2,
        "id": "job-1",
        "deviceId": "device-1",
        "workspaceId": "workspace-1",
        "nonce": "nonce-1",
        "expiresAt": "2026-08-25T12:00:01+00:00",
        "idempotencyKey": "idem-1",
        "payload": {},
    }
    with pytest.raises(ExactCloudReviewError, match="remote_exact_job_expiry_too_distant"):
        _exact_job_identity(job, now="2026-08-24T12:00:00+00:00")
    identity = _exact_job_identity({**job, "expiresAt": "2026-08-24T13:00:00Z"}, now="2026-08-24T12:00:00+00:00")
    assert identity["id"] == "job-1"


def test_without_the_runtime_no_capability_is_issued_or_honoured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = connected_exact_review_store(tmp_path)
    enable_exact_cloud_review(store)
    monkeypatch.setattr(runtime_request, "runtime_answer", lambda *_args, **_kwargs: None)
    # A resident this process talks to is the runtime too, so it is gone as well.
    monkeypatch.setattr(exact_cloud_review, "resident_exact_cloud_review_answer", lambda *_args: None)

    status = exact_cloud_review_status(store)
    assert status["capability_valid"] is False
    assert status["reason"] == "native_exact_cloud_review_unavailable"
    with pytest.raises(ExactCloudReviewError, match="native_exact_cloud_review_unavailable"):
        enable_exact_cloud_review(store)


class _Identity:
    path = Path("/runtime/hol-guard-runtime")


class _Status:
    identity = _Identity()


class _Store:
    guard_home = Path("/guard-home")


def _resident(monkeypatch: pytest.MonkeyPatch, *, ready: bool, reply: dict[str, object] | None) -> list[dict]:
    from codex_plugin_scanner.guard import native_execution, native_resident_client

    sent: list[dict] = []

    def resident_request(**kwargs: object) -> dict[str, object] | None:
        sent.append(dict(kwargs))
        return reply

    monkeypatch.setattr(native_execution, "native_runtime_status", lambda: _Status())
    monkeypatch.setattr(native_resident_client, "native_resident_client_ready", lambda *_args: ready)
    monkeypatch.setattr(native_execution, "_resident_request", resident_request)
    return sent


def _spawned(monkeypatch: pytest.MonkeyPatch) -> list[dict]:
    spawned: list[dict] = []

    def runtime_answer(_feature: str, _command: str, request: dict, **_kwargs: object) -> dict[str, object]:
        spawned.append(request)
        return {"digest": "spawned"}

    monkeypatch.setattr(runtime_request, "runtime_answer", runtime_answer)
    return spawned


def test_a_running_resident_answers_without_spawning_a_helper(monkeypatch: pytest.MonkeyPatch) -> None:
    reply = {"schema": "guard-exact-cloud-review-resident-result.v1", "answer": {"digest": "resident"}}
    sent = _resident(monkeypatch, ready=True, reply=reply)
    spawned = _spawned(monkeypatch)

    assert _capability_digest({"a": 1}, _Store()) == "resident"
    assert spawned == []
    assert sent[0]["operation"] == "exact_cloud_review"
    assert sent[0]["required_feature"] == "native-exact-cloud-review-resident-v1"
    assert sent[0]["request"] == {
        "schema": "guard-exact-cloud-review-resident-request.v1",
        "request": {"op": "digest", "payload": {"a": 1}},
    }


@pytest.mark.parametrize(
    ("ready", "reply"),
    [
        (False, {"answer": {"digest": "resident"}}),
        (True, None),
        (True, {"answer": "not an answer"}),
    ],
)
def test_the_helper_answers_when_the_resident_cannot(
    monkeypatch: pytest.MonkeyPatch, ready: bool, reply: dict[str, object] | None
) -> None:
    sent = _resident(monkeypatch, ready=ready, reply=reply)
    spawned = _spawned(monkeypatch)

    assert _capability_digest({"a": 1}, _Store()) == "spawned"
    assert spawned == [{"op": "digest", "payload": {"a": 1}}]
    assert len(sent) == (1 if ready else 0)


def test_without_a_store_only_the_helper_answers(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = _resident(monkeypatch, ready=True, reply={"answer": {"digest": "resident"}})
    spawned = _spawned(monkeypatch)

    assert _capability_digest({"a": 1}) == "spawned"
    assert sent == [] and len(spawned) == 1
