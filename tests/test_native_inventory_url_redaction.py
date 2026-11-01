"""The inventory URL adapter returns only answers bound to the request it sent."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard import (
    inventory_contract_redaction,
    native_execution,
    native_inventory_url_redaction,
)
from codex_plugin_scanner.guard.native_context import _canonical_request_sha256

_ANSWERS = {
    "redact_url": {"kind": "redact_url", "value": "https://example.test/path"},
    "redact_headers": {"kind": "redact_headers", "headers": [["authorization", "present_redacted"]]},
    "classify_endpoint_host": {"kind": "classify_endpoint_host", "host_class": "remote_public"},
    "redact_command_value": {"kind": "redact_command_value", "value": "npx server --api-key redacted"},
    "redact_known_path": {"kind": "redact_known_path", "value": "{home}/work/file.txt"},
}


def _install(monkeypatch: pytest.MonkeyPatch, mutate) -> list[tuple[str, object]]:
    recorded: list[tuple[str, object]] = []

    def fake(*, request, response_schema, record_success, status, **_kwargs) -> dict[str, Any]:
        assert record_success is False
        assert status.identity.sha256 == "0" * 64
        result: dict[str, Any] = {
            "schema": response_schema,
            "request_id": request["request_id"],
            # The resident answers with the prefixed token.
            "request_sha256": "sha256:" + _canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "answers": [dict(_ANSWERS[task["kind"]]) for task in request["tasks"]],
        }
        mutate(result)
        return result

    monkeypatch.setattr(native_inventory_url_redaction, "ensure_resident_prerequisite", lambda _home: True)
    monkeypatch.setattr(native_execution, "_resident_request", fake)
    monkeypatch.setattr(
        native_inventory_url_redaction,
        "native_runtime_status",
        lambda: SimpleNamespace(identity=SimpleNamespace(sha256="0" * 64)),
    )
    monkeypatch.setattr(
        native_inventory_url_redaction,
        "native_record_resident_success",
        lambda *_args: recorded.append(("success", None)),
    )
    monkeypatch.setattr(
        native_inventory_url_redaction,
        "native_record_resident_failure",
        lambda *_args, reason: recorded.append(("failure", reason)),
    )
    return recorded


def test_each_seam_returns_the_answer_the_resident_gave_for_its_task(monkeypatch, tmp_path) -> None:
    recorded = _install(monkeypatch, lambda result: None)
    assert (
        native_inventory_url_redaction.redact_url("https://u:p@example.test/path", guard_home=tmp_path)
        == "https://example.test/path"
    )
    assert native_inventory_url_redaction.redact_headers(["Authorization"], guard_home=tmp_path) == {
        "authorization": "present_redacted"
    }
    assert (
        native_inventory_url_redaction.classify_endpoint_host("https://example.test", guard_home=tmp_path)
        == "remote_public"
    )
    assert recorded == [("success", None)] * 3


def test_a_batch_keeps_one_answer_per_task_in_the_order_they_were_sent(monkeypatch, tmp_path) -> None:
    _install(monkeypatch, lambda result: None)
    answers = native_inventory_url_redaction._answers(
        [
            {"kind": "classify_endpoint_host", "value": None},
            {"kind": "redact_url", "value": "https://example.test/path"},
            {"kind": "redact_headers", "header_names": ["Cookie"]},
        ],
        guard_home=tmp_path,
    )
    assert answers == [
        "remote_public",
        "https://example.test/path",
        {"authorization": "present_redacted"},
    ]


def test_more_tasks_than_the_bound_allows_never_reach_the_resident(monkeypatch, tmp_path) -> None:
    recorded = _install(monkeypatch, lambda result: None)
    tasks = [{"kind": "redact_url", "value": "https://example.test"}] * (native_inventory_url_redaction._MAX_TASKS + 1)
    with pytest.raises(native_inventory_url_redaction.NativeInventoryUrlRedactionError, match="invalid"):
        native_inventory_url_redaction._answers(tasks, guard_home=tmp_path)
    assert recorded == []


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda result: result.update(request_sha256="sha256:" + "0" * 64), id="foreign-digest"),
        pytest.param(
            # The bare hex of the right request is still the wrong token.
            lambda result: result.update(request_sha256=result["request_sha256"].removeprefix("sha256:")),
            id="unprefixed-digest",
        ),
        pytest.param(lambda result: result.update(request_id="other"), id="foreign-request-id"),
        pytest.param(lambda result: result.update(code="other"), id="not-ok-code"),
        pytest.param(lambda result: result.update(status="error"), id="not-ok-status"),
        pytest.param(lambda result: result.update(extra=1), id="unknown-key"),
        pytest.param(lambda result: result.pop("answers"), id="missing-answers"),
        pytest.param(lambda result: result.update(answers="nope"), id="answers-not-a-list"),
        pytest.param(lambda result: result["answers"].append({}), id="one-answer-too-many"),
        pytest.param(lambda result: result["answers"][0].update(kind="other"), id="answer-for-another-task"),
        pytest.param(lambda result: result["answers"][0].update(value=None), id="answer-field-not-a-string"),
    ],
)
def test_an_unusable_reply_raises_and_records_a_failure(monkeypatch, tmp_path, mutate) -> None:
    recorded = _install(monkeypatch, mutate)
    with pytest.raises(native_inventory_url_redaction.NativeInventoryUrlRedactionError):
        native_inventory_url_redaction.redact_url("https://example.test", guard_home=tmp_path)
    assert recorded == [("failure", "native_inventory_url_redaction_result")]


@pytest.mark.parametrize(
    "headers",
    [
        pytest.param([["authorization"]], id="pair-of-one"),
        pytest.param([["authorization", None]], id="presence-not-a-string"),
        pytest.param([{"name": "authorization"}], id="pair-not-a-list"),
    ],
)
def test_a_header_answer_that_is_not_a_name_and_a_presence_is_refused(monkeypatch, tmp_path, headers) -> None:
    recorded = _install(monkeypatch, lambda result: result["answers"][0].update(headers=headers))
    with pytest.raises(native_inventory_url_redaction.NativeInventoryUrlRedactionError):
        native_inventory_url_redaction.redact_headers(["Authorization"], guard_home=tmp_path)
    assert recorded == [("failure", "native_inventory_url_redaction_result")]


def test_a_missing_resident_reply_leaves_recording_to_the_transport(monkeypatch, tmp_path) -> None:
    recorded = _install(monkeypatch, lambda result: None)
    monkeypatch.setattr(native_execution, "_resident_request", lambda **_kwargs: None)
    with pytest.raises(native_inventory_url_redaction.NativeInventoryUrlRedactionError, match="unavailable"):
        native_inventory_url_redaction.redact_url("https://example.test", guard_home=tmp_path)
    assert recorded == []


def test_a_resident_that_cannot_start_is_not_asked_for_a_redaction(monkeypatch, tmp_path) -> None:
    recorded = _install(monkeypatch, lambda result: None)
    monkeypatch.setattr(native_inventory_url_redaction, "ensure_resident_prerequisite", lambda _home: False)
    with pytest.raises(native_inventory_url_redaction.NativeInventoryUrlRedactionError, match="unavailable"):
        native_inventory_url_redaction.classify_endpoint_host("https://example.test", guard_home=tmp_path)
    assert recorded == []


@pytest.mark.parametrize(
    "call",
    [
        pytest.param(lambda: inventory_contract_redaction.redact_url("https://example.test"), id="redact-url"),
        pytest.param(
            lambda: inventory_contract_redaction.redact_headers({"Authorization": "secret"}),
            id="redact-headers",
        ),
        pytest.param(
            lambda: inventory_contract_redaction.classify_endpoint_host("https://example.test"),
            id="classify-endpoint-host",
        ),
        pytest.param(
            lambda: inventory_contract_redaction._redact_command_value("npx server --api-key k", Path.home(), None),
            id="redact-command-value",
        ),
        pytest.param(
            lambda: inventory_contract_redaction._redact_known_path("/etc/hosts", Path.home(), None),
            id="redact-known-path",
        ),
    ],
)
def test_the_exported_seams_fail_closed_rather_than_redacting_in_python(monkeypatch, call) -> None:
    def unavailable(*_args, **_kwargs):
        raise native_inventory_url_redaction.NativeInventoryUrlRedactionError(
            "native_inventory_url_redaction_unavailable"
        )

    for name in (
        "redact_url",
        "redact_headers",
        "classify_endpoint_host",
        "redact_command_value",
        "redact_known_path",
    ):
        monkeypatch.setattr(native_inventory_url_redaction, name, unavailable)
    with pytest.raises(native_inventory_url_redaction.NativeInventoryUrlRedactionError, match="unavailable"):
        call()


def test_a_host_class_outside_the_contract_is_refused(monkeypatch, tmp_path) -> None:
    def mutate(result: dict[str, Any]) -> None:
        result["answers"] = [{"kind": "classify_endpoint_host", "host_class": "trusted"}]

    recorded = _install(monkeypatch, mutate)
    with pytest.raises(native_inventory_url_redaction.NativeInventoryUrlRedactionError):
        native_inventory_url_redaction.classify_endpoint_host("https://example.test", guard_home=tmp_path)
    assert recorded == [("failure", "native_inventory_url_redaction_result")]


def test_a_pass_answers_every_prefetched_value_in_one_request(monkeypatch, tmp_path) -> None:
    recorded = _install(monkeypatch, lambda result: None)
    urls = [f"https://example.test/{index}" for index in range(50)]
    with native_inventory_url_redaction.redaction_pass():
        native_inventory_url_redaction.prefetch([*urls, *urls], urls[:3], guard_home=tmp_path)
        for url in urls:
            native_inventory_url_redaction.redact_url(url, guard_home=tmp_path)
        native_inventory_url_redaction.classify_endpoint_host(urls[0], guard_home=tmp_path)
    assert recorded == [("success", None)]


def test_a_pass_splits_a_prefetch_larger_than_one_request(monkeypatch, tmp_path) -> None:
    recorded = _install(monkeypatch, lambda result: None)
    urls = [f"https://example.test/{index}" for index in range(native_inventory_url_redaction._MAX_TASKS + 1)]
    with native_inventory_url_redaction.redaction_pass():
        native_inventory_url_redaction.prefetch(urls, guard_home=tmp_path)
    assert recorded == [("success", None)] * 2


def test_answers_are_forgotten_when_the_pass_ends(monkeypatch, tmp_path) -> None:
    recorded = _install(monkeypatch, lambda result: None)
    with native_inventory_url_redaction.redaction_pass():
        native_inventory_url_redaction.redact_url("https://example.test", guard_home=tmp_path)
    native_inventory_url_redaction.redact_url("https://example.test", guard_home=tmp_path)
    native_inventory_url_redaction.prefetch(["https://example.test/other"], guard_home=tmp_path)
    assert recorded == [("success", None)] * 2


def test_a_command_and_a_path_travel_with_the_roots_their_answer_depends_on(monkeypatch, tmp_path) -> None:
    sent: list[dict[str, Any]] = []

    def fake(*, request, response_schema, **_kwargs) -> dict[str, Any]:
        sent.extend(request["tasks"])
        return {
            "schema": response_schema,
            "request_id": request["request_id"],
            "request_sha256": "sha256:" + _canonical_request_sha256(request),
            "status": "ok",
            "code": "ok",
            "answers": [dict(_ANSWERS[task["kind"]]) for task in request["tasks"]],
        }

    _install(monkeypatch, lambda result: None)
    monkeypatch.setattr(native_execution, "_resident_request", fake)
    assert (
        native_inventory_url_redaction.redact_command_value(
            "npx server --api-key k", Path("/home/u"), Path("/home/u/work"), guard_home=tmp_path
        )
        == "npx server --api-key redacted"
    )
    assert (
        native_inventory_url_redaction.redact_known_path("work/file.txt", Path("/home/u"), None, guard_home=tmp_path)
        == "{home}/work/file.txt"
    )
    assert sent == [
        {
            "kind": "redact_command_value",
            "value": "npx server --api-key k",
            "home_dir": "/home/u",
            "workspace_dir": "/home/u/work",
            "cwd": os.getcwd(),
        },
        {
            "kind": "redact_known_path",
            "value": "work/file.txt",
            "home_dir": "/home/u",
            "workspace_dir": None,
            "cwd": os.getcwd(),
        },
    ]


def test_one_string_under_two_roots_is_two_answers_not_one_cached_answer(monkeypatch, tmp_path) -> None:
    recorded = _install(monkeypatch, lambda result: None)
    with native_inventory_url_redaction.redaction_pass():
        for home in (Path("/home/one"), Path("/home/two"), Path("/home/one")):
            native_inventory_url_redaction.redact_known_path("/x/file.txt", home, None, guard_home=tmp_path)
    # Three lookups, two distinct roots: the third reads the first answer.
    assert recorded == [("success", None)] * 2


def test_a_prefetched_path_and_command_answer_their_own_later_lookups(monkeypatch, tmp_path) -> None:
    recorded = _install(monkeypatch, lambda result: None)
    home = tmp_path / "home"
    workspace = tmp_path / "workspace"
    paths = [f"{home}/config/{index}.json" for index in range(30)]
    commands = [f"npx tool-{index} --token abc" for index in range(30)]
    with native_inventory_url_redaction.redaction_pass():
        native_inventory_url_redaction.prefetch(
            [],
            paths=[*paths, *paths],
            commands=commands,
            home_dir=home,
            workspace_dir=workspace,
            guard_home=tmp_path,
        )
        for path in paths:
            native_inventory_url_redaction.redact_known_path(path, home, workspace, guard_home=tmp_path)
        for command in commands:
            native_inventory_url_redaction.redact_command_value(command, home, workspace, guard_home=tmp_path)
    assert recorded == [("success", None)]


def test_a_prefetched_path_is_not_reused_under_other_roots(monkeypatch, tmp_path) -> None:
    recorded = _install(monkeypatch, lambda result: None)
    home = tmp_path / "home"
    with native_inventory_url_redaction.redaction_pass():
        native_inventory_url_redaction.prefetch(
            [],
            paths=["config.json"],
            home_dir=home,
            workspace_dir=tmp_path / "one",
            guard_home=tmp_path,
        )
        native_inventory_url_redaction.redact_known_path("config.json", home, tmp_path / "two", guard_home=tmp_path)
    assert recorded == [("success", None)] * 2


def test_roots_a_prefetch_was_not_given_leave_its_paths_to_their_own_requests(monkeypatch, tmp_path) -> None:
    recorded = _install(monkeypatch, lambda result: None)
    with native_inventory_url_redaction.redaction_pass():
        native_inventory_url_redaction.prefetch([], paths=["config.json"], guard_home=tmp_path)
        native_inventory_url_redaction.redact_known_path("config.json", tmp_path, None, guard_home=tmp_path)
    assert recorded == [("success", None)]


def test_a_deleted_working_directory_still_describes_a_task(monkeypatch, tmp_path) -> None:
    def raising() -> str:
        raise OSError("getcwd")

    monkeypatch.setattr(native_inventory_url_redaction.os, "getcwd", raising)
    task = native_inventory_url_redaction._rooted("redact_known_path", "config.json", tmp_path, None)
    assert task["cwd"] == ""
