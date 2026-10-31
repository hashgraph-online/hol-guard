"""The daemon's managed-policy view and its thin pass-through of the edge answer.

What the managed policy means is decided natively: the Rust edge resolves the
view and mediates the content (`guard-runtime` `edge_structured_tests.rs`, and
`guard-command` `content_sensitivity_tests.rs` for the resolution and the
mediation). These tests pin what the daemon sends and what it lets through.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import hook_worker_structured
from codex_plugin_scanner.guard.daemon.hook_worker_structured import (
    MEDIATION_FIELD,
    read_structured_view,
    structured_destination_required,
    withhold_stale_forward,
    withhold_structured_destination,
    withholds_structured_destination,
)
from codex_plugin_scanner.guard.native_content_sensitivity import NativeContentSensitivityError
from codex_plugin_scanner.guard.native_policy_snapshot_direct_lane_structured import structured_output_view
from tests.structured_output_mediation_support import (
    FORWARD,
    WITHHOLD,
    _config,
    _mediation,
    _NativeRouteFixture,
    _review,
)


@pytest.mark.parametrize("variant", ["malformed", "missing", "revoked"])
def test_the_view_sent_for_a_configured_policy_carries_its_failure(tmp_path: Path, variant: str) -> None:
    config = _config(status="revoked" if variant == "revoked" else "active")
    if variant == "malformed":
        config.managed_policy.settings["data_control"]["structured_output"]["onMatch"] = "allow"
    elif variant == "missing":
        config.managed_policy = None
    # The edge answers a policy it cannot trust with a withhold; the daemon
    # neither resolves nor softens it.
    fixture = _NativeRouteFixture(config, mediation=_mediation("withhold", "structured_managed_policy_invalid"))
    response, native_used = _review(fixture, tmp_path)
    assert native_used is True
    (request,) = fixture.captured
    assert request["structured_output_config"] == structured_output_view(config)
    assert response[MEDIATION_FIELD]["action"] == "withhold"  # type: ignore[index]
    assert response["decision"] == "allow"


@pytest.mark.parametrize(
    ("harness", "event_name", "expected"),
    [
        ("pi", "PostToolUse", True),
        ("omp", "PostToolUse", True),
        ("Oh-My-Pi", "PostToolUse", True),
        ("oh_my_pi", "PostToolUse", True),
        (" pi-agent ", "PostToolUse", True),
        ("PI_CODING_AGENT", "PostToolUse", True),
        ("pi", "PreToolUse", False),
        ("omp", "UserPromptSubmit", False),
        ("codex", "PostToolUse", False),
        ("claude-code", "PostToolUse", False),
    ],
)
def test_only_a_pi_post_tool_use_can_carry_a_managed_destination(harness: str, event_name: str, expected: bool) -> None:
    assert withholds_structured_destination(harness=harness, event_name=event_name) is expected


def test_the_unavailable_withhold_keeps_the_answer_and_names_no_receipt() -> None:
    response = {"decision": "allow", "policy_action": "allow"}
    withheld = withhold_structured_destination(response)
    assert withheld == {
        **response,
        MEDIATION_FIELD: {
            "schema": "guard-structured-content-mediation.v1",
            "action": "withhold",
            "reason_code": "structured_native_edge_unavailable",
        },
    }
    assert MEDIATION_FIELD not in response


def test_a_view_is_read_from_the_config_and_an_unreadable_config_reads_as_empty() -> None:
    config = _config()
    assert read_structured_view(lambda: config) == structured_output_view(config)

    def broken() -> object:
        raise OSError("machine policy unavailable")

    assert read_structured_view(broken) == {}
    assert read_structured_view(lambda: None) == {}
    # A config whose view cannot be sent unchanged binds nothing.
    unsendable = _config()
    unsendable.managed_policy.settings["data_control"]["structured_output"]["onMatch"] = 1.5
    assert read_structured_view(lambda: unsendable) == {}


def test_an_empty_view_requires_the_destination_without_asking_native(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("an empty view needs no native resolution")

    monkeypatch.setattr(hook_worker_structured, "content_query", refuse)
    assert structured_destination_required({}, harness="omp") is True


@pytest.mark.parametrize(
    ("answer", "required"),
    [
        ({"binding": None, "required": False, "reason_code": None}, False),
        ({"binding": None, "required": True, "reason_code": "structured_managed_authority_revoked"}, True),
        ({"binding": None, "required": "no"}, True),
        ({"binding": None}, True),
        ("not an object", True),
        (NativeContentSensitivityError("down"), True),
        (RuntimeError("down"), True),
    ],
    ids=["not-required", "required", "malformed-flag", "missing-flag", "not-a-mapping", "native-error", "other-error"],
)
def test_only_a_native_answer_that_requires_nothing_leaves_the_destination_open(
    monkeypatch: pytest.MonkeyPatch,
    answer: object,
    required: bool,
) -> None:
    seen: list[tuple[str, dict[str, object]]] = []

    def resolve(query: str, body: dict[str, object]) -> object:
        seen.append((query, body))
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(hook_worker_structured, "content_query", resolve)
    view = structured_output_view(_config())
    assert view is not None
    assert structured_destination_required(view, harness="omp") is required
    assert seen == [("resolution", {"config": view, "harness": "omp"})]


def _loader(*configs: object) -> tuple[Callable[[], object], list[int]]:
    reads: list[int] = []
    pending = list(configs)

    def load() -> object:
        reads.append(1)
        current = pending.pop(0) if len(pending) > 1 else pending[0]
        if isinstance(current, Exception):
            raise current
        return current

    return load, reads


@pytest.mark.parametrize("disposition", [WITHHOLD, {"action": "withhold"}])
def test_a_withhold_passes_through_without_a_second_read(disposition: dict[str, object]) -> None:
    load, reads = _loader(_config(status="revoked"))
    response = {"decision": "allow", MEDIATION_FIELD: disposition}
    view = structured_output_view(_config())
    assert view is not None
    assert withhold_stale_forward(response, view=view, load_config=load, deadline=None) is response
    assert reads == []


@pytest.mark.parametrize("response", [{"decision": "allow"}, {MEDIATION_FIELD: None}, {MEDIATION_FIELD: "forward"}])
def test_an_answer_without_a_forward_passes_through(response: dict[str, object]) -> None:
    load, reads = _loader(_config())
    assert withhold_stale_forward(response, view={}, load_config=load, deadline=None) is response
    assert reads == []


def test_a_forward_under_an_unchanged_view_passes_through_once_reread() -> None:
    config = _config()
    load, reads = _loader(config)
    view = structured_output_view(config)
    assert view is not None
    response = {"decision": "allow", MEDIATION_FIELD: FORWARD}
    released = withhold_stale_forward(response, view=view, load_config=load, deadline=time.monotonic() + 60)
    assert released is response
    assert reads == [1]


@pytest.mark.parametrize(
    ("after", "reason"),
    [
        (_config(status="revoked"), "structured_binding_changed"),
        (_config(status="absent", locked=()), "structured_binding_changed"),
        (OSError("untrusted callback detail"), "structured_binding_recheck_failed"),
        (ValueError("untrusted callback detail"), "structured_binding_recheck_failed"),
        (None, "structured_binding_changed"),
    ],
    ids=["revoked", "removed", "os-error", "value-error", "no-config"],
)
def test_a_forward_is_withheld_when_the_view_changed_or_cannot_be_confirmed(
    after: object,
    reason: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    view = structured_output_view(_config())
    assert view is not None
    load, reads = _loader(after)
    response = {"decision": "allow", "policy_action": "allow", MEDIATION_FIELD: FORWARD}
    withheld = withhold_stale_forward(response, view=view, load_config=load, deadline=None)
    # The verdict is untouched, the forward is not, and its scan binding goes.
    assert withheld == {
        "decision": "allow",
        "policy_action": "allow",
        MEDIATION_FIELD: _mediation("withhold", reason),
    }
    assert "content_sha256" not in withheld[MEDIATION_FIELD]  # type: ignore[operator]
    assert "untrusted callback detail" not in caplog.text
    assert "untrusted callback detail" not in str(withheld)
    assert reads == [1]


def test_a_forward_is_withheld_once_the_deadline_has_passed_without_reading() -> None:
    load, reads = _loader(_config())
    view = structured_output_view(_config())
    assert view is not None
    response = {"decision": "allow", MEDIATION_FIELD: FORWARD}
    withheld = withhold_stale_forward(response, view=view, load_config=load, deadline=0.0)
    assert withheld[MEDIATION_FIELD] == _mediation("withhold", "structured_review_deadline_exceeded")
    assert reads == []


def test_a_forward_is_withheld_when_its_reread_crosses_the_deadline() -> None:
    config = _config()
    view = structured_output_view(config)
    assert view is not None
    deadline = time.monotonic() + 0.2

    def slow_load() -> object:
        time.sleep(0.3)
        return config

    response = {"decision": "allow", MEDIATION_FIELD: FORWARD}
    withheld = withhold_stale_forward(response, view=view, load_config=slow_load, deadline=deadline)
    assert withheld[MEDIATION_FIELD] == _mediation("withhold", "structured_review_deadline_exceeded")


def test_an_unmediated_allow_is_withheld_once_a_policy_is_activated() -> None:
    view = structured_output_view(_config(status="absent", locked=()))
    assert view is not None
    load, reads = _loader(_config())
    response = {"decision": "allow"}
    withheld = withhold_stale_forward(response, view=view, load_config=load, deadline=None, allowed=True)
    # Nothing was mediated, so the withhold names no native decision.
    expected = _mediation("withhold", "structured_binding_changed")
    del expected["native_decision_id"]
    assert withheld == {"decision": "allow", MEDIATION_FIELD: expected}
    assert reads == [1]


def test_an_unmediated_allow_under_an_unchanged_view_passes_through() -> None:
    config = _config(status="absent", locked=())
    view = structured_output_view(config)
    assert view is not None
    load, reads = _loader(config)
    response = {"decision": "allow"}
    # The deadline only bounds a forward the edge scanned.
    assert withhold_stale_forward(response, view=view, load_config=load, deadline=0.0, allowed=True) is response
    assert reads == [1]
