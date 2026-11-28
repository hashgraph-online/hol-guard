"""The daemon's managed-policy view and its thin pass-through of the edge answer.

What the managed policy means is decided natively: the Rust edge resolves the
view and mediates the content (`guard-runtime` `edge_structured_tests.rs`, and
`guard-command` `content_sensitivity_tests.rs` for the resolution and the
mediation). These tests pin what the daemon sends and what it lets through.
"""

from __future__ import annotations

from pathlib import Path
from time import monotonic

import pytest

from codex_plugin_scanner.guard.hook_review.hook_worker_unavailable import (
    MEDIATION_FIELD,
    structured_outage_overlay,
    withhold_structured_destination,
    withholds_structured_destination,
)
from tests.structured_output_mediation_support import (
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
    assert "structured_output_config" not in request
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


@pytest.mark.parametrize(
    ("answer", "withholds"),
    [
        (("document", {}), False),
        (("document", withhold_structured_destination({})), True),
        (("document", {MEDIATION_FIELD: {"action": "forward"}}), True),
        (("document", {"decision": "allow"}), True),
        (("document", None), True),
        (("silent", None), True),
        (None, True),
        (RuntimeError("down"), True),
    ],
)
def test_only_a_native_answer_that_requires_nothing_leaves_the_destination_open(
    monkeypatch: pytest.MonkeyPatch,
    answer: object,
    withholds: bool,
    tmp_path: Path,
) -> None:
    seen: list[tuple[object, ...]] = []

    def render(kind: str, harness: str, body: dict[str, object], *, guard_home: Path, deadline: float) -> object:
        seen.append((kind, harness, body, guard_home, deadline))
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr("codex_plugin_scanner.guard.hook_review.hook_worker_unavailable.native_render_cli", render)
    deadline = monotonic() + 2
    overlay = structured_outage_overlay(
        harness="omp", event_name="PostToolUse", guard_home=tmp_path, deadline=deadline, load_config=_config
    )
    assert overlay == (withhold_structured_destination({}) if withholds else {})
    params = {"event_name": "PostToolUse"}
    assert seen == [("structured_outage", "omp", params, tmp_path, deadline)]


def test_a_late_native_reply_keeps_the_destination_withheld(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    module = "codex_plugin_scanner.guard.hook_review.hook_worker_unavailable"
    times = iter([1.0, 3.0])
    monkeypatch.setattr(f"{module}.monotonic", lambda: next(times))
    monkeypatch.setattr(f"{module}.native_render_cli", lambda *_args, **_kwargs: ("document", {}))
    overlay = structured_outage_overlay(
        harness="pi", event_name="PostToolUse", guard_home=tmp_path, deadline=2.0, load_config=_config
    )
    assert overlay == withhold_structured_destination({})
