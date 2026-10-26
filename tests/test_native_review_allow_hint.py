"""The daemon asks the resident for the Extensions hints instead of reviewing the command itself.

The resident's ``extension_review_hint`` op owns the review, the all-or-nothing
settlement gate and the coverage read-out (``hook_direct_review_hint_op.rs``).
These tests pin what the daemon still decides: which command and launch
directory it asks about, that an answer is shape-checked before it is stored,
and that a failed or late answer never touches the review itself.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from codex_plugin_scanner.guard.daemon import native_review_allow_hint as module
from codex_plugin_scanner.guard.runtime.extension_allow_hint import validated_extension_allow_hint
from codex_plugin_scanner.guard.runtime.extension_coverage_hint import validated_extension_coverage_hint

_ADMITTED = SimpleNamespace(authority_failure=None, awaiting_enrollment=False)


def _record_asks(monkeypatch, answer: dict[str, object] | None = None) -> list[dict[str, Any]]:
    asked: list[dict[str, Any]] = []

    def ask(payload, **kwargs: Any) -> dict[str, object] | None:
        asked.append({"payload": payload, **kwargs})
        return answer

    monkeypatch.setattr(module, "_ask_review_hint", ask)
    return asked


def _pending_shell(workspace: Path, cwd: str | None = None, **tool_input: object) -> dict[str, object]:
    raw_payload: dict[str, object] = {
        "tool_name": "Shell",
        "tool_input": {"command": "git fetch origin main", **tool_input},
    }
    if cwd is not None:
        raw_payload["cwd"] = cwd
    return {
        "status": "pending",
        "workspace": str(workspace),
        "raw_command_text": "git fetch origin main",
        "action_envelope_json": {
            "action_type": "shell_command",
            "command": "git fetch origin main",
            "raw_payload_redacted": raw_payload,
        },
    }


def test_live_recovery_asks_about_the_command_alone_in_its_launch_directory(monkeypatch, tmp_path: Path) -> None:
    asked = _record_asks(monkeypatch, answer=dict(_LIVE_ALLOW))
    sub_cwd = tmp_path / "subdir"
    sub_cwd.mkdir()

    hint = module.live_approval_extension_hint(
        _pending_shell(tmp_path, str(sub_cwd)), guard_home=tmp_path, snapshot=_ADMITTED
    )

    assert hint == _LIVE_ALLOW
    assert asked[0]["payload"] == {"tool_input": {"command": "git fetch origin main"}, "cwd": str(sub_cwd.resolve())}
    assert asked[0]["guard_home"] == tmp_path
    assert asked[0]["workspace"] is None
    assert asked[0].get("paused") is None
    assert 0 < asked[0]["budget_seconds"] <= 1.2


def test_live_recovery_skips_a_tool_call_that_carried_more_than_the_command(monkeypatch, tmp_path: Path) -> None:
    asked = _record_asks(monkeypatch, answer=dict(_LIVE_ALLOW))

    approval = _pending_shell(tmp_path, str(tmp_path), path=".env")

    assert module.live_approval_extension_hint(approval, guard_home=tmp_path, snapshot=_ADMITTED) is None
    assert asked == []


def test_live_recovery_resolves_a_home_relative_launch_directory(monkeypatch, tmp_path: Path) -> None:
    asked = _record_asks(monkeypatch, answer=dict(_LIVE_ALLOW))
    home = tmp_path / "home"
    project = home / "project"
    project.mkdir(parents=True)
    monkeypatch.setattr(module.Path, "home", classmethod(lambda _cls: home))

    hint = module.live_approval_extension_hint(
        _pending_shell(tmp_path, "~/project", working_directory="~/project"), guard_home=tmp_path, snapshot=_ADMITTED
    )

    assert hint is not None
    assert asked[0]["payload"]["cwd"] == str(project.resolve())
    assert asked[0]["home_dir"] == home


def test_a_redacted_launch_directory_recovers_neither_hint(monkeypatch, tmp_path: Path) -> None:
    """A review run somewhere else names neither the settlement nor the extension.

    An approval queued from a directory outside the home directory stores
    ``.../name``, so the command cannot be re-reviewed where it really ran.
    Extension rules read the directory — Git matches a fetch differently inside
    a repository than outside one — so a review run in the workspace can name
    an extension that never governed the command. A step label pointing at a
    permission to pre-configure is as wrong as a settlement promise when it
    names the wrong extension, so this row asks nothing.
    """

    asked = _record_asks(monkeypatch, answer=dict(_LIVE_ALLOW))
    home = tmp_path / "home"
    (home / "project").mkdir(parents=True)
    monkeypatch.setattr(module.Path, "home", classmethod(lambda _cls: home))

    approval = _pending_shell(tmp_path, ".../project", working_directory=".../project")

    assert module.live_approval_extension_hint(approval, guard_home=tmp_path, snapshot=_ADMITTED) is None
    assert asked == []


@pytest.mark.parametrize(
    ("approval", "snapshot"),
    [
        ({"status": "approved", "raw_command_text": "git fetch origin main"}, _ADMITTED),
        ({"status": "pending", "action_envelope_json": {"action_type": "file_write"}}, _ADMITTED),
        ({"status": "pending", "raw_command_text": "  "}, _ADMITTED),
        (
            {"status": "pending", "raw_command_text": "git fetch origin main"},
            SimpleNamespace(authority_failure="tampered", awaiting_enrollment=False),
        ),
    ],
)
def test_live_recovery_asks_only_for_a_pending_shell_command_under_an_admitted_authority(
    monkeypatch, tmp_path: Path, approval: dict[str, object], snapshot: object
) -> None:
    asked = _record_asks(monkeypatch, answer=dict(_LIVE_ALLOW))

    assert module.live_approval_extension_hint(approval, guard_home=tmp_path, snapshot=snapshot) is None
    assert asked == []


def test_a_never_enrolled_device_still_asks(monkeypatch, tmp_path: Path) -> None:
    asked = _record_asks(monkeypatch, answer=dict(_LIVE_ALLOW))
    snapshot = SimpleNamespace(authority_failure="unenrolled", awaiting_enrollment=True)

    assert (
        module.live_approval_extension_hint(
            {"status": "pending", "workspace": str(tmp_path), "raw_command_text": "git fetch origin main"},
            guard_home=tmp_path,
            snapshot=snapshot,
        )
        == _LIVE_ALLOW
    )
    assert asked[0]["payload"] == {"tool_input": {"command": "git fetch origin main"}, "cwd": str(tmp_path.resolve())}


def test_queue_time_hints_hand_the_resident_the_paused_result(monkeypatch, tmp_path: Path) -> None:
    asked = _record_asks(monkeypatch, answer=dict(_STORED_COVERAGE))
    payload = {"tool_name": "Bash", "tool_input": {"command": "git fetch origin main"}}
    paused = {"decision": "review", "reason_code": "native_extension_review", "command_extensions": {}}
    store = SimpleNamespace(guard_home=tmp_path)

    hint = module.native_review_hint(store, payload, paused, tmp_path, tmp_path, None, None)

    assert hint == _STORED_COVERAGE
    assert asked[0]["payload"] == payload
    assert asked[0]["paused"] == paused
    assert asked[0]["workspace"] == tmp_path
    assert asked[0]["home_dir"] == tmp_path
    assert asked[0]["budget_seconds"] == 5.0


def test_queue_time_hints_leave_the_hook_time_to_persist_the_review(monkeypatch, tmp_path: Path) -> None:
    asked = _record_asks(monkeypatch)
    monkeypatch.setattr(module.time, "monotonic", lambda: 100.0)
    store = SimpleNamespace(guard_home=tmp_path)
    paused = {"command_extensions": {}}

    module.native_review_hint(store, {}, paused, None, None, 100.6, None)
    assert asked[0]["budget_seconds"] == pytest.approx(0.25)

    # Too little left after the margin: the review is persisted without hints.
    assert module.native_review_hint(store, {}, paused, None, None, 100.45, None) is None
    assert len(asked) == 1


def test_queue_time_hints_need_extension_evidence_to_ask(monkeypatch, tmp_path: Path) -> None:
    asked = _record_asks(monkeypatch, answer=dict(_STORED_COVERAGE))
    store = SimpleNamespace(guard_home=tmp_path)

    assert module.native_review_hint(store, {}, {"decision": "review"}, tmp_path, tmp_path, None, None) is None
    assert asked == []


def test_queue_time_hints_need_a_guard_home_to_reach_the_resident(monkeypatch, tmp_path: Path) -> None:
    asked = _record_asks(monkeypatch, answer=dict(_STORED_COVERAGE))

    assert module.native_review_hint(object(), {}, {"command_extensions": {}}, tmp_path, tmp_path, None, None) is None
    assert asked == []


def _answering(monkeypatch, hint: object) -> list[dict[str, Any]]:
    """Stand in for the resident: record the query and hand ``hint`` to the validator."""

    queries: list[dict[str, Any]] = []

    def decide(query, _guard_home, _fields, validate, **kwargs: Any) -> None:
        queries.append({"query": query, **kwargs})
        validate({"hint": hint})

    monkeypatch.setattr(module, "_decide", decide)
    return queries


def test_the_query_sends_every_field_the_resident_digests(monkeypatch, tmp_path: Path) -> None:
    queries = _answering(monkeypatch, None)
    payload = {"tool_input": {"command": "git status"}}

    assert (
        module._ask_review_hint(payload, guard_home=tmp_path, workspace=None, home_dir=None, budget_seconds=30) is None
    )

    query = queries[0]["query"]
    assert query == {"kind": "review_hint", "payload": payload, "workspace": "", "home_dir": "", "budget_ms": 10_000}
    assert queries[0]["operation"].timeout_seconds == 10.0

    module._ask_review_hint(
        payload, guard_home=tmp_path, workspace=tmp_path, home_dir=tmp_path, budget_seconds=0.5, paused={"a": 1}
    )
    assert queries[1]["query"]["paused"] == {"a": 1}
    assert queries[1]["query"]["workspace"] == str(tmp_path)
    assert queries[1]["query"]["budget_ms"] == 500


def test_a_spent_budget_never_reaches_the_resident(monkeypatch, tmp_path: Path) -> None:
    queries = _answering(monkeypatch, dict(_LIVE_ALLOW))

    for budget in (0.0, 0.0004, -1.0):
        assert (
            module._ask_review_hint({}, guard_home=tmp_path, workspace=None, home_dir=None, budget_seconds=budget)
            is None
        )
    assert queries == []


def test_an_answer_is_shape_checked_before_it_is_stored(monkeypatch, tmp_path: Path) -> None:
    carried = {**_LIVE_ALLOW, "coverage": _STORED_COVERAGE}
    _answering(monkeypatch, carried)
    hint = module._ask_review_hint({}, guard_home=tmp_path, workspace=None, home_dir=None, budget_seconds=1)
    assert validated_extension_allow_hint(hint) == validated_extension_allow_hint(_LIVE_ALLOW)
    assert validated_extension_coverage_hint(hint) == validated_extension_coverage_hint(_STORED_COVERAGE)

    _answering(monkeypatch, {"schema": "guard.extension-allow-hint.v1", "permission_ids": ["../../etc"]})
    assert module._ask_review_hint({}, guard_home=tmp_path, workspace=None, home_dir=None, budget_seconds=1) is None


def test_a_resident_failure_never_reaches_the_review(monkeypatch, tmp_path: Path) -> None:
    def unavailable(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("native_extension_review_hint_unavailable")

    monkeypatch.setattr(module, "_decide", unavailable)

    assert module._ask_review_hint({}, guard_home=tmp_path, workspace=None, home_dir=None, budget_seconds=1) is None


_STORED_COVERAGE: dict[str, object] = {
    "schema": "guard.extension-coverage-hint.v1",
    "catalog_digest": "a" * 64,
    "segments": [
        {
            "index": 0,
            "executable": "git",
            "extension_ids": ["command.git"],
            "rule_ids": ["command.git.unverified-fetch"],
            "permission_ids": [],
        }
    ],
}
_LIVE_ALLOW: dict[str, object] = {
    "schema": "guard.extension-allow-hint.v1",
    "permission_ids": ["command.git.permission.fetch"],
    "rule_ids": ["command.git.unverified-fetch"],
    "extension_ids": ["command.git"],
    "relied_permission_ids": [],
    "catalog_digest": "b" * 64,
}


def test_a_stored_coverage_only_hint_still_re_reviews_for_the_settlement(monkeypatch, tmp_path: Path) -> None:
    """Coverage in the stored column must not read as "the settlement was decided".

    A queue-time review that ran out of budget, missed the digest or found no
    all-or-nothing settlement still stores the coverage it read out of evidence
    it already had. Before coverage existed, that row stored nothing and the
    read path re-reviewed it; a row that now carries coverage has to be
    re-reviewed the same way or it silently loses its Always allow offer.
    """

    live_coverage = {**_STORED_COVERAGE, "catalog_digest": "c" * 64}
    monkeypatch.setattr(
        module,
        "live_approval_extension_hint",
        lambda *_args, **_kwargs: {**_LIVE_ALLOW, "coverage": live_coverage},
    )

    merged = module.recovered_approval_extension_hint(
        _STORED_COVERAGE, {"status": "pending"}, guard_home=tmp_path, snapshot=object()
    )

    assert validated_extension_allow_hint(merged) == validated_extension_allow_hint(_LIVE_ALLOW)
    # The queue-time coverage saw the directory the command really ran in.
    assert validated_extension_coverage_hint(merged) == validated_extension_coverage_hint(_STORED_COVERAGE)


def test_a_stored_settlement_and_a_connector_hint_are_left_alone(monkeypatch, tmp_path: Path) -> None:
    def refuse(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise AssertionError("a stored hint that answered the settlement must not be re-reviewed")

    monkeypatch.setattr(module, "live_approval_extension_hint", refuse)
    stored = {**_LIVE_ALLOW, "coverage": _STORED_COVERAGE}
    connector = {"schema": "guard.connector-setup-hint.v1", "cli_id": "local-cli.gh"}

    for hint in (stored, _LIVE_ALLOW, connector):
        assert (
            module.recovered_approval_extension_hint(
                hint, {"status": "pending"}, guard_home=tmp_path, snapshot=object()
            )
            is hint
        )


def test_a_row_with_nothing_stored_keeps_the_read_time_recovery(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(module, "live_approval_extension_hint", lambda *_args, **_kwargs: dict(_LIVE_ALLOW))
    assert (
        module.recovered_approval_extension_hint(None, {"status": "pending"}, guard_home=tmp_path, snapshot=object())
        == _LIVE_ALLOW
    )

    monkeypatch.setattr(module, "live_approval_extension_hint", lambda *_args, **_kwargs: None)
    assert (
        module.recovered_approval_extension_hint(None, {"status": "pending"}, guard_home=tmp_path, snapshot=object())
        is None
    )


def test_python_and_resident_command_only_keys_stay_identical() -> None:
    import re

    source = (
        Path(__file__).resolve().parents[1]
        / "rust"
        / "crates"
        / "guard-runtime"
        / "src"
        / "hook_direct_review_request.rs"
    ).read_text(encoding="utf-8")
    block = re.search(r"const COMMAND_ONLY_INPUT_KEYS: \[&str; \d+\] = \[(.*?)\];", source, re.DOTALL)
    assert block is not None
    assert set(re.findall(r'"([^"]+)"', block.group(1))) == set(module._COMMAND_ONLY_INPUT_KEYS)
