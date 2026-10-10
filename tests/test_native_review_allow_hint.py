"""Native daemon reviews store an Extensions allow hint only when enabling it would really allow."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.daemon.native_review_allow_hint import hint_for_reviewed_command
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_allow_hint import validated_extension_allow_hint
from tests.native_command_test_support import project_native_review_fixture, real_native_review_fixture


def _hint(command: str, tmp_path: Path, *, controls=(), native_result_override: dict[str, object] | None = None):
    fixture = real_native_review_fixture(command, cwd=tmp_path, home_dir=tmp_path, controls=controls)
    reviewed = project_native_review_fixture(fixture, cwd=tmp_path, home_dir=tmp_path)
    native_result = {**fixture.payload, **(native_result_override or {})}
    return fixture, hint_for_reviewed_command(
        native_result=native_result,
        reviewed=reviewed,
        snapshot=fixture.snapshot,
        command=command,
        cwd=tmp_path,
        home_dir=tmp_path,
    )


def test_plain_origin_fetch_hints_the_origin_refresh_permission(tmp_path: Path) -> None:
    _fixture, hint = _hint("git fetch origin main", tmp_path)

    assert hint is not None
    assert hint["permission_ids"] == ["command.git.permission.unverified-fetch"]
    assert hint["rule_ids"] == ["command.git.unverified-fetch"]
    assert hint["catalog_digest"] == BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest
    assert validated_extension_allow_hint(hint) == hint
    assert "main" not in repr(hint)


def test_uncertain_fetch_forms_store_no_hint(tmp_path: Path) -> None:
    for command in (
        "git -c core.sshCommand=payload fetch origin",
        "git fetch origin --upload-pack=payload",
        "git fetch https://example.invalid/project.git",
    ):
        _fixture, hint = _hint(command, tmp_path)
        assert hint is None, command


def test_no_hint_when_the_origin_refresh_permission_is_already_allowed(tmp_path: Path) -> None:
    _fixture, hint = _hint(
        "git fetch origin",
        tmp_path,
        controls=(("permission", "command.git.permission.unverified-fetch", "enabled"),),
    )

    assert hint is None


def test_hint_requires_the_fresh_evidence_to_match_the_paused_decision(tmp_path: Path) -> None:
    fixture, _hint_value = _hint("git fetch origin", tmp_path)
    binding = dict(fixture.payload["command_extensions"]["binding"])  # type: ignore[index]
    binding["observations_digest"] = "0" * 64

    _fixture, hint = _hint(
        "git fetch origin",
        tmp_path,
        native_result_override={"command_extensions": {**fixture.payload["command_extensions"], "binding": binding}},  # type: ignore[dict-item]
    )

    assert hint is None


def test_no_hint_for_a_blocked_native_decision(tmp_path: Path) -> None:
    _fixture, hint = _hint("git fetch origin", tmp_path, native_result_override={"minimum_action": "block"})

    assert hint is None


def test_no_hint_when_the_paused_reason_differs(tmp_path: Path) -> None:
    _fixture, hint = _hint("git fetch origin", tmp_path, native_result_override={"reason_code": "native_other_floor"})

    assert hint is None


class _Store:
    def __init__(self, guard_home: Path) -> None:
        self.guard_home = guard_home

    def read_extension_control_authority_for_registry(self, _registry, *, read_only: bool) -> object:
        assert read_only is True
        return object()


def _queue_hint(monkeypatch, tmp_path: Path, *, tool_input: dict[str, object], deadline: float | None = None):
    import time

    from codex_plugin_scanner.guard.daemon import native_review_allow_hint as module
    from codex_plugin_scanner.guard.native_route_receipt import native_hook_route, record_native_hook_route

    fixture = real_native_review_fixture("git fetch origin main", cwd=tmp_path, home_dir=tmp_path)
    reviewed = project_native_review_fixture(fixture, cwd=tmp_path, home_dir=tmp_path)
    calls: list[dict[str, object]] = []

    def review(_command: str, **kwargs: object):
        calls.append(kwargs)
        record_native_hook_route("native_fail_safe")
        return reviewed

    monkeypatch.setattr(module, "review_command_native", review)
    monkeypatch.setattr(
        module.ExtensionControlRuntimeSnapshot, "from_authority_view", staticmethod(lambda _view: fixture.snapshot)
    )
    record_native_hook_route("native_resident")
    hint = module.native_review_extension_allow_hint(
        _Store(tmp_path),
        payload={"tool_name": "Bash", "tool_input": tool_input},
        native_result=fixture.payload,
        workspace=tmp_path,
        home_dir=tmp_path,
        deadline=time.monotonic() + 5 if deadline is None else deadline,
    )
    return hint, calls, native_hook_route()


def test_queue_hint_is_advisory_and_keeps_the_hook_route(monkeypatch, tmp_path: Path) -> None:
    hint, calls, route = _queue_hint(monkeypatch, tmp_path, tool_input={"command": "git fetch origin main"})

    assert hint is not None
    assert hint["permission_ids"] == ["command.git.permission.unverified-fetch"]
    assert route == "native_resident"
    assert calls[0]["record_health"] is False
    assert 0 < float(calls[0]["timeout_seconds"]) <= 0.5  # type: ignore[arg-type]


def test_queue_hint_skips_tool_calls_with_extra_content(monkeypatch, tmp_path: Path) -> None:
    hint, calls, _route = _queue_hint(
        monkeypatch, tmp_path, tool_input={"command": "git fetch origin main", "path": ".env"}
    )

    assert hint is None
    assert calls == []


def test_queue_hint_skips_when_the_hook_deadline_is_near(monkeypatch, tmp_path: Path) -> None:
    import time

    hint, calls, _route = _queue_hint(
        monkeypatch, tmp_path, tool_input={"command": "git fetch origin main"}, deadline=time.monotonic() + 0.3
    )

    assert hint is None
    assert calls == []
