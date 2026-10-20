"""Guard-clause coverage for native hook evaluation helpers."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.cli import commands_hook_native_eval as eval_module
from codex_plugin_scanner.guard.cli.commands_hook_native_edge_facts import _native_edge_facts
from codex_plugin_scanner.guard.cli.commands_hook_native_eval import (
    _runtime_external_archive_has_digest_binding_sink,
)
from codex_plugin_scanner.guard.cli.commands_hook_native_generic import _observed_action_detail
from codex_plugin_scanner.guard.native_shim_admin import NativeShimAdminError


def test_native_edge_facts_forward_the_edge_verdict_without_deciding() -> None:
    assert _native_edge_facts(None, "PostToolUse") is None
    edge = {"decision": "deny", "policy_action": "block", "reason_code": "native_secret_exfiltration", "extra": 1}
    assert _native_edge_facts(edge, "PreToolUse", artifact_type="package_request") == {
        "event_name": "PreToolUse",
        "policy_action": "block",
        "minimum_action": None,
        "decision": "deny",
        "reason_code": "native_secret_exfiltration",
        "package_request": True,
    }
    assert _native_edge_facts({}, "PostToolUse", artifact_type="command")["package_request"] is False


def test_digest_binding_sink_never_asks_without_package_metadata(tmp_path) -> None:
    """Without a manager and an executable there is nothing for a shim to own."""

    def refuse(*args: object, **fields: object) -> bool:
        raise AssertionError("asked the resident about an artifact that names no shim")

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(eval_module, "package_shim_digest_binding_sink", refuse)
        for metadata in (None, {"package_manager": "uv"}, {"package_executable": "/usr/bin/uv"}):
            assert (
                _runtime_external_archive_has_digest_binding_sink(
                    artifact=SimpleNamespace(metadata=metadata),
                    context=SimpleNamespace(),
                    raw_command="tar xf a.tgz",
                    runtime_workspace=tmp_path,
                )
                is False
            )


def test_digest_binding_sink_forwards_the_facts_and_returns_the_resident_answer(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The parse and the path resolution are the resident's; this forwards them."""

    asked: list[dict[str, object]] = []

    def record(context: object, **fields: object) -> bool:
        asked.append(dict(fields))
        return True

    monkeypatch.setattr(eval_module, "package_shim_digest_binding_sink", record)
    artifact = SimpleNamespace(metadata={"package_manager": "uv", "package_executable": "/usr/bin/uv"})
    assert (
        _runtime_external_archive_has_digest_binding_sink(
            artifact=artifact,
            context=SimpleNamespace(),
            raw_command="/usr/bin/uv run tool",
            runtime_workspace=tmp_path,
        )
        is True
    )
    assert asked == [
        {
            "manager": "uv",
            "executable": "/usr/bin/uv",
            "command": "/usr/bin/uv run tool",
            "workspace_dir": tmp_path,
            "path_env": asked[0]["path_env"],
        }
    ]


def test_digest_binding_sink_treats_an_unreachable_resident_as_no_sink(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No binding sink leaves the approval with the user, not with the shim."""

    def unavailable(context: object, **fields: object) -> bool:
        raise NativeShimAdminError("native_shim_admin_unavailable")

    monkeypatch.setattr(eval_module, "package_shim_digest_binding_sink", unavailable)
    assert (
        _runtime_external_archive_has_digest_binding_sink(
            artifact=SimpleNamespace(metadata={"package_manager": "uv", "package_executable": "/usr/bin/uv"}),
            context=SimpleNamespace(),
            raw_command="/usr/bin/uv run tool",
            runtime_workspace=tmp_path,
        )
        is False
    )


def test_observed_action_detail_falls_back_to_envelope_composition(tmp_path) -> None:
    assert _observed_action_detail(None, action_envelope=None, home_dir=tmp_path) is None
    envelope = SimpleNamespace(tool_name=None, target_paths=())
    assert _observed_action_detail(None, action_envelope=envelope, home_dir=tmp_path) is None
    envelope = SimpleNamespace(tool_name="Read", target_paths=("/etc/hosts",))
    detail = _observed_action_detail(None, action_envelope=envelope, home_dir=tmp_path)
    assert isinstance(detail, str) and "Read" in detail
