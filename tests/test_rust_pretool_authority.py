"""Tests for Rust PreToolUse authority transport and daemon fail-closed behavior."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard import native_pretool as pretool
from codex_plugin_scanner.guard import native_route_receipt as routes
from codex_plugin_scanner.guard import native_runtime as runtime
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.native_hook_decision import NativeHookDecisionError
from codex_plugin_scanner.guard.store import GuardStore


def _native_allow(command: str) -> dict[str, Any]:
    return {
        "authority": "rust",
        "decision": "allow",
        "minimum_action": "allow",
        "policy_action": "allow",
        "reason_code": "native_exact_safe_command",
        "reason": "The Rust command authority proved this bounded command explicitly benign.",
        "explicitly_benign": True,
        "command_model": {"normalized_text": command},
    }


def _native_block(command: str) -> dict[str, Any]:
    return {
        "authority": "rust",
        "decision": "deny",
        "minimum_action": "block",
        "policy_action": "block",
        "reason_code": "native_destructive_command",
        "reason": "HOL Guard blocked a destructive command before execution.",
        "explicitly_benign": False,
        "command_model": {"normalized_text": command},
    }


def test_decode_pre_tool_rejects_unbound_command_model() -> None:
    payload = _native_allow("pwd")
    payload["command_model"] = {"normalized_text": "whoami"}
    assert pretool._decode_pre_tool(payload, command="pwd") is None


def test_unavailable_native_pretool_records_fail_safe_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_pretool.native_runtime_status",
        lambda: runtime.NativeRuntimeStatus(
            mode="force",
            available=False,
            compatible=False,
            reason="missing",
        ),
    )
    routes.reset_native_hook_route()

    assert (
        pretool.review_pre_tool_native(
            "pwd",
            guard_home=tmp_path,
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is None
    )
    assert routes.native_hook_route() == "native_fail_safe"


def test_missing_pretool_feature_records_fail_safe_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime_path = tmp_path / "hol-guard-runtime"
    runtime_path.write_bytes(b"runtime")
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_pretool.native_runtime_status",
        lambda: runtime.NativeRuntimeStatus(
            mode="auto",
            available=True,
            compatible=True,
            reason="ready",
            identity=runtime.NativeRuntimeIdentity(
                path=runtime_path,
                size=runtime_path.stat().st_size,
                mtime_ns=runtime_path.stat().st_mtime_ns,
                sha256="0" * 64,
            ),
            capabilities=runtime.NativeRuntimeCapabilities(
                protocol_version=2,
                runtime_version="test",
                rule_digest="1" * 64,
                build_sha="2" * 40,
                target="test",
                features=("resident-protocol-v2",),
            ),
        ),
    )
    routes.reset_native_hook_route()

    assert (
        pretool.review_pre_tool_native(
            "pwd",
            guard_home=tmp_path,
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        is None
    )
    assert routes.native_hook_route() == "native_fail_safe"


def test_policy_floor_asks_the_resident_with_the_whole_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    review = _native_block("rm -rf /")
    reviewed: list[dict[str, Any]] = []
    floored: list[tuple[dict[str, Any], Path | None]] = []

    def review_pre_tool_native(*_args: object, **kwargs: Any) -> dict[str, Any]:
        reviewed.append(kwargs)
        return review

    def native_pretool_floor(answer: dict[str, Any], *, guard_home: Path | None) -> str:
        floored.append((answer, guard_home))
        return "block"

    monkeypatch.setattr("codex_plugin_scanner.guard.native_pretool.review_pre_tool_native", review_pre_tool_native)
    monkeypatch.setattr("codex_plugin_scanner.guard.native_pretool.native_pretool_floor", native_pretool_floor)
    assert (
        pretool.native_pre_tool_policy_floor(
            "rm -rf /",
            guard_home=tmp_path,
            cwd=tmp_path,
            home_dir=tmp_path,
        )
        == "block"
    )
    # The floor path admits every canonical action, so a contained or
    # reapproval answer reaches the resident instead of collapsing to a block.
    assert [call["full_lattice"] for call in reviewed] == [True]
    assert floored == [(review, tmp_path)]


def test_policy_floor_without_a_review_is_the_host_outage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # This used to return ``block``, a floor Python picked. No review is a
    # resident outage, which the hook answers with the host outage response.
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_pretool.review_pre_tool_native",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_pretool.native_runtime_status",
        lambda: runtime.NativeRuntimeStatus(
            mode="force",
            available=False,
            compatible=False,
            reason="missing",
        ),
    )
    with pytest.raises(NativeHookDecisionError) as raised:
        pretool.native_pre_tool_policy_floor(
            "pwd",
            guard_home=tmp_path,
            cwd=tmp_path,
            home_dir=tmp_path,
        )
    assert raised.value.code == "native_pre_tool_floor_unavailable"


def test_hook_worker_fails_closed_when_forced_native_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_runtime_status",
        lambda: runtime.NativeRuntimeStatus(
            mode="force",
            available=False,
            compatible=False,
            reason="missing",
        ),
    )
    worker = HookWorker(store=GuardStore(tmp_path / "guard-home"))
    result = worker.review_http_payload(
        payload={"hook_event_name": "PreToolUse", "tool_input": {"command": "git push"}},
        params={},
        default_harness="pi",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )
    assert result["decision"] == "deny"


def test_hook_worker_fails_closed_when_auto_pretool_native_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.native_runtime_status",
        lambda: runtime.NativeRuntimeStatus(
            mode="auto",
            available=False,
            compatible=False,
            reason="missing",
        ),
    )
    worker = HookWorker(store=GuardStore(tmp_path / "guard-home"))
    result = worker.review_http_payload(
        payload={"hook_event_name": "PreToolUse", "tool_input": {"command": "git push"}},
        params={},
        default_harness="pi",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )
    assert result["decision"] == "deny"


def test_hook_worker_denies_unreviewed_non_command_pretool_without_native_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native",
        lambda *_args, **_kwargs: None,
    )
    worker = HookWorker(store=GuardStore(tmp_path / "guard-home"))
    result = worker.review_http_payload(
        payload={"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": "src/foo.ts"}},
        params={},
        default_harness="pi",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )
    assert result["decision"] == "deny"


def test_hook_worker_leaves_out_of_scope_events_to_existing_handling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.daemon.hook_worker.review_raw_hook_native",
        lambda *_args, **_kwargs: None,
    )
    worker = HookWorker(store=GuardStore(tmp_path / "guard-home"))
    result = worker.review_http_payload(
        # Claude, Codex, Copilot, Devin and ZCode permission dialogs have
        # their own passthrough routes; other harnesses' permission events
        # still reach the native fail-safe.
        payload={"hook_event_name": "PermissionRequest", "tool_input": {"command": "pwd"}},
        params={},
        default_harness="kimi",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
    )
    assert (
        result["reason_code"] == "native_hook_event_unavailable"
        and result["hookSpecificOutput"]["decision"]["behavior"] == "deny"
    )


def _status(
    tmp_path: Path,
    features: tuple[str, ...],
) -> runtime.NativeRuntimeStatus:
    runtime_path = tmp_path / "hol-guard-runtime"
    runtime_path.write_bytes(b"runtime")
    return runtime.NativeRuntimeStatus(
        mode="auto",
        available=True,
        compatible=True,
        reason="ready",
        identity=runtime.NativeRuntimeIdentity(
            path=runtime_path,
            size=runtime_path.stat().st_size,
            mtime_ns=runtime_path.stat().st_mtime_ns,
            sha256="0" * 64,
        ),
        capabilities=runtime.NativeRuntimeCapabilities(
            protocol_version=2,
            runtime_version="test",
            rule_digest="1" * 64,
            build_sha="2" * 40,
            target="test",
            features=features,
        ),
    )


def _sent_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    features: tuple[str, ...],
    execution_environment: dict[str, Any] | None = None,
    **review_kwargs: Any,
) -> dict[str, Any]:
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_pretool.native_runtime_status",
        lambda: _status(tmp_path, features),
    )
    sent: dict[str, Any] = {}

    class SentError(Exception):
        """Stops the review once the request has been read."""

    def capture(**kwargs: Any) -> bytes | None:
        sent.update(json.loads(kwargs["payload"]))
        raise SentError

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.native_pretool.native_resident_client_request",
        capture,
    )
    routes.reset_native_hook_route()
    with pytest.raises(SentError):
        pretool.review_pre_tool_native(
            "rg -n fixture ../service-api",
            guard_home=tmp_path,
            cwd=tmp_path / "app-portal",
            home_dir=tmp_path,
            execution_environment=execution_environment,
            **review_kwargs,
        )
    return sent


_EVIDENCE_FEATURES = (
    "pre-tool-command-authority-v1",
    "resident-protocol-v2",
    "pre-tool-extension-evidence-v1",
)


def test_a_caller_that_resolves_extensions_asks_for_their_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent = _sent_request(tmp_path, monkeypatch, _EVIDENCE_FEATURES, extension_evidence=True)
    assert sent["request"]["extension_evidence"] is True


def test_the_enforcing_review_never_asks_for_extension_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent = _sent_request(tmp_path, monkeypatch, _EVIDENCE_FEATURES)
    assert "extension_evidence" not in sent["request"]


def test_an_older_runtime_is_never_sent_the_evidence_field(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent = _sent_request(tmp_path, monkeypatch, _EVIDENCE_FEATURES[:2], extension_evidence=True)
    assert "extension_evidence" not in sent["request"]


def test_pre_tool_request_carries_the_directories_the_command_runs_in(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent = _sent_request(
        tmp_path,
        monkeypatch,
        ("pre-tool-command-authority-v1", "resident-protocol-v2", "pre-tool-path-context-v1"),
    )
    assert sent["request"]["cwd"] == str(tmp_path / "app-portal")
    assert sent["request"]["home_dir"] == str(tmp_path)


def test_the_request_carries_the_shell_the_command_will_run_in(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The runtime cannot read the agent's shell, so the hook says what it is.

    A resident daemon is started with its own sanitized environment, so the
    variables it can read are not the ones the command inherits. Every rule
    that proves an inherited variable away — a ``RIPGREP_CONFIG_PATH`` that
    prepends options to ``rg``, an npm or rustup variable that moves what a
    tool loads — is answered from this stamp or not at all.
    """

    stamp = {"path": "/usr/bin:/bin", "environment_names": ["PATH"], "environment_digest": "0" * 64}
    sent = _sent_request(
        tmp_path,
        monkeypatch,
        (
            "pre-tool-command-authority-v1",
            "resident-protocol-v2",
            "pre-tool-path-context-v1",
            "pre-tool-execution-environment-v1",
        ),
        execution_environment=stamp,
    )
    assert sent["request"]["execution_environment"] == stamp


def test_a_caller_that_cannot_name_the_shell_sends_no_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unstamped request leaves the environment proofs unproven.

    The alternative is worse than a review: the runtime would answer them
    from its own variables, and a shell that exports a search config would
    have the command admitted because the daemon exports none.
    """

    sent = _sent_request(
        tmp_path,
        monkeypatch,
        (
            "pre-tool-command-authority-v1",
            "resident-protocol-v2",
            "pre-tool-path-context-v1",
            "pre-tool-execution-environment-v1",
        ),
    )
    assert "execution_environment" not in sent["request"]


def test_a_runtime_without_the_feature_is_asked_the_question_it_understands(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent = _sent_request(
        tmp_path,
        monkeypatch,
        ("pre-tool-command-authority-v1", "resident-protocol-v2"),
    )
    assert "cwd" not in sent["request"]
    assert "home_dir" not in sent["request"]
