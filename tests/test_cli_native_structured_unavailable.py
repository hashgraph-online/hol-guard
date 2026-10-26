"""CLI native-unavailable presentation for managed structured destinations."""

from __future__ import annotations

import io
import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import commands_hook_native_authority as authority
from codex_plugin_scanner.guard.daemon.hook_worker_native import HookWorkerNativeMixin
from codex_plugin_scanner.guard.runtime.structured_output_mediation import STRUCTURED_OUTPUT_SETTING_PATH
from codex_plugin_scanner.guard.store import GuardStore


def _structured_policy() -> tuple[dict[str, object], int]:
    return {
        "version": "hol-guard-structured-output-policy.v1",
        "enabled": True,
        "harnesses": ["pi", "omp"],
        "event": "PostToolUse",
        "destinationRole": "model_visible_tool_result",
        "schema": {"fields": [{"path": ["note"], "role": "ordinary", "valueType": "string"}]},
        "onMatch": "withhold",
        "onUnsupported": "withhold",
    }


@dataclass
class _Args:
    harness: str
    json: bool = True


@dataclass
class _ManagedPolicy:
    settings: dict[str, object]
    content_hash: str


@dataclass
class _Config:
    managed_policy_status: str
    managed_policy_hash: str | None
    managed_locked_settings: tuple[str, ...]
    managed_policy: _ManagedPolicy | None


def _managed_config() -> _Config:
    policy_hash = "a" * 64
    return _Config(
        managed_policy_status="active",
        managed_policy_hash=policy_hash,
        managed_locked_settings=(STRUCTURED_OUTPUT_SETTING_PATH,),
        managed_policy=_ManagedPolicy(
            settings={"data_control": {"structured_output": _structured_policy()}},
            content_hash=policy_hash,
        ),
    )


def _optional_config() -> _Config:
    return _Config(
        managed_policy_status="absent",
        managed_policy_hash=None,
        managed_locked_settings=(),
        managed_policy=None,
    )


@dataclass
class _OverlayWorker(HookWorkerNativeMixin):
    config: _Config

    def _load_config(self, _guard_home: Path, _workspace: Path | None) -> _Config:
        return self.config

    def review_http_payload(self, **_kwargs: object) -> dict[str, object]:
        raise RuntimeError("injected native failure")


def _emit_unavailable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    harness: str,
    event_name: str,
    config: _Config,
) -> tuple[dict[str, object], int]:
    monkeypatch.setattr(authority, "NativeHookEvidenceWriter", lambda **_kwargs: None)
    monkeypatch.setattr(authority, "HookWorker", lambda **_kwargs: _OverlayWorker(config))
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "workspace",
        guard_home=tmp_path / "guard-home",
    )
    output = io.StringIO()
    rc = authority.route_native_hook(
        _Args(harness=harness),  # type: ignore[arg-type]
        config=None,
        context=context,
        payload={"hook_event_name": event_name},
        runtime_workspace=context.workspace_dir,
        store=GuardStore(context.guard_home),
        output_stream=output,
    )
    response = json.loads(output.getvalue())
    assert isinstance(response, dict)
    return response, rc


@pytest.mark.parametrize("harness", ["pi", "omp"])
def test_cli_native_unavailable_withholds_managed_posttool_destination(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    harness: str,
) -> None:
    response, rc = _emit_unavailable(
        monkeypatch,
        tmp_path,
        harness=harness,
        event_name="PostToolUse",
        config=_managed_config(),
    )

    # PostToolUse unavailability is an allow envelope; rc mirrors verdict -> 0.
    assert rc == 0
    assert response["decision"] == "allow"
    assert response["policy_action"] == "allow"
    assert response["reason_code"] == "native_hook_worker_exception"
    assert response["structured_content_mediation"] == {
        "schema": "guard-structured-content-mediation.v1",
        "action": "withhold",
        "reason_code": "structured_native_edge_unavailable",
    }
    assert "receipt" not in response
    assert "native_decision_id" not in response["structured_content_mediation"]


@pytest.mark.parametrize("harness", ["pi", "omp"])
def test_cli_worker_construction_failure_withholds_posttool_destination(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    harness: str,
) -> None:
    def broken_worker(**_kwargs: object) -> None:
        raise RuntimeError("injected worker construction failure")

    monkeypatch.setattr(authority, "NativeHookEvidenceWriter", lambda **_kwargs: None)
    monkeypatch.setattr(authority, "HookWorker", broken_worker)
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "workspace",
        guard_home=tmp_path / "guard-home",
    )
    output = io.StringIO()
    rc = authority.route_native_hook(
        _Args(harness=harness),  # type: ignore[arg-type]
        config=None,
        context=context,
        payload={"hook_event_name": "PostToolUse"},
        runtime_workspace=context.workspace_dir,
        store=GuardStore(context.guard_home),
        output_stream=output,
    )
    response = json.loads(output.getvalue())

    assert rc == 0
    assert response["reason_code"] == "native_hook_worker_exception"
    assert response["structured_content_mediation"] == {
        "schema": "guard-structured-content-mediation.v1",
        "action": "withhold",
        "reason_code": "structured_native_edge_unavailable",
    }


@pytest.mark.parametrize("harness", ["pi", "omp"])
def test_cli_native_unavailable_keeps_optional_structured_destination_off(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    harness: str,
) -> None:
    response, rc = _emit_unavailable(
        monkeypatch,
        tmp_path,
        harness=harness,
        event_name="PostToolUse",
        config=_optional_config(),
    )

    assert rc == 0
    assert response["decision"] == "allow"
    assert response["policy_action"] == "allow"
    assert response["reason_code"] == "native_hook_worker_exception"
    assert "structured_content_mediation" not in response


def test_cli_native_unavailable_blocks_the_prompt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    response, rc = _emit_unavailable(
        monkeypatch,
        tmp_path,
        harness="pi",
        event_name="UserPromptSubmit",
        config=_optional_config(),
    )

    # pi/omp are envelope-driven: a preemptive (UserPromptSubmit) block rides
    # the decision envelope and exits 0 — nonzero rc reads as a hook error.
    # Gauntlet-verified: omp deny arrives as decision==deny while host exits 0.
    assert rc == 0
    assert response["decision"] == "block"
    assert response["reason_code"] == "native_prompt_unavailable"
