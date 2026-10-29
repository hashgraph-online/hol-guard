from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.daemon.hook_worker_native import HookWorkerNativeMixin
from codex_plugin_scanner.guard.mdm.contracts import MDM_POLICY_SCHEMA_VERSION, ManagedPolicyState
from codex_plugin_scanner.guard.mdm.policy import parse_managed_policy

STRUCTURED_OUTPUT_SETTING_PATH = "data_control.structured_output"


def _policy_value() -> dict[str, object]:
    return {
        "version": "hol-guard-structured-output-policy.v1",
        "enabled": True,
        "harnesses": ["pi", "omp"],
        "event": "PostToolUse",
        "destinationRole": "model_visible_tool_result",
        "schema": {
            "fields": [
                {
                    "path": ["employee", "email"],
                    "role": "protected_personal",
                    "valueType": "string",
                    "category": "email_address",
                },
                {"path": ["employee", "id"], "role": "ordinary", "valueType": "integer"},
                {"path": ["note"], "role": "ordinary", "valueType": "string"},
            ]
        },
        "onMatch": "withhold",
        "onUnsupported": "withhold",
    }


@dataclass
class _PolicyFixture:
    settings: dict[str, object]
    content_hash: str


@dataclass
class _ConfigFixture:
    managed_policy_status: str
    managed_policy_hash: str | None
    managed_locked_settings: tuple[str, ...]
    managed_policy: _PolicyFixture | None


def _config(*, status: str = "active", locked: tuple[str, ...] = (STRUCTURED_OUTPUT_SETTING_PATH,)) -> object:
    managed_policy = (
        _PolicyFixture(
            settings={"data_control": {"structured_output": _policy_value()}},
            content_hash="a" * 64,
        )
        if status != "absent"
        else None
    )
    return _ConfigFixture(
        managed_policy_status=status,
        managed_policy_hash=None if status == "absent" else "a" * 64,
        managed_locked_settings=locked,
        managed_policy=managed_policy,
    )


def _real_observe_managed_config(tmp_path: Path) -> object:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    (guard_home / "config.toml").write_text('mode = "observe"\ndefault_action = "allow"\n', encoding="utf-8")
    managed_payload = {
        "schemaVersion": MDM_POLICY_SCHEMA_VERSION,
        "settings": {"data_control": {"structured_output": _policy_value()}},
        "lockedSettings": [STRUCTURED_OUTPUT_SETTING_PATH],
        "update": {"owner": "mdm"},
    }
    managed_policy = parse_managed_policy(managed_payload)
    config = load_guard_config(
        guard_home,
        managed_policy_state=ManagedPolicyState("active", "machine-policy-fixture", policy=managed_policy),
    )
    assert config.mode == "observe"
    assert config.managed_policy_status == "active"
    assert config.managed_locked_settings == (STRUCTURED_OUTPUT_SETTING_PATH,)
    assert config.install_owner == "mdm"
    return config


def _native_result(**overrides: object) -> dict[str, object]:
    result: dict[str, object] = {
        "decision": "allow",
        "model_output_action": "allow_original",
        "policy_action": "allow",
        "observe_mode": False,
    }
    result.update(overrides)
    return result


def _receipt(**overrides: object) -> dict[str, object]:
    receipt: dict[str, object] = {"decision_id": "b" * 64, "decision": "allow"}
    receipt.update(overrides)
    return receipt


def _mediation(action: str, reason_code: str, **extra: object) -> dict[str, object]:
    """A disposition as the Rust edge answers it."""

    return {
        "schema": "guard-structured-content-mediation.v1",
        "action": action,
        "reason_code": reason_code,
        "native_decision_id": "b" * 64,
        **extra,
    }


FORWARD = _mediation("forward", "structured_clean_forward", content_sha256="c" * 64)
WITHHOLD = _mediation("withhold", "structured_content_unproved")


@dataclass
class _NativeRouteFixture(HookWorkerNativeMixin):
    """A daemon whose Rust edge answers with ``mediation`` already attached."""

    config: object
    mediation: dict[str, object] | None = None
    # What a second read of the config returns once the edge has answered.
    config_after_edge: object | None = None
    reload_error: Exception | None = None
    captured: list[dict[str, object]] = field(default_factory=list)
    reads: int = 0
    raw_result: object | None = None
    raw_receipt: object | None = None
    recorded_receipt: object | None = None
    answered: bool = False
    # No resident writer: the receipt stays with this fixture's own recorder.
    activity_writer: object | None = None

    def _load_config(self, _guard_home: Path, _workspace: Path | None) -> object:
        self.reads += 1
        if self.answered and self.reload_error is not None:
            raise self.reload_error
        return self.config_after_edge if self.answered and self.config_after_edge is not None else self.config

    def _edge_result(self) -> dict[str, object]:
        return _native_result()

    def _review_raw_hook_native(self, **kwargs: object) -> dict[str, object]:
        self.captured.append(kwargs)
        self.answered = True
        result = self._edge_result()
        receipt = _receipt(decision=result["decision"])
        self.raw_result = result
        self.raw_receipt = receipt
        response = dict(result)
        if self.mediation is not None and result["decision"] == "allow":
            response["structured_content_mediation"] = dict(self.mediation)
        return {
            "event_name": "PostToolUse",
            "harness": kwargs.get("harness", "pi"),
            "result": result,
            "receipt": receipt,
            "harness_response": response,
        }

    def _record_native_decision_receipt(self, receipt: object) -> object:
        self.recorded_receipt = receipt
        return receipt

    def _record_post_tool_activity(self, **_kwargs: object) -> None:
        return None


@dataclass
class _LoadErrorNativeRouteFixture(_NativeRouteFixture):
    def _load_config(self, _guard_home: Path, _workspace: Path | None) -> object:
        raise OSError("machine policy unavailable")


@dataclass
class _UnavailableNativeRouteFixture(_NativeRouteFixture):
    def _review_raw_hook_native(self, **_kwargs: object) -> None:
        return None


@dataclass
class _UnavailableLoadErrorNativeRouteFixture(_LoadErrorNativeRouteFixture):
    def _review_raw_hook_native(self, **_kwargs: object) -> None:
        return None


@dataclass
class _ObserveNativeRouteFixture(_NativeRouteFixture):
    def _edge_result(self) -> dict[str, object]:
        return _native_result(observe_mode=True)


@dataclass
class _DenyingNativeRouteFixture(_NativeRouteFixture):
    def _edge_result(self) -> dict[str, object]:
        return _native_result(
            decision="deny",
            model_output_action="block",
            policy_action="block",
            reason_code="native_secret_detected",
        )


def _review(
    fixture: _NativeRouteFixture,
    tmp_path: Path,
    *,
    harness: str = "pi",
    recording_only: bool = False,
    deadline: float | None = None,
) -> tuple[dict[str, object], bool]:
    return fixture._review_native_edge_with_snapshot(
        payload={
            "hook_event_name": "PostToolUse",
            "structured_output_json": '{"employee":{"email":"","id":7},"note":"x"}',
        },
        harness=harness,
        event_name="PostToolUse",
        default_harness=harness,
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard",
        workspace=tmp_path,
        deadline=deadline,
        policy_snapshot={"mode": "observe" if recording_only else "enforce"},
        recording_only=recording_only,
    )
