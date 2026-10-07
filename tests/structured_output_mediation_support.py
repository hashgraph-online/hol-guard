from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.daemon.hook_worker_native import HookWorkerNativeMixin
from codex_plugin_scanner.guard.mdm.contracts import MDM_POLICY_SCHEMA_VERSION, ManagedPolicyState
from codex_plugin_scanner.guard.mdm.policy import parse_managed_policy
from codex_plugin_scanner.guard.runtime.structured_output_mediation import (
    STRUCTURED_OUTPUT_SETTING_PATH,
    StructuredOutputBinding,
    resolve_managed_structured_output_binding,
)


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


def _binding(harness: str = "pi") -> StructuredOutputBinding:
    binding = resolve_managed_structured_output_binding(_config(), harness=harness)
    assert binding is not None
    return binding


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


@dataclass
class _NativeRouteFixture(HookWorkerNativeMixin):
    config: object
    raw_result: object | None = None
    raw_receipt: object | None = None
    recorded_receipt: object | None = None

    def _load_config(self, _guard_home: Path, _workspace: Path | None) -> object:
        return self.config

    def _review_raw_hook_native(self, **_kwargs: object) -> dict[str, object]:
        result = _native_result()
        receipt = _receipt()
        self.raw_result = result
        self.raw_receipt = receipt
        return {
            "event_name": "PostToolUse",
            "harness": "pi",
            "result": result,
            "receipt": receipt,
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
class _ObserveNativeRouteFixture(_NativeRouteFixture):
    def _review_raw_hook_native(self, **_kwargs: object) -> dict[str, object]:
        result = _native_result(observe_mode=True)
        receipt = _receipt()
        self.raw_result = result
        self.raw_receipt = receipt
        return {
            "event_name": "PostToolUse",
            "harness": "pi",
            "result": result,
            "receipt": receipt,
        }
