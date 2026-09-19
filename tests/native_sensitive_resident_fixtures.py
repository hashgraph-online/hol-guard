"""Loaded synthetic MDM sources and verified source-built native auto discovery.

The fixture selects an explicit MDM test file. Machine ownership, installed
artifacts, real enrollment and production capability advertisement are not tested.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import config as config_module
from codex_plugin_scanner.guard.config import GuardConfig, load_guard_config
from codex_plugin_scanner.guard.mdm.policy import load_managed_policy
from codex_plugin_scanner.guard.native_managed_configuration import MANAGED_CONFIGURATION_FEATURE
from codex_plugin_scanner.guard.native_policy_authority_contract import NATIVE_MANAGED_AUTHORITY_FEATURE
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_scoped import SCOPED_PUBLISH_FEATURES
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeStatus, native_runtime_status
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_scoped_resident_fixtures import prepare_store
from tests.test_native_sensitive_read_sources import produce_sensitive_read


@dataclass(frozen=True)
class OriginCase:
    name: str
    local: str
    managed: dict[str, object]
    mode: str
    expected: str
    observed: str | None = None


@dataclass(frozen=True)
class SensitiveSource:
    store: GuardStore
    workspace: Path
    home: Path
    managed_path: Path
    artifact_id: str

    def payload(self) -> dict[str, object]:
        return {"tool_name": "Read", "tool_input": {"file_path": str(self.workspace / ".npmrc")}}

    def select(self, case: OriginCase) -> GuardConfig:
        self.managed_path.write_text(
            json.dumps(
                {
                    "schemaVersion": "hol-guard-mdm-policy.v1",
                    "settings": case.managed,
                    "lockedSettings": list(case.managed),
                }
            ),
            encoding="utf-8",
        )
        (self.store.guard_home / "config.toml").write_text(
            f'mode="{case.mode}"\nsecurity_level="balanced"\nunknown_publisher_action="review"\n' + case.local,
            encoding="utf-8",
        )
        loaded = load_guard_config(self.store.guard_home, workspace=self.workspace)
        assert loaded.managed_policy_status == "active" and loaded.managed_policy is not None
        assert loaded.local_policy_origin is not None
        assert dict(loaded.managed_policy.settings) == case.managed
        return loaded


def sensitive_source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SensitiveSource:
    store, workspace = prepare_store(tmp_path)
    managed_path = tmp_path / "synthetic-managed-policy.json"
    # Only the source path is selected by the fixture; the real file reader,
    # parser, config loader, origin composition and publisher remain in use.
    monkeypatch.setattr(
        config_module,
        "load_managed_policy",
        lambda: load_managed_policy(policy_path=managed_path, write_cache=False),
    )
    source: dict[str, object] = {
        "harness": "codex",
        "source": {"home_dir": str(tmp_path), "cwd": str(workspace), "guard_home": str(store.guard_home)},
        "payload": {"tool_name": "Read", "tool_input": {"file_path": str(workspace / ".npmrc")}},
    }
    artifact = produce_sensitive_read(source)
    assert artifact.metadata["path_class"] == "npm registry credentials"
    return SensitiveSource(store, workspace, tmp_path, managed_path, artifact.artifact_id)


def origin_cases(artifact_id: str) -> tuple[OriginCase, ...]:
    artifact_allow = f'[artifacts]\n{json.dumps(artifact_id)}="allow"\n'
    risk_allow = '[risk_actions]\nlocal_secret_read="allow"\n'
    return (
        OriginCase(
            "managed-default-local-artifact",
            'default_action="allow"\n' + artifact_allow + risk_allow,
            {"default_action": "block"},
            "enforce",
            "block",
        ),
        OriginCase(
            "managed-risk-local-harness-risk",
            'default_action="allow"\n[harness_risk_actions.codex]\nlocal_secret_read="allow"\n',
            {"risk_actions": {"local_secret_read": "block"}},
            "enforce",
            "block",
        ),
        OriginCase(
            "local-default-managed-harness",
            'default_action="block"\n' + risk_allow,
            {"harnesses": {"codex": "allow"}},
            "enforce",
            "block",
        ),
        OriginCase(
            "local-risk-managed-harness-risk",
            'default_action="allow"\n[risk_actions]\nlocal_secret_read="block"\n',
            {"harness_risk_actions": {"codex": {"local_secret_read": "allow"}}},
            "enforce",
            "block",
        ),
        OriginCase(
            "managed-selector-precedence",
            'default_action="allow"\n' + risk_allow,
            {"default_action": "block", "artifacts": {artifact_id: "allow"}},
            "enforce",
            "allow",
        ),
        OriginCase(
            "managed-risk-default-absent",
            'default_action="warn"\n' + risk_allow,
            {"risk_actions": {"local_secret_read": "block"}},
            "observe",
            "allow",
            "block",
        ),
        OriginCase(
            "managed-risk-default-explicit",
            'default_action="warn"\n' + risk_allow,
            {"default_action": "allow", "risk_actions": {"local_secret_read": "block"}},
            "observe",
            "warn",
            "block",
        ),
    )


def sensitive_test_status() -> NativeRuntimeStatus:
    """Require actual auto selection; negotiate only the staged contract names."""
    assert os.environ.get("HOL_GUARD_NATIVE") == "auto"
    selected = os.environ.get("HOL_GUARD_NATIVE_BINARY")
    assert selected, "an exact independently built runtime is required"
    status = native_runtime_status()
    assert status.mode == "auto" and status.available and status.compatible, status.reason
    assert status.identity is not None and status.capabilities is not None
    root = Path(__file__).resolve().parents[1]
    bundled = root / "src/codex_plugin_scanner/_native/hol-guard-runtime"
    assert status.identity.path.resolve() == bundled.resolve()
    assert status.identity.sha256 == hashlib.sha256(Path(selected).read_bytes()).hexdigest()
    assert status.identity.sha256 == hashlib.sha256(bundled.read_bytes()).hexdigest()
    assert (
        status.capabilities.build_sha
        == subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    )
    return replace(
        status,
        capabilities=replace(
            status.capabilities,
            features=tuple(
                sorted(
                    {
                        *status.capabilities.features,
                        *SCOPED_PUBLISH_FEATURES,
                        MANAGED_CONFIGURATION_FEATURE,
                        NATIVE_MANAGED_AUTHORITY_FEATURE,
                    }
                )
            ),
        ),
    )
