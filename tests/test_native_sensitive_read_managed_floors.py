"""Real managed floors must survive the supported sensitive Read path."""

from __future__ import annotations

import json
import sys
from contextlib import contextmanager
from pathlib import Path
from types import FrameType

import pytest

from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.mdm.contracts import ManagedPolicyState
from codex_plugin_scanner.guard.mdm.policy import parse_managed_policy
from codex_plugin_scanner.guard.models import GuardAction
from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY as REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_contract import ControlSurface
from codex_plugin_scanner.guard.runtime.extension_control_resolver import resolve_extension_controls
from codex_plugin_scanner.guard.runtime.extension_control_runtime import (
    ExtensionControlRuntimeSnapshot,
    use_extension_control_snapshot,
)
from tests import native_sensitive_read_policy_vectors as vectors
from tests.native_managed_source_support import managed_store
from tests.test_native_sensitive_read_sources import FIXTURE, produce_sensitive_read


def _source() -> dict[str, object]:
    source = json.loads(FIXTURE.read_text())["cases"][0]
    assert source["harness"] == "codex"
    return source


def _evaluated_action(result: dict[str, object]) -> object:
    expected = result["expected"]
    assert isinstance(expected, dict)
    return expected["evaluatedPolicyAction"]


@pytest.mark.parametrize("floor", ["default", "risk"])
def test_managed_sensitive_floor_cannot_be_masked_by_local_priority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    floor: str,
) -> None:
    source = _source()
    artifact = produce_sensitive_read(source)
    if floor == "default":
        local = "[artifacts]\n" + json.dumps(artifact.artifact_id) + ' = "allow"\n'
        settings: dict[str, object] = {"default_action": "block"}
    else:
        local = '[harness_risk_actions.codex]\nlocal_secret_read = "allow"\n'
        settings = {"risk_actions": {"local_secret_read": "block"}}
    (tmp_path / "config.toml").write_text(
        'mode = "enforce"\nsecurity_level = "balanced"\n'
        'default_action = "warn"\nunknown_publisher_action = "review"\n' + local
    )
    policy = parse_managed_policy(
        {
            "schemaVersion": "hol-guard-mdm-policy.v1",
            "settings": settings,
            "lockedSettings": list(settings),
        }
    )
    loaded = load_guard_config(
        tmp_path,
        managed_policy_state=ManagedPolicyState("active", "synthetic-fixture", policy=policy),
    )
    assert loaded.managed_policy is policy
    monkeypatch.setattr(vectors, "config_for", lambda *args, **kwargs: loaded)
    result = vectors.evaluate_case(source, vectors.Configuration(floor), "enforce", tmp_path)
    assert _evaluated_action(result) == "block"


@contextmanager
def _observe_control_calls():
    targets = {
        REGISTRY.observations.__func__.__code__: "registry",
        resolve_extension_controls.__code__: "resolver",
    }
    counts = {label: 0 for label in targets.values()}

    def observer(frame: FrameType, event: str, _arg: object) -> None:
        if event == "call" and frame.f_code in targets:
            counts[targets[frame.f_code]] += 1

    assert sys.getprofile() is None
    sys.setprofile(observer)
    try:
        yield counts
    finally:
        sys.setprofile(None)


@pytest.mark.parametrize("cloud,lockdown", [(False, False), (True, False), (True, True)])
def test_sensitive_read_observations_keep_unrelated_controls_separate_and_lockdown_hard(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cloud: bool,
    lockdown: bool,
) -> None:
    store = managed_store(tmp_path, monkeypatch, cloud=cloud, lockdown=lockdown)
    view = store.read_extension_control_authority_for_registry(REGISTRY)
    snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(view)
    assert snapshot.authority_failure is None
    assert any(layer.global_lockdown for layer in snapshot.layers) is lockdown
    with _observe_control_calls() as positive, use_extension_control_snapshot(snapshot):
        evaluate_command("git push --force origin main", cwd=tmp_path, home_dir=tmp_path)
    assert positive["registry"] > 0 and positive["resolver"] > 0

    def captured_producer(case: dict[str, object]):
        # This is the actual hook's source-capture interval. Evaluation follows it.
        with use_extension_control_snapshot(snapshot):
            return produce_sensitive_read(case)

    monkeypatch.setattr(vectors, "produce_sensitive_read", captured_producer)
    monkeypatch.setattr(vectors, "GuardStore", lambda _home: store)
    source = _source()
    cases: tuple[tuple[GuardAction | None, GuardAction], ...] = (
        (None, "require-reapproval"),
        ("allow", "allow"),
        ("block", "block"),
    )
    for risk, ordinary in cases:
        with _observe_control_calls() as observed:
            result = vectors.evaluate_case(
                source,
                vectors.Configuration("managed", risk_action=risk),
                "enforce",
                store.guard_home,
            )
        # Read has no shell command and must not invent a command extension match.
        assert observed["registry"] == 0
        if not lockdown:
            assert _evaluated_action(result) == ordinary
        else:
            direct = resolve_extension_controls(
                snapshot.layers,
                REGISTRY,
                extension_ids=(),
                permission_ids=(),
                surface=ControlSurface.COMMAND_EVALUATION,
                authority_failure=snapshot.authority_failure,
            )
            assert direct.blocked and not direct.failures
            assert _evaluated_action(result) == "block"


@pytest.mark.parametrize("lockdown", [False, True])
def test_sensitive_read_observe_finalizer_preserves_signed_lockdown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lockdown: bool,
) -> None:
    store = managed_store(tmp_path, monkeypatch, cloud=True, lockdown=lockdown)
    view = store.read_extension_control_authority_for_registry(REGISTRY)
    snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(view)
    assert snapshot.authority_failure is None
    assert any(layer.global_lockdown for layer in snapshot.layers) is lockdown

    def captured_producer(case: dict[str, object]):
        with use_extension_control_snapshot(snapshot):
            return produce_sensitive_read(case)

    monkeypatch.setattr(vectors, "produce_sensitive_read", captured_producer)
    monkeypatch.setattr(vectors, "GuardStore", lambda _home: store)
    result = vectors.evaluate_case(
        _source(),
        vectors.Configuration("managed-observe", risk_action="block"),
        "observe",
        store.guard_home,
    )
    expected = result["expected"]
    assert isinstance(expected, dict)
    # Both sources evaluate Block before the real Observe review/finalizer.
    # Only the unrelated-controls case may project that local restriction away.
    assert expected["evaluatedPolicyAction"] == "block"
    assert expected["evaluatedDecision"] == "block"
    assert expected["finalPolicyAction"] == ("block" if lockdown else "allow")
    assert expected["finalDecision"] == ("block" if lockdown else "allow")
    if not lockdown:
        assert expected["observedPolicyAction"] == "block"
        assert expected["rendererExitCode"] == 0
