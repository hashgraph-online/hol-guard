"""A managed exception cannot erase the independently loaded local policy."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import overlay_synced_guard_policy, resolve_risk_action
from tests import native_sensitive_read_policy_vectors as vectors
from tests.test_managed_action_origin import loaded
from tests.test_native_sensitive_read_managed_floors import _evaluated_action, _source


@pytest.mark.parametrize("origin", ["default", "risk"])
def test_loaded_local_block_survives_managed_specific_allow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, origin: str
) -> None:
    if origin == "default":
        local = 'default_action="block"\n'
        settings: dict[str, object] = {"harnesses": {"codex": "allow"}}
    else:
        local = '[risk_actions]\nlocal_secret_read="block"\n'
        settings = {"harness_risk_actions": {"codex": {"local_secret_read": "allow"}}}
    # The helper already writes a default, so default replacement is explicit.
    config = loaded(tmp_path, local if origin != "default" else "", settings)
    if origin == "default":
        path = tmp_path / "config.toml"
        path.write_text(path.read_text().replace('default_action="allow"', 'default_action="block"'))
        from codex_plugin_scanner.guard.config import load_guard_config
        from codex_plugin_scanner.guard.mdm.contracts import ManagedPolicyState

        config = load_guard_config(
            tmp_path, managed_policy_state=ManagedPolicyState("active", "test", policy=config.managed_policy)
        )
    monkeypatch.setattr(vectors, "config_for", lambda *args, **kwargs: config)
    result = vectors.evaluate_case(_source(), vectors.Configuration(origin), "enforce", tmp_path)
    assert _evaluated_action(result) == "block"


@pytest.mark.parametrize(
    ("local", "settings", "kind", "expected"),
    [
        ('[harnesses]\ncodex="block"\n', {"artifacts": {"target": "allow"}}, "selector", "block"),
        ('[publishers]\nvendor="block"\n', {"artifacts": {"target": "allow"}}, "selector", "block"),
        ('[artifacts]\ntarget="allow"\n', {"default_action": "block"}, "selector", "block"),
        (
            '[risk_actions]\nlocal_secret_read="block"\n',
            {"harness_risk_actions": {"codex": {"local_secret_read": "allow"}}},
            "risk",
            "block",
        ),
        (
            '[risk_actions]\nlocal_secret_read="allow"\n',
            {"risk_actions": {"local_secret_read": "block"}},
            "risk",
            "block",
        ),
    ],
)
def test_each_origin_resolves_its_own_priority_before_composition(
    tmp_path: Path, local: str, settings: dict[str, object], kind: str, expected: str
) -> None:
    config = loaded(tmp_path, local, settings)
    actual = (
        resolve_risk_action(config, "local_secret_read", harness="codex")
        if kind == "risk"
        else config.resolve_action_override("codex", "target", "vendor")
    )
    assert actual == expected


def test_cloud_default_updates_original_local_origin_before_managed_composition(tmp_path: Path) -> None:
    config = loaded(tmp_path, "", {"harnesses": {"codex": "allow"}})
    overlaid = overlay_synced_guard_policy(config, {"defaultAction": "block"})
    assert overlaid.resolve_action_override("codex", "target", None) == "block"
    assert config.resolve_action_override("codex", "target", None) == "allow"


def test_implicit_original_local_defaults_and_runtime_overlays_remain_floors(tmp_path: Path) -> None:
    from dataclasses import replace

    config = loaded(tmp_path, "", {"risk_actions": {"local_secret_read": "allow"}})
    assert resolve_risk_action(config, "local_secret_read", harness="codex") == "require-reapproval"
    overlaid = replace(config, artifact_actions={"target": "block"})
    assert overlaid.resolve_action_override("codex", "target", None) == "block"


def test_local_specific_exception_stays_within_local_origin(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.config import load_guard_config
    from codex_plugin_scanner.guard.mdm.contracts import ManagedPolicyState

    config = loaded(tmp_path, '[harnesses]\ncodex="block"\n[artifacts]\ntarget="allow"\n', {"default_action": "allow"})
    assert config.resolve_action_override("codex", "target", None) == "allow"
    assert config.resolve_action_override("codex", "other", None) == "block"
    local = config.local_policy_origin
    assert local is not None and local.managed_policy is None and local.local_policy_origin is None
    standalone = load_guard_config(tmp_path, managed_policy_state=ManagedPolicyState("absent", "test"))
    assert local == standalone
    assert "local_policy_origin=" not in repr(config)


def test_original_local_fields_enter_exact_approval_context_when_flattening_matches(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.cli.commands_support_runtime_policy import _runtime_hook_effective_policy_config
    from codex_plugin_scanner.guard.config import load_guard_config
    from codex_plugin_scanner.guard.mdm.contracts import ManagedPolicyState
    from codex_plugin_scanner.guard.native_policy_snapshot_policy import effective_native_policy_v3

    original = loaded(tmp_path, "", {"default_action": "block"})
    path = tmp_path / "config.toml"
    path.write_text(path.read_text().replace('default_action="allow"', 'default_action="warn"'))
    changed = load_guard_config(
        tmp_path, managed_policy_state=ManagedPolicyState("active", "test", policy=original.managed_policy)
    )
    assert effective_native_policy_v3(original) == effective_native_policy_v3(changed)
    assert original.managed_policy_hash == changed.managed_policy_hash
    original_context = _runtime_hook_effective_policy_config(original)
    changed_context = _runtime_hook_effective_policy_config(changed)
    assert original_context != changed_context
    assert "local_policy_origin" in original_context
    local = original.local_policy_origin
    assert local is not None
    assert "local_policy_origin" not in _runtime_hook_effective_policy_config(local)
