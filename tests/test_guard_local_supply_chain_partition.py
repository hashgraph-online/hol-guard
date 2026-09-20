"""Exercise live dependency and import seams of the local supply-chain facade."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import local_supply_chain as supply_chain
from codex_plugin_scanner.guard.local_supply_chain_policy_identity import recompute_package_protect_artifact_hash
from codex_plugin_scanner.guard.local_supply_chain_posture import resolve_package_firewall_entitlement_with_refresh

_OWNERS = (
    "",
    "advisories",
    "archive_binding",
    "audit_discovery",
    "audit_evaluation",
    "audit_receipts",
    "cloud_audit",
    "cloud_requests",
    "cloud_sync",
    "inventory",
    "policy_evaluation",
    "policy_identity",
    "posture",
    "protect_authority",
    "protect_execution",
    "protect_projection",
    "stored_policy",
    "values",
)


@pytest.mark.parametrize("owner", _OWNERS, ids=lambda owner: owner or "facade")
def test_supply_chain_can_import_each_owner_first_and_resolve_annotations(owner: str) -> None:
    source_root = Path(supply_chain.__file__).resolve().parents[2]
    script = """
import importlib
import inspect
import sys
import typing
from pathlib import Path

sys.path.insert(0, sys.argv[1])
module = importlib.import_module(sys.argv[2])
facade = importlib.import_module('codex_plugin_scanner.guard.local_supply_chain')
assert Path(facade.__file__).resolve().is_relative_to(Path(sys.argv[1]).resolve())
assert facade._PackageProtectAuthority.__module__ == facade.__name__
assert facade._StoredPackagePolicyResolution.__module__ == facade.__name__
assert facade._PackageProtectAuthority.__dataclass_fields__['invoking_harness'].default_factory is (
    facade._resolve_local_supply_chain_harness
)
for name, value in vars(module).items():
    if inspect.isfunction(value) and value.__module__.startswith(facade.__name__):
        assert getattr(facade, name) is value
        typing.get_type_hints(value)
typing.get_type_hints(facade._PackageProtectAuthority)
typing.get_type_hints(facade._StoredPackagePolicyResolution)
"""
    module = supply_chain.__name__ + (f"_{owner}" if owner else "")
    result = subprocess.run(
        [sys.executable, "-c", script, str(source_root), module],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_refresh_uses_replaced_facade_lock_state_path_and_interval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    events: list[object] = []
    allowed = {"value": False}
    store = SimpleNamespace(guard_home=tmp_path, get_cloud_sync_profile=lambda: {"connected": True})
    denied = {"allowed": False, "reason": "guard_cloud_connect_required"}
    granted = {"allowed": True}

    class RefreshLock:
        def __enter__(self):
            events.append("lock")

        def __exit__(self, *args):
            events.append("unlock")

    def entitlement(_store):
        assert _store is store
        return granted if allowed["value"] else denied

    def refresh(_store, *, auth_context):
        assert _store is store
        assert auth_context == {"proof": "current"}
        events.append("refresh")
        allowed["value"] = True

    runner = SimpleNamespace(
        GuardSyncAuthorizationExpiredError=RuntimeError,
        GuardSyncNotAvailableError=ValueError,
        GuardSyncNotConfiguredError=LookupError,
    )
    monkeypatch.setattr(supply_chain, "_runtime_runner_module", lambda: runner)
    monkeypatch.setattr(
        supply_chain,
        "_package_firewall_entitlement_module",
        lambda: SimpleNamespace(resolve_package_firewall_entitlement=entitlement),
    )
    monkeypatch.setattr(supply_chain, "_PACKAGE_FIREWALL_REFRESH_LOCK", RefreshLock())
    monkeypatch.setattr(supply_chain, "_PACKAGE_FIREWALL_REFRESH_STATE_FILE", "replacement-refresh.json")
    monkeypatch.setattr(supply_chain, "_PACKAGE_FIREWALL_REFRESH_MIN_INTERVAL_SECONDS", 300)
    monkeypatch.setattr(supply_chain, "time", SimpleNamespace(time=lambda: 1100.0))
    monkeypatch.setattr(supply_chain, "_resolve_guard_sync_auth_context", lambda _store: {"proof": "current"})
    monkeypatch.setattr(supply_chain, "sync_local_guard_cloud_proof", refresh)
    monkeypatch.setattr(supply_chain, "sync_supply_chain_bundle", refresh)
    state_path = tmp_path / "replacement-refresh.json"
    state_path.write_text('{"last_refresh_attempt_at":1000}', encoding="utf-8")

    assert resolve_package_firewall_entitlement_with_refresh(store) is denied
    assert events == ["lock", "unlock"]
    monkeypatch.setattr(supply_chain, "_PACKAGE_FIREWALL_REFRESH_MIN_INTERVAL_SECONDS", 50)
    assert resolve_package_firewall_entitlement_with_refresh(store) is granted
    assert events == ["lock", "unlock", "lock", "unlock", "refresh", "refresh"]
    assert json.loads(state_path.read_text(encoding="utf-8")) == {"last_refresh_attempt_at": 1100.0}
    assert not (tmp_path / "package-firewall-refresh.json").exists()


def test_imported_policy_hash_recomputation_uses_current_facade_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, object]] = []

    def authority(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(artifact_hash="fresh-authority")

    monkeypatch.setattr(supply_chain, "_build_package_protect_authority", authority)
    result = recompute_package_protect_artifact_hash(
        ("npm", "install", "example"), store=None, workspace_dir=tmp_path, now="2026-09-19T00:00:00Z"
    )
    assert result == "fresh-authority"
    assert calls[0]["command"] == ("npm", "install", "example")
    assert calls[0]["workspace_dir"] == tmp_path
    monkeypatch.setattr(supply_chain, "_build_package_protect_authority", lambda **kwargs: None)
    assert recompute_package_protect_artifact_hash(("npm", "install"), store=None, workspace_dir=tmp_path) is None


@pytest.mark.parametrize(
    ("resolver", "relative_module"),
    (
        ("_runtime_runner_module", ".runtime.runner"),
        ("_package_firewall_entitlement_module", ".package_firewall_entitlement"),
        ("_package_intent_parser_module", ".runtime.package_intent_parser"),
        ("_supply_chain_package_eval_module", ".runtime.supply_chain_package_eval"),
    ),
)
def test_lazy_resolvers_keep_the_original_package_anchor(
    resolver: str, relative_module: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[str, str]] = []
    module = object()

    def import_module(name, package):
        calls.append((name, package))
        return module

    monkeypatch.setattr(supply_chain, "importlib", SimpleNamespace(import_module=import_module))
    assert getattr(supply_chain, resolver)() is module
    assert calls == [(relative_module, "codex_plugin_scanner.guard")]


def test_lazy_runtime_exports_follow_current_facade_resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    sentinel = object()
    monkeypatch.setattr(
        supply_chain, "_runtime_runner_module", lambda: SimpleNamespace(GuardSyncNotAvailableError=sentinel)
    )
    assert supply_chain.GuardSyncNotAvailableError is sentinel
    with pytest.raises(AttributeError, match=r"codex_plugin_scanner\.guard\.local_supply_chain.*unknown_export"):
        _ = supply_chain.unknown_export
