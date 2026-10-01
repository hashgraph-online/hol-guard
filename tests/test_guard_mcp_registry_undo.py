from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approval_gate import update_settings
from codex_plugin_scanner.guard.daemon import mcp_registry_undo
from codex_plugin_scanner.guard.daemon.local_cli_api import LocalCliApiError, LocalCliApiService
from codex_plugin_scanner.guard.runtime.codex_mcp_setup import CodexMcpSetupReceipt
from codex_plugin_scanner.guard.store import GuardStore


def _setup(tmp_path: Path):
    store = GuardStore(tmp_path / "guard")
    service = LocalCliApiService(store=store)
    candidate = {
        "host": "codex",
        "kind": "remote",
        "setup_name": "example",
        "registry_name": "org.example/server",
        "version": "1.0.0",
        "endpoint": "https://example.test/mcp",
        "selection_digest": "a" * 64,
        "permissions_granted": False,
        "host_change_applied": False,
    }
    receipt = CodexMcpSetupReceipt(
        "example", "/synthetic/private/config.toml", "v1", json.dumps({"url": candidate["endpoint"]})
    )
    handle = service._registry_setup_undo.remember(receipt, candidate)
    payload = {
        "operation": "rollback",
        "rollback_handle": handle,
        "setup_name": "example",
        "selection_digest": "a" * 64,
        "confirm_host_change": True,
        "session_nonce": "n" * 32,
    }
    return store, service, receipt, handle, payload


def _protect(store):
    update_settings(
        store.guard_home,
        {
            "enabled": True,
            "new_password": "synthetic-password",
            "confirm_password": "synthetic-password",
            "cooldown_seconds": 0,
        },
    )


def test_undo_requires_fresh_proof_and_success_cannot_be_replayed(tmp_path, monkeypatch):
    store, service, receipt, handle, payload = _setup(tmp_path)
    calls = []
    monkeypatch.setattr(mcp_registry_undo.shutil, "which", lambda _name: "/synthetic/codex")
    monkeypatch.setattr(mcp_registry_undo, "rollback_reviewed_codex_mcp", lambda *args: calls.append(args) or "v2")
    with pytest.raises(LocalCliApiError) as missing:
        service.registry_setup(payload)
    assert missing.value.status == 423 and not calls
    _protect(store)
    with pytest.raises(LocalCliApiError):
        service.registry_setup({**payload, "approval_password": "wrong"})
    assert not calls
    result = service.registry_setup({**payload, "approval_password": "synthetic-password"})
    assert result["setup_rolled_back"] is True and result["permissions_granted"] is False
    assert calls == [("/synthetic/codex", receipt)]
    assert service.registry_setup({"operation": "recent"})["setups"] == []
    with pytest.raises(LocalCliApiError) as replay:
        service.registry_setup({**payload, "approval_password": "synthetic-password"})
    assert replay.value.status == 404 and len(calls) == 1
    assert handle not in service._registry_setup_undo._receipts


@pytest.mark.parametrize(
    "change", [{"confirm_host_change": False}, {"setup_name": "other"}, {"selection_digest": "b" * 64}]
)
def test_undo_review_must_match_owned_receipt(tmp_path, monkeypatch, change):
    _, service, _, _, payload = _setup(tmp_path)
    calls = []
    monkeypatch.setattr(mcp_registry_undo, "rollback_reviewed_codex_mcp", lambda *args: calls.append(args))
    with pytest.raises(LocalCliApiError) as mismatch:
        service.registry_setup({**payload, **change})
    assert mismatch.value.status == 409 and not calls
    assert len(service.registry_setup({"operation": "recent"})["setups"]) == 1


def test_receipts_are_daemon_owned_expire_and_never_expose_host_config(tmp_path, monkeypatch):
    store, service, _, handle, _ = _setup(tmp_path)
    recent = service.registry_setup({"operation": "recent"})["setups"]
    assert recent == [
        {
            "rollback_handle": handle,
            "setup_name": "example",
            "rollback_available": True,
            "kind": "remote",
            "registry_name": "org.example/server",
            "version": "1.0.0",
            "selection_digest": "a" * 64,
        }
    ]
    preview = service.registry_setup({"operation": "rollback-preview", "rollback_handle": handle})
    assert preview["permissions_granted"] is False and preview["host_change_applied"] is False
    assert "private" not in json.dumps(preview) and "file_path" not in preview
    other = LocalCliApiService(store=store)
    with pytest.raises(LocalCliApiError) as foreign:
        other.registry_setup({"operation": "rollback-preview", "rollback_handle": handle})
    assert foreign.value.status == 404
    record = service._registry_setup_undo._receipts[handle]
    monkeypatch.setattr(mcp_registry_undo.time, "monotonic", lambda: record.expires_at + 1)
    assert service.registry_setup({"operation": "recent"})["setups"] == []
    with pytest.raises(LocalCliApiError) as expired:
        service.registry_setup({"operation": "rollback-preview", "rollback_handle": handle})
    assert expired.value.status == 404


def test_config_conflict_keeps_receipt_and_does_not_depend_on_registry(tmp_path, monkeypatch):
    store, service, _, handle, payload = _setup(tmp_path)
    _protect(store)
    monkeypatch.setattr(mcp_registry_undo.shutil, "which", lambda _name: "/synthetic/codex")

    def conflict(*_args):
        raise ValueError("codex_config_changed")

    monkeypatch.setattr(mcp_registry_undo, "rollback_reviewed_codex_mcp", conflict)
    with pytest.raises(LocalCliApiError) as changed:
        service.registry_setup({**payload, "approval_password": "synthetic-password"})
    assert changed.value.status == 409
    assert "kept it unchanged" in str(changed.value)
    assert service.registry_setup({"operation": "recent"})["setups"][0]["rollback_handle"] == handle
    assert service.registry_setup({"operation": "recent"})["setups"][0]["rollback_available"] is False
    with pytest.raises(LocalCliApiError) as unavailable:
        service.registry_setup({"operation": "rollback-preview", "rollback_handle": handle})
    assert unavailable.value.code == "codex_config_changed"


def test_receipt_capacity_is_bounded_and_rejects_mismatched_entries(tmp_path):
    _, service, receipt, handle, _ = _setup(tmp_path)
    undo = service._registry_setup_undo
    candidate = undo.preview({"rollback_handle": handle})
    for _ in range(31):
        undo.remember(receipt, candidate)
    with pytest.raises(ValueError, match="receipt_limit"):
        undo.remember(receipt, candidate)
    with pytest.raises(ValueError, match="outcome_uncertain"):
        undo.remember(receipt, {**candidate, "endpoint": "https://other.test/mcp"})
    assert len(undo.recent()) == 32
    with pytest.raises(ValueError, match="receipt_limit"):
        undo.ensure_capacity()


@pytest.mark.parametrize("order", [("example", "second"), ("second", "example")])
def test_guard_owned_writes_keep_both_setups_undoable_in_either_order(tmp_path, monkeypatch, order):
    store, service, receipt, handle, payload = _setup(tmp_path)
    _protect(store)
    undo = service._registry_setup_undo
    candidate = {**undo.preview({"rollback_handle": handle}), "setup_name": "second"}
    second = replace(receipt, name="second", version="v2", previous_version="v1")
    second_handle = undo.remember(second, candidate)
    assert undo._receipts[handle].receipt.version == "v2"
    assert all(item["rollback_available"] for item in undo.recent())
    monkeypatch.setattr(mcp_registry_undo.shutil, "which", lambda _name: "/synthetic/codex")
    versions = iter(["v3", "v4"])
    observed = []

    def remove(_executable, current):
        observed.append((current.name, current.version))
        return next(versions)

    monkeypatch.setattr(mcp_registry_undo, "rollback_reviewed_codex_mcp", remove)
    handles = {"example": handle, "second": second_handle}
    for index, name in enumerate(order):
        result = service.registry_setup(
            {
                **payload,
                "rollback_handle": handles[name],
                "setup_name": name,
                "session_nonce": f"fresh-{index}",
                "approval_password": "synthetic-password",
            }
        )
        assert result["setup_rolled_back"] is True and result["permissions_granted"] is False
    assert observed == [(order[0], "v2"), (order[1], "v3")]
    assert undo.recent() == []


def test_guard_write_after_external_edit_marks_older_undo_unavailable(tmp_path):
    _, service, receipt, handle, _ = _setup(tmp_path)
    undo = service._registry_setup_undo
    candidate = {**undo.preview({"rollback_handle": handle}), "setup_name": "second"}
    undo.remember(replace(receipt, name="second", previous_version="user-edit", version="v3"), candidate)
    older = next(item for item in undo.recent() if item["rollback_handle"] == handle)
    assert older["rollback_available"] is False
    with pytest.raises(mcp_registry_undo.RegistryUndoError, match="configuration changed"):
        undo.preview({"rollback_handle": handle})


def test_version_chain_does_not_touch_receipts_from_another_profile(tmp_path):
    _, service, receipt, handle, _ = _setup(tmp_path)
    undo = service._registry_setup_undo
    candidate = {**undo.preview({"rollback_handle": handle}), "setup_name": "second"}
    undo.remember(
        replace(receipt, name="second", file_path="/synthetic/other/config.toml", previous_version="v1", version="v2"),
        candidate,
    )
    assert undo._receipts[handle].receipt == receipt
    assert undo._receipts[handle].available is True


@pytest.mark.parametrize("stage", ["approval", "host"])
def test_history_and_preview_remain_responsive_during_undo(tmp_path, monkeypatch, stage):
    store, service, _, handle, payload = _setup(tmp_path)
    _protect(store)
    entered, release = threading.Event(), threading.Event()

    def wait():
        entered.set()
        assert release.wait(5), "test did not release the pending Undo"

    original_trust = mcp_registry_undo.require_local_cli_trust

    def trust(*args, **kwargs):
        if stage == "approval":
            wait()
        return original_trust(*args, **kwargs)

    def remove(*_args):
        if stage == "host":
            wait()
        return "v2"

    monkeypatch.setattr(mcp_registry_undo, "require_local_cli_trust", trust)
    monkeypatch.setattr(mcp_registry_undo.shutil, "which", lambda _name: "/synthetic/codex")
    monkeypatch.setattr(mcp_registry_undo, "rollback_reviewed_codex_mcp", remove)
    with ThreadPoolExecutor(max_workers=2) as workers:
        undo = workers.submit(service.registry_setup, {**payload, "approval_password": "synthetic-password"})
        try:
            assert entered.wait(3)
            recent = workers.submit(service.registry_setup, {"operation": "recent"}).result(timeout=2)
            assert recent["setups"][0]["rollback_handle"] == handle
            preview = workers.submit(
                service.registry_setup, {"operation": "rollback-preview", "rollback_handle": handle}
            ).result(timeout=2)
            assert preview["rollback_handle"] == handle
        finally:
            release.set()
        assert undo.result(timeout=3)["setup_rolled_back"] is True


def test_undo_does_not_remove_a_receipt_replaced_while_host_was_pending(tmp_path, monkeypatch):
    store, service, _, handle, payload = _setup(tmp_path)
    _protect(store)
    undo = service._registry_setup_undo
    monkeypatch.setattr(mcp_registry_undo.shutil, "which", lambda _name: "/synthetic/codex")

    def remove(*_args):
        undo.advance_version_chain("/synthetic/private/config.toml", [("v1", "v2")])
        return "v3"

    monkeypatch.setattr(mcp_registry_undo, "rollback_reviewed_codex_mcp", remove)
    with pytest.raises(LocalCliApiError) as uncertain:
        service.registry_setup({**payload, "approval_password": "synthetic-password"})
    assert uncertain.value.code == "codex_setup_outcome_uncertain"
    assert undo._receipts[handle].receipt.version == "v2"
