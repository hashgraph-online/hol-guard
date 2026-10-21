from __future__ import annotations

import copy
import json

import pytest

from codex_plugin_scanner.guard.daemon.mcp_registry_undo import RegistrySetupUndo
from codex_plugin_scanner.guard.runtime import codex_mcp_setup
from codex_plugin_scanner.guard.store import GuardStore


class ConfigHost:
    def __init__(self, path):
        self.path = str(path)
        self.config = {"model": "untouched", "mcp_servers": {"existing": {"url": "https://example.test/existing"}}}
        self.version = 1
        self.reads = 0
        self.writes = []
        self.corrupt_verification = False
        self.change_before_write = False
        self.drop_write_reply = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass

    def request(self, method, params):
        if method == "config/read":
            self.reads += 1
            if self.corrupt_verification and self.reads == 2:
                return {"layers": []}
            return {
                "layers": [
                    {
                        "name": {"type": "user", "file": self.path, "profile": None},
                        "version": str(self.version),
                        "config": copy.deepcopy(self.config),
                    }
                ]
            }
        assert method == "config/batchWrite"
        assert params["filePath"] == self.path and params["reloadUserConfig"] is False
        if self.change_before_write:
            self.version += 1
            self.config["user_edit"] = "preserved"
            self.change_before_write = False
        if params["expectedVersion"] != str(self.version):
            raise ValueError("codex_config_changed")
        [edit] = params["edits"]
        assert edit["keyPath"].startswith("mcp_servers.") and edit["mergeStrategy"] == "replace"
        name = edit["keyPath"].removeprefix("mcp_servers.")
        self.writes.append(copy.deepcopy(params))
        if edit["value"] is None:
            self.config["mcp_servers"].pop(name)
        else:
            self.config["mcp_servers"][name] = copy.deepcopy(edit["value"])
        self.version += 1
        if self.drop_write_reply:
            raise ValueError("codex_config_rpc_timeout")
        return {"status": "ok", "filePath": self.path, "version": str(self.version)}


@pytest.fixture
def host(tmp_path, monkeypatch):
    fixture = ConfigHost(tmp_path / "config.toml")
    monkeypatch.setattr(codex_mcp_setup, "CodexConfigRpc", lambda _executable: fixture)
    return fixture


def test_setup_and_rollback_only_edit_the_reviewed_connection(host):
    before = copy.deepcopy(host.config)
    receipts = []
    entry = {"url": "https://example.test/reviewed"}
    assert (
        codex_mcp_setup.install_reviewed_codex_mcp("fixture", "reviewed", entry, on_installed=receipts.append)
        == "reviewed"
    )
    assert len(receipts) == 1 and receipts[0].version == "2"
    assert host.config["model"] == before["model"]
    assert host.config["mcp_servers"]["existing"] == before["mcp_servers"]["existing"]
    codex_mcp_setup.rollback_reviewed_codex_mcp("fixture", receipts[0])
    assert host.config == before
    assert [write["expectedVersion"] for write in host.writes] == ["1", "2"]


def test_existing_connection_including_null_metadata_is_never_replaced(host):
    host.config["mcp_servers"]["reviewed"] = None
    with pytest.raises(ValueError, match="codex_connection_already_exists"):
        codex_mcp_setup.install_reviewed_codex_mcp("fixture", "reviewed", {"url": "https://example.test"})
    assert host.writes == []


@pytest.mark.parametrize(
    "case,reason",
    [
        ("malformed_layers", "codex_config_layers_unavailable"),
        ("no_layers", "codex_config_no_layers"),
        ("malformed_layer", "codex_config_invalid_layer"),
        ("invalid_servers", "codex_config_invalid_servers"),
        ("no_user", "codex_config_no_user_layer"),
        ("multiple_users", "codex_config_multiple_user_layers"),
        ("invalid_version", "codex_config_invalid_user_version"),
        ("invalid_path", "codex_config_invalid_user_path"),
        ("disabled", "codex_config_user_layer_disabled"),
    ],
)
def test_invalid_host_layers_have_safe_distinct_reasons_before_any_write(host, monkeypatch, case, reason):
    before = copy.deepcopy(host.config)
    payload = host.request("config/read", {})
    layer = payload["layers"][0]
    if case == "malformed_layers":
        payload["layers"] = "private configuration"
    elif case == "no_layers":
        payload["layers"] = []
    elif case == "malformed_layer":
        layer["config"] = "private configuration"
    elif case == "invalid_servers":
        layer["config"]["mcp_servers"] = "private configuration"
    elif case == "no_user":
        layer["name"]["type"] = "project"
    elif case == "multiple_users":
        payload["layers"].append(copy.deepcopy(layer))
    elif case == "invalid_version":
        layer["version"] = {"private": "configuration"}
    elif case == "invalid_path":
        layer["name"]["file"] = "private/config.toml"
    elif case == "disabled":
        layer["disabledReason"] = "private configuration"
    original_request = host.request

    def read_layers(method, params):
        if method == "config/read":
            return payload
        return original_request(method, params)

    monkeypatch.setattr(host, "request", read_layers)
    with pytest.raises(ValueError) as caught:
        codex_mcp_setup.install_reviewed_codex_mcp("fixture", "reviewed", {"url": "https://example.test"})
    assert str(caught.value) == reason
    assert host.writes == [] and host.config == before


def test_setup_version_conflict_preserves_concurrent_user_edits(host):
    host.change_before_write = True
    with pytest.raises(ValueError, match="codex_config_changed"):
        codex_mcp_setup.install_reviewed_codex_mcp("fixture", "reviewed", {"url": "https://example.test"})
    assert host.writes == [] and host.config["user_edit"] == "preserved"
    assert "reviewed" not in host.config["mcp_servers"]


def test_uncertain_write_is_not_replayed_or_removed_without_a_version_receipt(host):
    host.drop_write_reply = True
    receipts = []
    with pytest.raises(ValueError, match="codex_setup_outcome_uncertain"):
        codex_mcp_setup.install_reviewed_codex_mcp(
            "fixture", "reviewed", {"url": "https://example.test"}, on_installed=receipts.append
        )
    assert len(host.writes) == 1 and receipts == []
    assert "reviewed" in host.config["mcp_servers"]


def test_failed_verification_rolls_back_only_the_acknowledged_setup(host):
    before = copy.deepcopy(host.config)
    host.corrupt_verification = True
    with pytest.raises(ValueError, match="codex_setup_rolled_back"):
        codex_mcp_setup.install_reviewed_codex_mcp("fixture", "reviewed", {"url": "https://example.test"})
    assert host.config == before
    assert host.writes[-1]["edits"][0]["value"] is None


def test_rollback_refuses_changed_host_configuration(host):
    receipts = []
    codex_mcp_setup.install_reviewed_codex_mcp(
        "fixture", "reviewed", {"url": "https://example.test"}, on_installed=receipts.append
    )
    host.version += 1
    host.config["user_edit"] = "preserved"
    with pytest.raises(ValueError, match="codex_config_changed"):
        codex_mcp_setup.rollback_reviewed_codex_mcp("fixture", receipts[0])
    assert len(host.writes) == 1 and host.config["user_edit"] == "preserved"
    assert "reviewed" in host.config["mcp_servers"]


def test_failed_receipt_retention_rolls_back_before_reporting_success(host):
    before = copy.deepcopy(host.config)

    def fail(_receipt):
        raise ValueError("receipt_retention_failed")

    with pytest.raises(ValueError, match="codex_setup_rolled_back"):
        codex_mcp_setup.install_reviewed_codex_mcp(
            "fixture", "reviewed", {"url": "https://example.test"}, on_installed=fail
        )
    assert host.config == before


@pytest.mark.parametrize("failure", ["verification", "receipt"])
@pytest.mark.parametrize("outside_edit", [False, True])
def test_failed_setup_reports_both_owned_writes_without_reviving_external_edits(host, tmp_path, failure, outside_edit):
    undo = RegistrySetupUndo(GuardStore(tmp_path / "guard"))
    entry = host.config["mcp_servers"]["existing"]
    receipt = codex_mcp_setup.CodexMcpSetupReceipt("existing", host.path, "1", json.dumps(entry))
    handle = undo.remember(receipt, {"setup_name": "existing", "kind": "remote", "endpoint": entry["url"]})
    if outside_edit:
        host.version += 1
        host.config["user_edit"] = "preserved"
    if failure == "verification":
        host.corrupt_verification = True

    def fail(_receipt):
        raise ValueError("receipt_retention_failed")

    with pytest.raises(ValueError, match="codex_setup_rolled_back"):
        codex_mcp_setup.install_reviewed_codex_mcp(
            "fixture",
            "reviewed",
            {"url": "https://example.test/reviewed"},
            on_installed=fail if failure == "receipt" else None,
            on_version_chain=undo.advance_version_chain,
        )
    record = undo._receipts[handle]
    assert "reviewed" not in host.config["mcp_servers"]
    if outside_edit:
        assert record.available is False
        assert host.config["user_edit"] == "preserved"
        assert record.receipt.version == "1"
    else:
        assert record.available is True and record.receipt.version == "3"
        assert codex_mcp_setup.rollback_reviewed_codex_mcp("fixture", record.receipt) == "4"
        assert host.config == {"model": "untouched", "mcp_servers": {}}


@pytest.mark.parametrize("name", ["other.config", "../../config", "", "a" * 65])
def test_setup_rejects_configuration_key_injection(host, name):
    with pytest.raises(ValueError, match="invalid_codex_setup_selection"):
        codex_mcp_setup.install_reviewed_codex_mcp("fixture", name, {"url": "https://example.test"})
    assert host.reads == 0 and host.writes == []
