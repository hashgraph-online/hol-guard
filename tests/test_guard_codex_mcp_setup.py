"""The Python side of Codex MCP setup: the request it sends, and what it does with the answer.

The checks that decide what is safe to write (layer validation, version binding,
read-back, rollback) are the native runtime's and are tested in
`rust/crates/guard-runtime/src/codex_mcp_setup_tests.rs`.
"""

from __future__ import annotations

import json
import os

import pytest

from codex_plugin_scanner.guard.local_clis.mcp_registry_undo import RegistrySetupUndo
from codex_plugin_scanner.guard.runtime import codex_mcp_setup
from codex_plugin_scanner.guard.store import GuardStore

ENTRY: dict[str, object] = {"url": "https://example.test/reviewed"}


class NativeStub:
    """Stands in for the native runtime: records each request and answers from a queue."""

    def __init__(self, monkeypatch, *answers):
        self.answers = list(answers)
        self.calls = []
        monkeypatch.setattr("codex_plugin_scanner.guard.mdm.runtime_request.runtime_answer", self)

    def __call__(self, feature, command, request, *, output_limit, timeout_seconds=None, **_):
        assert feature == "native-codex-mcp-setup-v1" and command == "codex-mcp-setup"
        assert isinstance(request, str) and output_limit > 0 and timeout_seconds and timeout_seconds > 0
        self.calls.append(json.loads(request))
        return self.answers.pop(0) if self.answers else None


def _receipt(version="2", previous="1", name="reviewed"):
    return {
        "name": name,
        "file_path": "/synthetic/config.toml",
        "version": version,
        "entry_json": json.dumps(ENTRY, sort_keys=True, separators=(",", ":")),
        "previous_version": previous,
    }


def test_install_sends_the_reviewed_entry_with_this_process_environment(monkeypatch):
    stub = NativeStub(monkeypatch, {"receipt": _receipt()})
    receipts = []
    monkeypatch.setenv("HOL_SETUP_PROBE", "1")

    assert (
        codex_mcp_setup.install_reviewed_codex_mcp("/bin/codex", "reviewed", ENTRY, on_installed=receipts.append)
        == "reviewed"
    )

    [request] = stub.calls
    assert request["op"] == "install" and request["name"] == "reviewed" and request["executable"] == "/bin/codex"
    assert request["cwd"] == os.getcwd() and request["environment"]["HOL_SETUP_PROBE"] == "1"
    assert json.loads(request["entry_json"]) == ENTRY
    assert receipts == [
        codex_mcp_setup.CodexMcpSetupReceipt("reviewed", "/synthetic/config.toml", "2", request["entry_json"], "1")
    ]


def test_rollback_sends_the_receipt_and_returns_the_new_version(monkeypatch):
    stub = NativeStub(monkeypatch, {"version": "3"})
    receipt = codex_mcp_setup.CodexMcpSetupReceipt(**_receipt())

    assert codex_mcp_setup.rollback_reviewed_codex_mcp("/bin/codex", receipt) == "3"

    [request] = stub.calls
    assert request["op"] == "rollback" and request["receipt"] == _receipt()


@pytest.mark.parametrize(
    "reason",
    [
        "codex_connection_already_exists",
        "codex_config_changed",
        "codex_config_readonly",
        "codex_setup_outcome_uncertain",
        "codex_config_no_user_layer",
        "invalid_codex_setup_selection",
    ],
)
def test_a_native_refusal_is_raised_as_its_reason_without_recording_anything(monkeypatch, reason):
    NativeStub(monkeypatch, {"error": reason})
    receipts = []

    with pytest.raises(ValueError) as caught:
        codex_mcp_setup.install_reviewed_codex_mcp("/bin/codex", "reviewed", ENTRY, on_installed=receipts.append)

    assert str(caught.value) == reason and receipts == []


def test_an_unavailable_native_runtime_changes_nothing_and_says_so(monkeypatch):
    stub = NativeStub(monkeypatch)
    receipt = codex_mcp_setup.CodexMcpSetupReceipt(**_receipt())

    with pytest.raises(ValueError, match="codex_setup_native_unavailable"):
        codex_mcp_setup.install_reviewed_codex_mcp("/bin/codex", "reviewed", ENTRY)
    with pytest.raises(ValueError, match="codex_setup_native_unavailable"):
        codex_mcp_setup.rollback_reviewed_codex_mcp("/bin/codex", receipt)

    assert [call["op"] for call in stub.calls] == ["install", "rollback"]


@pytest.mark.parametrize(
    "answer",
    [{"receipt": "text"}, {"receipt": {"name": "reviewed"}}, {"receipt": {**_receipt(), "version": 2}}, {"error": 7}],
)
def test_a_malformed_native_answer_is_treated_as_unavailable(monkeypatch, answer):
    NativeStub(monkeypatch, answer)

    with pytest.raises(ValueError, match="codex_setup_native_unavailable"):
        codex_mcp_setup.install_reviewed_codex_mcp("/bin/codex", "reviewed", ENTRY)


def test_a_non_finite_entry_is_refused_before_the_native_runtime_is_asked(monkeypatch):
    stub = NativeStub(monkeypatch)

    with pytest.raises(ValueError):
        codex_mcp_setup.install_reviewed_codex_mcp("/bin/codex", "reviewed", {"timeout": float("nan")})

    assert stub.calls == []


def test_failed_receipt_retention_rolls_back_before_reporting_success(monkeypatch):
    stub = NativeStub(monkeypatch, {"receipt": _receipt()}, {"version": "3"})

    def fail(_receipt):
        raise ValueError("receipt_retention_failed")

    with pytest.raises(ValueError, match="codex_setup_rolled_back"):
        codex_mcp_setup.install_reviewed_codex_mcp("/bin/codex", "reviewed", ENTRY, on_installed=fail)

    assert [call["op"] for call in stub.calls] == ["install", "rollback"]
    assert stub.calls[1]["receipt"] == _receipt()


def test_a_rollback_that_cannot_complete_after_a_failed_receipt_is_uncertain(monkeypatch):
    NativeStub(monkeypatch, {"receipt": _receipt()}, {"error": "codex_config_changed"})

    def fail(_receipt):
        raise ValueError("receipt_retention_failed")

    with pytest.raises(ValueError, match="codex_setup_outcome_uncertain"):
        codex_mcp_setup.install_reviewed_codex_mcp("/bin/codex", "reviewed", ENTRY, on_installed=fail)


@pytest.mark.parametrize("failure", ["verification", "receipt"])
@pytest.mark.parametrize("outside_edit", [False, True])
def test_failed_setup_reports_both_owned_writes_without_reviving_external_edits(
    monkeypatch, tmp_path, failure, outside_edit
):
    undo = RegistrySetupUndo(GuardStore(tmp_path / "guard"))
    entry = {"url": "https://example.test/existing"}
    receipt = codex_mcp_setup.CodexMcpSetupReceipt("existing", "/synthetic/config.toml", "1", json.dumps(entry))
    handle = undo.remember(receipt, {"setup_name": "existing", "kind": "remote", "endpoint": entry["url"]})
    # An edit made outside Guard first moves the file's version from 1 to 2.
    start = "2" if outside_edit else "1"
    installed = str(int(start) + 1)
    removed = str(int(installed) + 1)
    if failure == "verification":
        pairs = [[start, installed], [installed, removed]]
        NativeStub(
            monkeypatch,
            {"error": "codex_setup_rolled_back", "version_chain": {"file_path": receipt.file_path, "pairs": pairs}},
        )
    else:
        NativeStub(monkeypatch, {"receipt": _receipt(installed, start)}, {"version": removed})

    def fail(_receipt):
        raise ValueError("receipt_retention_failed")

    with pytest.raises(ValueError, match="codex_setup_rolled_back"):
        codex_mcp_setup.install_reviewed_codex_mcp(
            "/bin/codex",
            "reviewed",
            ENTRY,
            on_installed=fail if failure == "receipt" else None,
            on_version_chain=undo.advance_version_chain,
        )

    record = undo._receipts[handle]
    if outside_edit:
        assert record.available is False
        assert record.receipt.version == "1"
    else:
        assert record.available is True and record.receipt.version == "3"


def test_a_failing_version_chain_callback_is_reported_as_uncertain(monkeypatch):
    NativeStub(
        monkeypatch,
        {
            "error": "codex_setup_rolled_back",
            "version_chain": {"file_path": "/synthetic/config.toml", "pairs": [["1", "2"], ["2", "3"]]},
        },
    )

    def fail(_file_path, _pairs):
        raise ValueError("chain_failed")

    with pytest.raises(ValueError, match="codex_setup_outcome_uncertain"):
        codex_mcp_setup.install_reviewed_codex_mcp("/bin/codex", "reviewed", ENTRY, on_version_chain=fail)
