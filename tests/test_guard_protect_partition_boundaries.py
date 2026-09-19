"""Check the live facade seams used by the Protect partition."""

from __future__ import annotations

import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import local_supply_chain, protect


class _Store:
    def __init__(self):
        self.receipts = []
        self.events = []

    def list_cached_advisories(self, *, limit):
        assert limit is None
        return []

    def add_receipt(self, receipt):
        self.receipts.append(receipt)

    def add_event(self, *event):
        self.events.append(event)


def test_parser_uses_current_facade_handler(monkeypatch):
    command = ["npm", "install", "demo"]
    sentinel = object()
    seen = []
    monkeypatch.setattr(protect, "_parse_npm_request", lambda value: (seen.append(value), sentinel)[1])

    assert protect.parse_protect_command(command) is sentinel
    assert seen == [command]


def test_target_parser_uses_current_facade_dependencies(monkeypatch):
    monkeypatch.setattr(protect, "_parse_package_identity", lambda *_: (" current-name ", " 2.0 "))
    monkeypatch.setattr(protect, "_spec_url", lambda _: None)
    monkeypatch.setattr(protect, "build_package_url", lambda *parts: "|".join(parts))
    monkeypatch.setattr(protect, "ProtectTarget", SimpleNamespace)

    target = protect._package_target("npm", "original-name@1.0")

    assert target.package_name == "current-name"
    assert target.version == "2.0"
    assert target.package_url == "npm|current-name|2.0"
    assert target.raw_spec == "original-name@1.0"


def test_current_advisory_callback_reloads_facade_evaluator(monkeypatch, tmp_path):
    allowed = protect.ProtectVerdict("allow", "allowed", (), ())
    blocked = protect.ProtectVerdict("block", "current block", (), ())
    monkeypatch.setattr(protect, "evaluate_protect_request", lambda *_: allowed)

    class AuthorityObservedError(RuntimeError):
        pass

    def capture_authority(**kwargs):
        monkeypatch.setattr(protect, "evaluate_protect_request", lambda *_: blocked)
        action, context = kwargs["additional_authority_provider"]()
        assert action == "block"
        assert context["action"] == "block"
        assert context["reason"] == "current block"
        raise AuthorityObservedError

    monkeypatch.setattr(local_supply_chain, "build_package_protect_payload", capture_authority)

    with pytest.raises(AuthorityObservedError):
        protect.build_protect_payload(
            command=["npm", "install", "demo@1.0"],
            store=_Store(),
            workspace_dir=tmp_path,
            dry_run=True,
            now="2026-09-19T00:00:00Z",
        )


def test_dry_run_uses_current_receipt_builder(monkeypatch, tmp_path):
    store = _Store()
    receipt = SimpleNamespace(to_dict=lambda: {"receipt_id": "current-receipt"})
    monkeypatch.setattr(local_supply_chain, "build_package_protect_payload", lambda **_: None)
    monkeypatch.setattr(
        protect,
        "evaluate_protect_request",
        lambda *_: protect.ProtectVerdict("allow", "allowed", (), ()),
    )
    monkeypatch.setattr(protect, "_build_install_receipt", lambda *_: receipt)

    payload, status = protect.build_protect_payload(
        command=["custom-tool", "argument"],
        store=store,
        workspace_dir=tmp_path,
        dry_run=True,
        now="2026-09-19T00:00:00Z",
    )

    assert status == 0
    assert payload["executed"] is False
    assert payload["receipt"] == {"receipt_id": "current-receipt"}
    assert store.receipts == [receipt]
    assert store.events[0][0] == "install_time_allow"


def test_receipt_reads_current_fingerprint_and_constructor(monkeypatch):
    request = protect.parse_protect_command(["custom-tool", "argument"])
    verdict = protect.ProtectVerdict("allow", "allowed", (), ())
    monkeypatch.setattr(protect, "_command_fingerprint", lambda _: "f" * 64)
    monkeypatch.setattr(protect, "GuardReceipt", SimpleNamespace)

    receipt = protect._build_install_receipt(request, verdict)

    assert receipt.artifact_hash == "f" * 64
    assert receipt.harness == "custom-tool"
    assert receipt.policy_decision == "allow"


def test_timeout_reads_current_facade_limits(monkeypatch):
    monkeypatch.setattr(protect, "_DEFAULT_PROTECT_TIMEOUT_SECONDS", 17)
    monkeypatch.setattr(protect, "_MAX_PROTECT_TIMEOUT_SECONDS", 29)
    monkeypatch.setenv("GUARD_PROTECT_TIMEOUT_SECONDS", "invalid")
    assert protect._protect_command_timeout_seconds() == 17
    monkeypatch.setenv("GUARD_PROTECT_TIMEOUT_SECONDS", "31")
    assert protect._protect_command_timeout_seconds() == 29


@pytest.mark.parametrize(
    ("helper", "export"),
    [
        ("protect_execution", "build_protect_payload"),
        ("protect_command_parsing", "parse_protect_command"),
        ("protect_target_parsing", "_package_target"),
        ("protect_receipts", "_build_install_receipt"),
    ],
)
def test_helper_can_be_imported_before_facade(helper, export):
    code = (
        "from importlib import import_module\n"
        f"helper = import_module('codex_plugin_scanner.guard.{helper}')\n"
        "facade = import_module('codex_plugin_scanner.guard.protect')\n"
        f"assert getattr(facade, {export!r}) is getattr(helper, {export!r})\n"
        "for name in ('ProtectTarget', 'ProtectRequest', 'ProtectVerdict'):\n"
        "    assert getattr(facade, name).__module__ == facade.__name__\n"
    )
    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    result = subprocess.run(
        [sys.executable, "-c", code],
        env=environment,
        capture_output=True,
        check=False,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
