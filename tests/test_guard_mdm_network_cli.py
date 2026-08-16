from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from codex_plugin_scanner import cli
from codex_plugin_scanner.guard.cli import commands_dispatch_mdm
from codex_plugin_scanner.guard.mdm.contracts import ManagedPolicyState
from codex_plugin_scanner.guard.mdm.network import NetworkDiagnostic, ProxyDiagnostic


def _status_validator() -> Draft202012Validator:
    schema_path = Path(__file__).parents[1] / "docs" / "guard" / "schemas" / "mdm-status-v1.schema.json"
    return Draft202012Validator(json.loads(schema_path.read_text(encoding="utf-8")))


def _reachable_diagnostic(endpoint: str) -> NetworkDiagnostic:
    return NetworkDiagnostic(
        endpoint=endpoint,
        dns="ok",
        proxy=ProxyDiagnostic(mode="none", selected=False, endpoint_hash=None, dns="not-tested", authenticated=False),
        tls="trusted",
        clock="ok",
        reachability="reachable",
        reason_code="endpoint_reachable",
        clock_skew_seconds=0,
    )


def test_network_diagnose_is_prompt_free_stable_json_even_without_json_flag(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        commands_dispatch_mdm,
        "load_managed_policy",
        lambda: ManagedPolicyState("absent", "native", reason_code="managed_policy_absent"),
    )
    monkeypatch.setattr(
        commands_dispatch_mdm,
        "diagnose_endpoint",
        lambda endpoint, _policy: _reachable_diagnostic(endpoint.removeprefix("https://")),
    )

    def reject_prompt(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("network-diagnose must not prompt")

    monkeypatch.setattr("builtins.input", reject_prompt)

    args = ["guard", "mdm", "network-diagnose", "--endpoint", "https://guard.example"]
    first_exit = cli.main(args)
    first_output = capsys.readouterr().out.strip()
    second_exit = cli.main(args)
    second_output = capsys.readouterr().out.strip()

    assert first_exit == 0
    assert second_exit == 0
    assert first_output == second_output
    payload = json.loads(first_output)
    _status_validator().validate(payload)
    assert payload["schemaVersion"] == "hol-guard-mdm-status.v1"
    assert payload["operation"] == "network-diagnose"
    assert payload["healthy"] is True
    assert payload["results"][0]["dns"] == "ok"
    assert payload["results"][0]["proxy"]["selected"] is False
    assert payload["results"][0]["tls"] == "trusted"
    assert payload["results"][0]["clock"] == "ok"
    assert payload["results"][0]["reachability"] == "reachable"


def test_network_diagnose_exception_is_redacted_and_machine_readable(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret = "synthetic-sensitive-detail"

    def fail_policy_load() -> ManagedPolicyState:
        raise RuntimeError(secret)

    monkeypatch.setattr(commands_dispatch_mdm, "load_managed_policy", fail_policy_load)

    exit_code = cli.main(["guard", "mdm", "network-diagnose", "--endpoint", "https://guard.example"])
    output = capsys.readouterr().out.strip()
    payload = json.loads(output)

    assert exit_code == 2
    _status_validator().validate(payload)
    assert payload["reasonCodes"] == ["network_diagnose_failed"]
    assert payload["managedPolicy"] == {
        "status": "invalid",
        "source": "redacted",
        "reasonCode": "network_diagnose_failed",
    }
    assert payload["results"] == []
    assert secret not in output
