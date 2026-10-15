from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approval_gate import (
    ApprovalGateError,
    ApprovalGateInput,
    require_high_risk,
    update_settings,
)
from codex_plugin_scanner.guard.policy_document import GuardPolicyDocument
from codex_plugin_scanner.guard.policy_document_authority import policy_import_approval_binding
from codex_plugin_scanner.guard.policy_document_compile import compile_policy_document
from codex_plugin_scanner.guard.policy_document_yaml import parse_policy_document_yaml
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_mcp_policy_test_support import _BASIC_POLICY_YAML


def test_cli_issues_document_bound_grant(
    tmp_path: Path,
    native_mcp_probe,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import json

    from codex_plugin_scanner.cli import main
    from codex_plugin_scanner.guard.cli import commands as command
    from codex_plugin_scanner.guard.policy_document_io import write_private_policy_text

    home = tmp_path / "cli-home"
    store = GuardStore(home)
    native_mcp_probe(home)
    password = "synthetic-policy-cli-approval"
    update_settings(home, {"enabled": True, "new_password": password, "confirm_password": password})
    policy_path = tmp_path / "policy.yaml"
    write_private_policy_text(policy_path, _BASIC_POLICY_YAML)
    monkeypatch.setenv("HOL_GUARD_POLICY_YAML_IMPORT", "1")
    monkeypatch.setattr(
        command, "prompt_for_approval_gate", lambda *args, **kwargs: ApprovalGateInput(password=password)
    )
    grants = []
    issue_grant = command.require_high_risk

    def capture_grant(*args, **kwargs):
        grant = issue_grant(*args, **kwargs)
        assert grant is not None
        grants.append(grant)
        return grant

    monkeypatch.setattr(command, "require_high_risk", capture_grant)
    assert (
        main(["guard", "policy", "import", str(policy_path), "--merge", "--apply", "--home", str(home), "--json"]) == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert password not in json.dumps(payload)
    assert len(store.list_policy_decisions()) == 1
    expected = policy_import_approval_binding(parse_policy_document_yaml(_BASIC_POLICY_YAML), "merge")
    assert len(grants) == 1
    assert grants[0].action == expected["action"]
    assert grants[0].scope == expected["scope"]
    assert grants[0].subject == expected["subject"]


@pytest.mark.parametrize("entrypoint", ["import", "creation"])
@pytest.mark.parametrize("change", ["revision", "action", "target", "provenance", "mode", "none"])
def test_native_grant_binds_complete_document_and_import_mode(
    tmp_path: Path,
    native_hook_force: Path,
    native_mcp_probe,
    monkeypatch: pytest.MonkeyPatch,
    entrypoint: str,
    change: str,
) -> None:
    store = GuardStore(tmp_path / "guard")
    native_mcp_probe(store.guard_home)
    from codex_plugin_scanner.guard import approval_gate

    native_gate = approval_gate._approval_gate_native

    def require_native_result(method, *args, **kwargs):
        result = native_gate(method, *args, **kwargs)
        if method == "require_high_risk":
            from codex_plugin_scanner.guard.native_resident_client import native_resident_client_failure_code

            assert result is not None, native_resident_client_failure_code()
        return result

    monkeypatch.setattr(approval_gate, "_approval_gate_native", require_native_result)
    password = "synthetic-document-approval-password"
    update_settings(
        store.guard_home,
        {
            "enabled": True,
            "new_password": password,
            "confirm_password": password,
            "cooldown_seconds": 0,
        },
    )
    original = parse_policy_document_yaml(_BASIC_POLICY_YAML)
    grant = require_high_risk(
        store.guard_home,
        purpose="policy_import",
        **policy_import_approval_binding(original, "merge"),
        approval_gate_input=ApprovalGateInput(password=password, use_cooldown=False),
    )
    assert grant is not None
    value = original.to_mapping()
    mode = "merge"
    if change == "revision":
        value["metadata"]["revision"] += 1
    elif change == "action":
        value["spec"]["rules"][0]["effect"] = "allow"
    elif change == "target":
        value["spec"]["rules"][0]["match"]["artifacts"] = ["npm:other-package"]
    elif change == "provenance":
        value["spec"]["rules"][0]["provenance"]["createdBy"] = "other-operator"
    elif change == "mode":
        mode = "replace"
    candidate = GuardPolicyDocument.from_mapping(value)
    rows = compile_policy_document(candidate)

    def apply() -> None:
        if entrypoint == "import":
            store.import_policy_document(candidate, rows, mode=mode, now=grant.issued_at, approval_gate_grant=grant)
        else:
            with store._connect() as connection:
                connection.execute("begin immediate")
                store.apply_policy_creation_request(
                    candidate, rows, mode=mode, now=grant.issued_at, approval_gate_grant=grant, connection=connection
                )
                connection.commit()

    if change == "none":
        apply()
        assert len(store.list_policy_decisions()) == 1
    else:
        with pytest.raises(ApprovalGateError):
            apply()
        assert store.list_policy_decisions() == []
