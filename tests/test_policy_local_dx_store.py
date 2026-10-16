"""Policy commands that read this device: status, explain, diff, import, export and history."""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli.commands_dispatch_records import _run_guard_history_command
from codex_plugin_scanner.guard.models import GuardReceipt
from codex_plugin_scanner.guard.policy_delivery_status import (
    format_policy_status,
    normalized_policy_delivery_url,
    policy_status_payload,
)
from codex_plugin_scanner.guard.policy_document_compile import compile_policy_document
from codex_plugin_scanner.guard.policy_document_yaml import parse_policy_document_yaml
from codex_plugin_scanner.guard.policy_starters import LEGACY_POLICY_MODELINES, POLICY_MODELINE
from codex_plugin_scanner.guard.store import GuardStore

FIXTURES = Path(__file__).resolve().parents[1] / "spec" / "guard-policy" / "v1alpha1" / "fixtures"
SCOPES = FIXTURES / "valid" / "enforceable-scopes.yaml"
NOW = "2026-10-14T12:00:00Z"


def _install_scopes(home: Path) -> GuardStore:
    store = GuardStore(home)
    document = parse_policy_document_yaml(SCOPES.read_bytes())
    store.import_policy_document(
        document, compile_policy_document(document), mode="replace", now=NOW, approval_gate_grant=None
    )
    return store


def _receipt(store: GuardStore, receipt_id: str, *, harness: str, artifact_id: str, decision: str) -> None:
    store.add_receipt(
        GuardReceipt(
            receipt_id=receipt_id,
            harness=harness,
            artifact_id=artifact_id,
            artifact_hash="sha256:test",
            policy_decision=decision,
            capabilities_summary="test",
            changed_capabilities=(),
            provenance_summary="test",
            timestamp=NOW,
        )
    )


def _json(capsys: pytest.CaptureFixture[str], home: Path, *argv: str) -> tuple[int, dict[str, object]]:
    code = main(["guard", "policy", *argv, "--home", str(home), "--format", "json"])
    return code, json.loads(capsys.readouterr().out)


def test_status_reports_version_mode_sync_ack_and_rejection(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "home"
    store = GuardStore(home)
    store.set_sync_payload("policy_bundle", {"bundleVersion": "7", "bundleHash": "ab" * 32}, NOW)
    store.set_sync_payload("policy_bundle_ack", {"status": "applied", "appliedAt": NOW, "bundleVersion": "7"}, NOW)
    store.set_sync_payload("policy_bundle_last_error", {"reason": "policy_bundle_signature_invalid"}, NOW)
    store.set_sync_payload("sync_summary", {"synced_at": "2026-10-14T11:00:00Z"}, NOW)

    code, payload = _json(capsys, home, "status", "--offline")
    text_code = main(["guard", "policy", "status", "--offline", "--home", str(home)])
    text = capsys.readouterr().out

    assert code == 0
    assert payload["live"]["version"] == "7"
    assert payload["lastSync"] == "2026-10-14T11:00:00Z"
    assert payload["lastAck"] == {"status": "applied", "appliedAt": NOW, "version": "7", "currentVersion": True}
    assert payload["rejectionReason"]
    assert payload["delivery"] == {"available": False, "reason": "offline"}
    assert text_code == 0
    assert "Live version: 7" in text
    assert "Last ACK: applied" in text
    assert "Rejection:" in text


def test_status_without_cloud_still_works_and_says_so(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, payload = _json(capsys, tmp_path / "home", "status")

    assert code == 0
    assert payload["live"]["version"] is None
    assert payload["delivery"]["available"] is False


def test_status_includes_cloud_delivery_for_this_device(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path / "home")
    delivery = {
        "available": True,
        "versionNumber": 8,
        "devices": [{"id": "a", "name": "laptop", "state": "applied", "reason": None}],
        "thisDevice": {"id": "a", "name": "laptop", "state": "rejected", "reason": "signature"},
    }
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.policy_delivery_status.fetch_policy_delivery", lambda _store: delivery
    )

    text = format_policy_status(policy_status_payload(store, offline=False))

    assert "Cloud version 8: 1 applied, 0 pending, 0 rejected" in text
    assert "This device: rejected (signature)" in text


def test_delivery_url_follows_the_receipts_sync_host() -> None:
    assert (
        normalized_policy_delivery_url("https://hol.example/api/guard/receipts/sync")
        == "https://hol.example/api/guard/policy/delivery"
    )
    assert (
        normalized_policy_delivery_url("https://hol.example/registry/api/v1/guard/receipts/sync")
        == "https://hol.example/registry/api/v1/guard/policy/delivery"
    )


def test_explain_decision_names_the_rule_that_decides_a_receipt(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    store = _install_scopes(home)
    _receipt(store, "receipt-1", harness="codex", artifact_id="pkg:npm/acme-reviewed", decision="warn")
    _receipt(store, "receipt-2", harness="codex", artifact_id="pkg:npm/unlisted", decision="allow")

    code, payload = _json(capsys, home, "explain", "receipt-1")
    default_code, default_payload = _json(capsys, home, "explain", "receipt-2")
    text_code = main(["guard", "policy", "explain", "receipt-1", "--home", str(home)])
    text = capsys.readouterr().out

    assert code == 0
    assert payload["decision"]["effect"] == "allow"
    assert payload["decision"]["ruleId"] == "allow-acme-reviewed"
    assert payload["receipt"]["recordedDecision"] == "warn"
    assert default_code == 0
    assert default_payload["decision"]["effect"] == "default"
    assert text_code == 0
    assert "allow-acme-reviewed" in text


def test_explain_decision_rejects_an_unknown_id(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, payload = _json(capsys, tmp_path / "home", "explain", "missing")

    assert code == 4
    assert payload["error"] == "decision_not_found"


def test_explain_without_an_id_still_summarizes_the_active_policy(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    _install_scopes(home)

    code, payload = _json(capsys, home, "explain")

    assert code == 0
    assert payload["rules"] > 0


def test_history_explain_shows_the_matched_rule(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    store = _install_scopes(tmp_path / "home")
    _receipt(store, "receipt-9", harness="codex", artifact_id="pkg:npm/acme-reviewed", decision="warn")
    args = argparse.Namespace(receipt_id="receipt-9", json=True, script=False, history_command="explain")

    assert _run_guard_history_command(args, store=store) == 0

    matched = json.loads(capsys.readouterr().out)["matched_rule"]
    assert matched["rule_id"] == "allow-acme-reviewed"
    assert matched["effect"] == "allow"
    assert matched["description"] is None
    assert matched["evaluated_against"] == "current_policy"


def test_history_explain_reports_no_rule_when_nothing_matches(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store = GuardStore(tmp_path / "home")
    _receipt(store, "receipt-0", harness="codex", artifact_id="pkg:npm/anything", decision="allow")
    args = argparse.Namespace(receipt_id="receipt-0", json=True, script=False, history_command="explain")

    assert _run_guard_history_command(args, store=store) == 0

    matched = json.loads(capsys.readouterr().out)["matched_rule"]
    assert matched["rule_id"] is None
    assert matched["effect"] == "default"


def test_diff_compares_against_the_live_policy(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "home"
    candidate = tmp_path / "candidate.yaml"
    shutil.copyfile(SCOPES, candidate)
    candidate.chmod(0o600)
    added_code, added = _json(capsys, home, "diff", str(candidate))
    _install_scopes(home)
    blank = tmp_path / "blank.yaml"
    assert main(["guard", "policy", "init", "--starter", "blank", "--output", str(blank)]) == 0
    capsys.readouterr()

    removed_code, removed = _json(capsys, home, "diff", str(blank))
    text_code = main(["guard", "policy", "diff", str(blank), "--home", str(home)])
    text = capsys.readouterr().out

    assert (added_code, added["changed"]) == (1, True)
    assert added["additions"]
    assert (removed_code, removed["changed"]) == (1, True)
    assert removed["removals"]
    assert text_code == 1
    assert "policy that is Live on this device" in text


def test_export_starts_with_the_schema_modeline_and_round_trips_through_fmt(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    exported = tmp_path / "exported.yaml"

    assert main(["guard", "policy", "export", "--home", str(home), "--output", str(exported)]) == 0
    capsys.readouterr()

    assert exported.read_text(encoding="utf-8").startswith(POLICY_MODELINE + "\n")
    assert main(["guard", "policy", "fmt", str(exported), "--check"]) == 0
    assert main(["guard", "policy", "validate", str(exported)]) == 0


def test_import_needs_no_environment_flag_and_dry_runs_by_default(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("HOL_GUARD_POLICY_YAML_IMPORT", raising=False)
    home = tmp_path / "home"
    source = tmp_path / "policy.yaml"
    shutil.copyfile(SCOPES, source)
    source.chmod(0o600)

    code, payload = _json(capsys, home, "import", str(source), "--replace")

    assert code == 0
    assert payload["dry_run"] is True
    assert payload["import_additions"]
    assert GuardStore(home).list_policy_decisions() == []


def test_import_apply_prints_the_diff_then_requires_confirmation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    source = tmp_path / "policy.yaml"
    shutil.copyfile(SCOPES, source)
    source.chmod(0o600)
    monkeypatch.setattr("sys.stdin", type("NoTty", (), {"isatty": lambda self: False, "read": lambda self, *_: ""})())

    code = main(["guard", "policy", "import", str(source), "--replace", "--apply", "--home", str(home)])
    output = capsys.readouterr().out

    assert code == 4
    assert "block-shell-in-ci" in output
    assert "--yes" in output
    assert GuardStore(home).list_policy_decisions() == []


def test_import_apply_with_yes_skips_the_confirmation_but_not_the_approval_gate(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    source = tmp_path / "policy.yaml"
    shutil.copyfile(SCOPES, source)
    source.chmod(0o600)
    gates: list[str] = []
    command = "codex_plugin_scanner.guard.cli.commands"

    def gate(*_args: object, **kwargs: object) -> object:
        gates.append(str(kwargs.get("summary")))
        return object()

    monkeypatch.setattr(f"{command}.prompt_for_approval_gate", gate)
    monkeypatch.setattr(f"{command}.require_high_risk", lambda *_a, **_k: None)

    code = main(["guard", "policy", "import", str(source), "--replace", "--apply", "--yes", "--home", str(home)])
    captured = capsys.readouterr().out

    assert code == 0, captured
    assert len(gates) == 1, captured
    assert GuardStore(home).list_policy_decisions()


def test_import_apply_can_be_declined_interactively(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    source = tmp_path / "policy.yaml"
    shutil.copyfile(SCOPES, source)
    source.chmod(0o600)
    monkeypatch.setattr("sys.stdin", type("Tty", (), {"isatty": lambda self: True})())
    monkeypatch.setattr("builtins.input", lambda _prompt="": "n")

    code = main(["guard", "policy", "import", str(source), "--replace", "--apply", "--home", str(home)])
    output = capsys.readouterr().out

    assert code == 4
    assert "block-shell-in-ci" in output
    assert "Import cancelled" in output
    assert GuardStore(home).list_policy_decisions() == []


def test_json_import_never_prompts_for_a_change_it_did_not_show(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    source = tmp_path / "policy.yaml"
    shutil.copyfile(SCOPES, source)
    source.chmod(0o600)
    monkeypatch.setattr("sys.stdin", type("Tty", (), {"isatty": lambda self: True})())

    def prompt(_prompt: str = "") -> str:
        raise AssertionError("JSON mode must not prompt")

    monkeypatch.setattr("builtins.input", prompt)

    code, payload = _json(capsys, home, "import", str(source), "--replace", "--apply")

    assert code == 4
    assert payload["error"] == "confirmation_required"
    assert GuardStore(home).list_policy_decisions() == []


def test_fmt_check_accepts_a_canonical_file_that_has_no_modeline(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exported = tmp_path / "exported.yaml"
    assert main(["guard", "policy", "export", "--home", str(tmp_path / "home"), "--output", str(exported)]) == 0
    capsys.readouterr()
    plain = tmp_path / "plain.yaml"
    plain.write_text(exported.read_text(encoding="utf-8").removeprefix(POLICY_MODELINE + "\n"), encoding="utf-8")
    plain.chmod(0o600)

    assert main(["guard", "policy", "fmt", str(plain), "--check"]) == 0
    capsys.readouterr()


def test_fmt_check_accepts_an_earlier_modeline_and_fmt_rewrites_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exported = tmp_path / "exported.yaml"
    assert main(["guard", "policy", "export", "--home", str(tmp_path / "home"), "--output", str(exported)]) == 0
    capsys.readouterr()
    current = exported.read_text(encoding="utf-8")
    legacy = tmp_path / "legacy.yaml"
    legacy.write_text(current.replace(POLICY_MODELINE, LEGACY_POLICY_MODELINES[0], 1), encoding="utf-8")
    legacy.chmod(0o600)

    assert main(["guard", "policy", "fmt", str(legacy), "--check"]) == 0
    assert main(["guard", "policy", "fmt", str(legacy)]) == 0
    capsys.readouterr()
    assert legacy.read_text(encoding="utf-8") == current


def test_status_reads_version_two_integer_versions_and_observed_at(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    store = GuardStore(home)
    store.set_sync_payload("policy_bundle", {"bundleVersion": 8, "bundleHash": "ab" * 32}, NOW)
    store.set_sync_payload("policy_bundle_ack", {"status": "applied", "observedAt": NOW, "bundleVersion": 8}, NOW)

    _, payload = _json(capsys, home, "status", "--offline")

    assert payload["live"]["version"] == "8"
    assert payload["lastAck"] == {"status": "applied", "appliedAt": NOW, "version": "8", "currentVersion": True}


def test_status_reports_the_locally_installed_policy(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    home = tmp_path / "home"
    _install_scopes(home)

    _, payload = _json(capsys, home, "status", "--offline")
    text_code = main(["guard", "policy", "status", "--offline", "--home", str(home)])
    text = capsys.readouterr().out

    assert payload["local"]["rules"] > 0
    assert payload["live"]["version"] is None
    assert text_code == 0
    assert f"Local policy: {payload['local']['documentId']}" in text


def test_status_never_repairs_sign_in_state_and_survives_runtime_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.policy_delivery_status import fetch_policy_delivery
    from codex_plugin_scanner.guard.runtime import runner

    def repair(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise AssertionError("status is a read and must not repair sign-in state")

    def unavailable(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise runner.GuardSyncNotAvailableError("rate limited", retryable=True)

    monkeypatch.setattr(runner, "prepare_guard_cloud_connect_authorization", repair)
    monkeypatch.setattr(runner, "_resolve_guard_sync_auth_context", unavailable)

    assert fetch_policy_delivery(GuardStore(tmp_path / "home")) == {"available": False, "reason": "unavailable"}


def test_history_explain_survives_a_policy_that_cannot_be_read(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.native_policy_snapshot_constants import NativePolicySnapshotError

    store = GuardStore(tmp_path / "home")
    _receipt(store, "receipt-3", harness="codex", artifact_id="pkg:npm/anything", decision="allow")

    def unreadable(_store: GuardStore) -> None:
        raise NativePolicySnapshotError("native_business_source_unreadable")

    monkeypatch.setattr("codex_plugin_scanner.guard.policy_decision_explain.active_policy_document", unreadable)
    args = argparse.Namespace(receipt_id="receipt-3", json=True, script=False, history_command="explain")

    assert _run_guard_history_command(args, store=store) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["matched_rule"]["note"] == "receipt_not_evaluable"
    assert payload["receipt"]["receipt_id"] == "receipt-3"


def test_receipt_explanations_say_publisher_and_workspace_scopes_were_not_replayed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "home"
    store = _install_scopes(home)
    _receipt(store, "receipt-4", harness="codex", artifact_id="pkg:npm/acme-reviewed", decision="warn")

    _, payload = _json(capsys, home, "explain", "receipt-4")

    assert payload["note"] == "publisher_and_workspace_scopes_not_replayed"
    assert payload["decision"]["ruleId"] == "allow-acme-reviewed"
