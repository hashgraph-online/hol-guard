"""Opt-in candidate proof through Python CLI, real resident and selected SDK."""

from __future__ import annotations

import argparse
import io
import json
import os
import subprocess
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.commands_parser import add_guard_root_parser
from codex_plugin_scanner.guard.cli.commands_router import run_guard_command
from codex_plugin_scanner.guard.native_resident_client import native_resident_client_failure_code


@pytest.mark.integration
@pytest.mark.skipif(
    not os.environ.get("GUARD_CIGAR_TEST_SELECTION") or not os.environ.get("GUARD_CIGAR_TEST_APPROVAL"),
    reason="requires explicitly selected and independently approved CIGAR 0.14.1 candidate",
)
def test_installed_candidate_via_public_context_cli(native_hook_force: Path, tmp_path: Path) -> None:
    parser = argparse.ArgumentParser()
    add_guard_root_parser(parser)

    def cli(action: str) -> dict[str, object]:
        args = parser.parse_args(["context", action, "--guard-home", str(tmp_path), "--json"])
        output = io.StringIO()
        result = run_guard_command(args, output_stream=output)
        assert result == 0, (
            f"CLI {action} failed: {output.getvalue()} resident_failure={native_resident_client_failure_code()}"
        )
        return json.loads(output.getvalue())

    def operator(command: str, request: dict[str, object]) -> dict[str, object]:
        result = subprocess.run(
            [str(native_hook_force), command, "--stdin"],
            input=json.dumps(request),
            text=True,
            capture_output=True,
            timeout=30,
        )
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)

    before = cli("status")
    assert before["availability"] == "off"
    assert before["runtime"] is None
    selection = json.loads(Path(os.environ["GUARD_CIGAR_TEST_SELECTION"]).read_text())
    approval = json.loads(Path(os.environ["GUARD_CIGAR_TEST_APPROVAL"]).read_text())
    enrollment = operator(
        "context-assistance-enroll-local",
        {
            "schema": "guard-cigar-enroll-local.v1",
            "guard_home": str(tmp_path),
            "runtime_id": "cli-candidate",
            "local_candidate_approved": True,
            "source_revision": "b47380e5a5cbeaaad5a61cab3372e9e67368732f",
            "selection": selection,
            "approval": approval,
        },
    )
    assert enrollment["ok"] is True
    assert enrollment["installation"]["activation_granted"] is False
    choices = cli("runtimes")["installation_options"]
    assert choices[0]["runtime_id"] == "cli-candidate"
    assert selection["site_packages"] not in json.dumps(choices)
    updated = operator(
        "guard-config-update",
        {
            "schema": "guard-config-update.v1",
            "guard_home": str(tmp_path),
            "kind": "settings",
            "value_text": json.dumps({"context_assistance": {"enabled": True, "runtime_id": "cli-candidate"}}),
        },
    )
    assert updated["ok"] is True
    assert cli("status")["effective_enabled"] is False
    try:
        cli("start")
        deadline = time.monotonic() + 30
        while True:
            observed = cli("status")
            if observed["job"] is None:
                break
            assert time.monotonic() < deadline, "CLI runtime verification did not finish"
            time.sleep(0.05)
        assert observed["effective_enabled"] is True, observed
        assert observed["runtime"]["interpreter"]["version"][:2] == [3, 14]
        assert observed["runtime"]["worker_fingerprint"] == approval["worker_sha256"]
    finally:
        stopped = cli("off")
        assert stopped["requested_enabled"] is False
        assert stopped["effective_enabled"] is False
    assert cli("status")["runtime"] is None
    from codex_plugin_scanner.guard.native_context_assistance import ContextAssistanceError, control

    with pytest.raises(ContextAssistanceError) as refusal:
        control("activate", guard_home=tmp_path, payload={"python_version": [3, 14], "approved": True})
    assert refusal.value.code == "native_context_assistance_control_input_invalid"
    print(
        "GUARD_CIGAR_CLI_VERIFICATION="
        + json.dumps(
            {
                "schema": "guard-cigar-public-cli-verification.v1",
                "status": "passed",
                "qualification": "local-development-darwin-arm64-only",
                "worker_fingerprint": approval["worker_sha256"],
                "final_effective_enabled": False,
                "checks": [
                    "public_cli_off_state",
                    "actual_candidate_enrollment",
                    "metadata_only_setup",
                    "native_opt_in",
                    "public_cli_background_activation",
                    "actual_python_314_worker",
                    "public_cli_persisted_opt_out",
                ],
            }
        )
    )
