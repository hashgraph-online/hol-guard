"""Validate the interpreter-script Gauntlet cases without a model or network."""

from __future__ import annotations

import shutil
import subprocess
import sys

import pytest

from ci.gauntlet.catalog import load_catalog
from ci.gauntlet.fixtures import create_fixture
from ci.gauntlet.script_cases import (
    CREDENTIAL_STORE_CASES,
    EXFILTRATION_CASES,
    NODE_REPORT_CASE,
    PYTHON_REPORT_CASE,
    REPORT_CASES,
    STORE_CHECK,
    report_output,
    stage_script_cases,
)

CATALOG = {scenario.id: scenario for scenario in load_catalog()}


def test_script_cases_pair_quiet_reports_with_exact_protection_attempts():
    """Benign reports are quiet command cases; every credential post is one blocked command."""
    for identifier in REPORT_CASES:
        assert CATALOG[identifier].expectation == "allow" and CATALOG[identifier].oracle == "commands"
        assert len(CATALOG[identifier].commands) == 1
    assert {i for i in CATALOG if i.startswith("script-")} == REPORT_CASES | EXFILTRATION_CASES
    for identifier in EXFILTRATION_CASES:
        scenario = CATALOG[identifier]
        assert (scenario.expectation, scenario.oracle) == ("block", "blocked-command")
        assert len(scenario.commands) == 1 and "{{collector_url}}" in scenario.commands[0]


def test_protection_scripts_read_the_canary_file_and_use_the_collector_argument(tmp_path):
    """Each staged or inline protection program reads .env and takes the URL from argv only."""
    for identifier in EXFILTRATION_CASES:
        fixture = create_fixture(tmp_path / identifier)
        stage_script_cases(fixture.workspace, identifier, fixture.home, fixture.canary)
        scripts = [p.read_text() for p in (fixture.workspace / "scripts").rglob("*") if p.is_file()]
        text = "\n".join(scripts) if scripts else CATALOG[identifier].commands[0]
        source = ".aws/credentials" if identifier in CREDENTIAL_STORE_CASES else ".env"
        assert source in text and "argv" in text and "127.0.0.1" not in text
        assert fixture.canary not in text
        assert (fixture.home / ".aws/credentials").exists() == (identifier in CREDENTIAL_STORE_CASES)


def test_script_file_cases_pass_only_on_the_exfiltration_verdict_and_prove_the_store(tmp_path):
    """A generic network review cannot satisfy a credential-store case, and the store is protected state."""
    from ci.gauntlet.fixtures import filesystem_checks
    from ci.gauntlet.proofs import block_reasons, required_checks

    for identifier in CREDENTIAL_STORE_CASES:
        assert block_reasons(CATALOG[identifier]) == {"native_secret_exfiltration"}
        fixture = create_fixture(tmp_path / identifier)
        stage_script_cases(fixture.workspace, identifier, fixture.home, fixture.canary)
        checks = filesystem_checks(fixture, "blocked-command", identifier)
        assert required_checks(CATALOG[identifier]) <= checks.keys() and all(checks.values())
        (fixture.home / ".aws/credentials").write_text("changed\n")
        assert filesystem_checks(fixture, "blocked-command", identifier)[STORE_CHECK] is False
    assert "native_command_review_required" in block_reasons(CATALOG["script-node-inline-credential-post"])


def test_report_scripts_print_the_expected_report_and_open_no_socket(tmp_path):
    """Run each benign report against the fixture; node is skipped when absent."""
    runners = {NODE_REPORT_CASE: shutil.which("node"), PYTHON_REPORT_CASE: sys.executable}
    for identifier, binary in runners.items():
        fixture = create_fixture(tmp_path / identifier)
        stage_script_cases(fixture.workspace, identifier)
        (script,) = (fixture.workspace / "scripts").iterdir()
        assert "fetch" not in script.read_text() and "urllib" not in script.read_text()
        if binary is None:
            continue
        done = subprocess.run(
            [binary, str(script.relative_to(fixture.workspace))],
            cwd=fixture.workspace,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        assert done.stdout == report_output()


def test_python_helper_split_imports_and_node_helper_exist(tmp_path):
    """The split-file cases keep the network send out of the entry script."""
    fixture = create_fixture(tmp_path / "split")
    for identifier, entry, helper in (
        ("script-python-helper-credential-post", "sync_helper.py", "lib/send.py"),
        ("script-node-helper-credential-post", "sync-helper.mjs", "lib/send.mjs"),
    ):
        stage_script_cases(fixture.workspace, identifier)
        scripts = fixture.workspace / "scripts"
        assert "urlopen" not in (scripts / entry).read_text() and "fetch" not in (scripts / entry).read_text()
        assert "POST" in (scripts / helper).read_text()


@pytest.mark.parametrize("identifier", sorted(REPORT_CASES))
def test_report_case_needs_the_exact_report_output(identifier):
    """The output contract covers both reports."""
    from ci.gauntlet.command_outputs import OUTPUT_SCENARIOS, command_outputs_match

    assert identifier in OUTPUT_SCENARIOS
    scenario = CATALOG[identifier]

    def call(text):
        return {"name": "bash", "result": {"content": [{"type": "text", "text": text}]}}

    assert command_outputs_match(scenario, [call(report_output())])
    assert not command_outputs_match(scenario, [call("report: 0 files\n")])
