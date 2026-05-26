"""Generated Guard install/connect docs contract tests."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli.docs import install_connect_command_catalog

REPO_ROOT = Path(__file__).resolve().parents[1]


def _read_repo_file(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def test_explain_install_connect_shares_canonical_command_catalog(capsys) -> None:
    rc = main(["guard", "explain", "install-connect", "--json"])
    output = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert output["target"] == "install-connect"
    assert output["category"] == "guard-docs"
    assert output["commands"] == [item.to_dict() for item in install_connect_command_catalog()]
    assert output["share_commands"]["terminal"] == "hol-guard explain install-connect"
    assert output["share_commands"]["cloud"] == "hol-guard connect status"


def test_static_docs_include_canonical_install_connect_commands() -> None:
    docs_text = "\n".join(
        [
            _read_repo_file("README.md"),
            _read_repo_file("docs/guard/get-started.md"),
            _read_repo_file("docs/guard/local-vs-cloud.md"),
            _read_repo_file("docs/guard/testing-matrix.md"),
        ]
    )

    for item in install_connect_command_catalog():
        assert item.command in docs_text


def test_static_docs_make_init_the_first_run_path() -> None:
    readme_text = _read_repo_file("README.md")
    get_started_text = _read_repo_file("docs/guard/get-started.md")

    readme_quickstart = readme_text.split("## Guard Quickstart", 1)[1].split(
        "Manual and follow-up commands:",
        1,
    )[0]
    everyday_flow = get_started_text.split("## The everyday flow", 1)[1].split(
        "## Which command should I use?",
        1,
    )[0]
    first_step = everyday_flow.split("2. Alternatively", 1)[0]

    assert "hol-guard init" in readme_quickstart
    assert "hol-guard init" in first_step
    assert "hol-guard bootstrap" not in first_step
    assert "first-run" in readme_text.lower()
    assert "first-run" in get_started_text.lower()
    assert "gates each side effect" in readme_text
    assert "Nothing opens or changes until you approve" in get_started_text
    assert "reports completion before the next prompt appears" in get_started_text
    assert "hol-guard init --yes" in get_started_text
    assert "desktop notification" in get_started_text.lower()


def test_static_docs_explain_safe_decode_sandbox_guarantee() -> None:
    docs_text = "\n".join(
        [
            _read_repo_file("docs/guard/architecture.md"),
            _read_repo_file("docs/guard/local-vs-cloud.md"),
        ]
    ).lower()

    assert "safe decode" in docs_text
    assert "never executes decoded payloads" in docs_text
    assert "base64" in docs_text
    assert "powershell" in docs_text


def test_static_docs_cover_supply_chain_support_levels() -> None:
    docs_text = "\n".join(
        [
            _read_repo_file("docs/guard/get-started.md"),
            _read_repo_file("docs/guard/testing-matrix.md"),
        ]
    ).lower()

    assert "hol-guard cloud sync-intel" in docs_text
    assert "protected" in docs_text
    assert "beta" in docs_text
    assert "monitor-only" in docs_text


def test_static_docs_cover_local_supply_chain_firewall_commands() -> None:
    docs_text = "\n".join(
        [
            _read_repo_file("README.md"),
            _read_repo_file("docs/guard/get-started.md"),
            _read_repo_file("docs/guard/local-vs-cloud.md"),
        ]
    ).lower()

    assert "hol-guard supply-chain scan" in docs_text
    assert "hol-guard supply-chain explain" in docs_text
    assert "hol-guard protect" in docs_text


def test_static_docs_cover_ci_wrapper_examples() -> None:
    docs_text = "\n".join(
        [
            _read_repo_file("README.md"),
            _read_repo_file("docs/guard/get-started.md"),
            _read_repo_file("docs/guard/testing-matrix.md"),
        ]
    ).lower()

    assert "hol-guard protect -- npm ci" in docs_text
    assert "install dependencies through hol guard" in docs_text
    assert ".github/workflows" in docs_text


def test_static_docs_include_skill_guidance_for_package_install_workflows() -> None:
    docs_text = "\n".join(
        [
            _read_repo_file("docs/guard/SKILL.md"),
            _read_repo_file("docs/guard/get-started.md"),
        ]
    ).lower()

    assert "before package installs" in docs_text
    assert "hol-guard protect --dry-run -- npm install" in docs_text
    assert "hol-guard supply-chain audit --json" in docs_text


def test_static_docs_cover_false_positive_remediation_and_incident_response() -> None:
    docs_text = "\n".join(
        [
            _read_repo_file("docs/guard/remediation.md"),
            _read_repo_file("docs/guard/incident-response.md"),
            _read_repo_file("docs/guard/get-started.md"),
        ]
    ).lower()

    assert "verified false positive" in docs_text
    assert "expiring exception" in docs_text
    assert "blocked malware" in docs_text
    assert "supply-chain audit --json" in docs_text
