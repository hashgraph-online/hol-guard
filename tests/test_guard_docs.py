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
