"""End-to-end coverage for ``hol-guard plugin`` through the native runtime.

Detection, checks and emitter output are pinned by the Rust golden fixtures in
``rust/crates/guard-plugin-kit/tests/fixtures``; these tests cover the
argument handling, rendering and exit codes of the Python shim.
"""

from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner import cli as guard_cli
from codex_plugin_scanner.guard import config as guard_config
from codex_plugin_scanner.guard import native_runtime
from codex_plugin_scanner.guard.plugin_kit import cli as plugin_kit_cli


@pytest.fixture(autouse=True)
def _guard_home(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path_factory.mktemp("guard-home")
    monkeypatch.setattr(guard_config, "resolve_guard_home", lambda override=None: home)
    return home


def _run(argv: list[str]) -> tuple[int, str, str]:
    output = io.StringIO()
    error = io.StringIO()
    original_argv = guard_cli.sys.argv
    try:
        guard_cli.sys.argv = ["hol-guard"]
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            exit_code = guard_cli.main(argv)
    finally:
        guard_cli.sys.argv = original_argv
    return exit_code, output.getvalue(), error.getvalue()


def _write_plugin(root: Path) -> None:
    (root / ".claude-plugin").mkdir(parents=True)
    (root / ".claude-plugin" / "plugin.json").write_text(
        json.dumps(
            {
                "name": "notes-kit",
                "version": "1.0.0",
                "description": "Search and edit notes.",
                "license": "MIT",
                "repository": "https://github.com/acme/notes-kit",
            }
        ),
        encoding="utf-8",
    )
    (root / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"notes": {"command": "npx", "args": ["-y", "@acme/notes-mcp"]}}}),
        encoding="utf-8",
    )
    skill = root / "skills" / "notes"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text(
        "---\nname: notes\ndescription: Use when the user asks about their notes.\n---\nBody.\n",
        encoding="utf-8",
    )


def test_check_reports_runtimes_and_passes(tmp_path: Path) -> None:
    _write_plugin(tmp_path)
    exit_code, output, error = _run(["plugin", "check", str(tmp_path), "--json"])
    assert (exit_code, error) == (0, "")
    payload = json.loads(output)
    assert payload["passed"] is True
    supported = [item["runtime"] for item in payload["runtimes"] if item["supported"]]
    assert {"claude-code", "codex", "cursor", "vscode", "opencode", "agent-skills"} <= set(supported)


def test_check_fails_with_exit_one_and_names_the_problem(tmp_path: Path) -> None:
    (tmp_path / ".claude-plugin").mkdir()
    (tmp_path / ".claude-plugin" / "plugin.json").write_text('{"name": "Bad Name"}', encoding="utf-8")
    exit_code, output, _error = _run(["plugin", "check", str(tmp_path)])
    assert exit_code == 1
    assert "name_not_kebab" in output
    assert "description_missing" in output
    assert "Check failed" in output


def test_package_writes_each_runtime_then_refuses_to_overwrite(tmp_path: Path) -> None:
    source = tmp_path / "source"
    _write_plugin(source)
    out = tmp_path / "out"
    exit_code, output, error = _run(["plugin", "package", str(source), "--out", str(out)])
    assert (exit_code, error) == (0, ""), output
    assert (out / "codex" / ".codex-plugin" / "plugin.json").is_file()
    assert (out / "cursor" / ".cursor" / "mcp.json").is_file()
    assert (out / "hol.provenance.json").is_file()
    exit_code, _output, error = _run(["plugin", "package", str(source), "--out", str(out)])
    assert exit_code == 2
    assert "--force" in error


def test_package_limits_to_requested_runtimes_and_rejects_unknown(tmp_path: Path) -> None:
    source = tmp_path / "source"
    _write_plugin(source)
    out = tmp_path / "out"
    exit_code, _output, _error = _run(
        ["plugin", "package", str(source), "--out", str(out), "--runtimes", "codex,vscode"]
    )
    assert exit_code == 0
    assert sorted(path.name for path in out.iterdir()) == ["codex", "hol.provenance.json", "vscode"]
    exit_code, _output, error = _run(["plugin", "package", str(source), "--runtimes", "windsurf"])
    assert exit_code == 2
    assert "Unknown runtime" in error


def test_package_rejects_an_empty_runtime_list_and_an_unsupported_runtime(tmp_path: Path) -> None:
    source = tmp_path / "source"
    _write_plugin(source)
    with pytest.raises(SystemExit) as raised:
        _run(["plugin", "package", str(source), "--runtimes", " , "])
    assert raised.value.code == 2
    skills_only = tmp_path / "skills-only"
    (skills_only / "skills" / "notes").mkdir(parents=True)
    (skills_only / "skills" / "notes" / "SKILL.md").write_text(
        "---\nname: notes\ndescription: Use for notes.\n---\nBody.\n",
        encoding="utf-8",
    )
    exit_code, _output, error = _run(["plugin", "package", str(skills_only), "--runtimes", "cursor"])
    assert exit_code == 2
    assert "cannot load this plugin" in error
    assert not (skills_only / "dist").exists()


def test_init_refuses_a_folder_that_already_holds_work(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# New\n", encoding="utf-8")
    (tmp_path / "main.py").write_text("print()\n", encoding="utf-8")
    exit_code, _output, error = _run(["plugin", "init", str(tmp_path), "--name", "hello-kit"])
    assert exit_code == 2
    assert "new folder" in error
    assert not (tmp_path / ".claude-plugin").exists()


def test_init_scaffolds_then_links_print_install_commands(tmp_path: Path) -> None:
    exit_code, output, error = _run(["plugin", "init", str(tmp_path), "--name", "hello-kit"])
    assert (exit_code, error) == (0, "")
    assert "skills/hello-kit/SKILL.md" in output
    exit_code, _output, error = _run(["plugin", "init", str(tmp_path), "--name", "hello-kit"])
    assert exit_code == 2
    assert "never overwrites" in error

    _write_plugin(tmp_path / "published")
    exit_code, output, _error = _run(["plugin", "links", str(tmp_path / "published")])
    assert exit_code == 0
    assert "npx skills add acme/notes-kit" in output
    assert "https://hol.org/plugins/connect?repo=acme/notes-kit&utm_source=hol-guard" in output


def test_plugin_fails_closed_without_native_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unavailable = SimpleNamespace(available=False, compatible=False, identity=None, capabilities=None)
    monkeypatch.setattr(native_runtime, "native_runtime_status", lambda **_kwargs: unavailable)
    exit_code, output, error = _run(["plugin", "check", str(tmp_path)])
    assert (exit_code, output) == (2, "")
    assert "requires the Guard native runtime" in error


def test_unknown_native_errors_are_printed_as_codes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(plugin_kit_cli, "_native_request", lambda _request: {"ok": False, "error": "new_code"})
    exit_code, _output, error = _run(["plugin", "links"])
    assert exit_code == 2
    assert "new_code" in error


def test_guard_offer_prints_once_and_never_in_json(tmp_path: Path) -> None:
    _write_plugin(tmp_path)
    _exit_code, output, _error = _run(["plugin", "check", str(tmp_path), "--json"])
    assert "hol-guard install" not in output
    _exit_code, output, _error = _run(["plugin", "check", str(tmp_path)])
    assert "hol-guard install claude-code" in output
    _exit_code, output, _error = _run(["plugin", "check", str(tmp_path)])
    assert "hol-guard install" not in output


def test_links_carry_campaign_attribution(tmp_path: Path) -> None:
    _write_plugin(tmp_path)
    _exit_code, output, _error = _run(["plugin", "links", str(tmp_path), "--json"])
    hol = json.loads(output)["hol"]
    assert hol["connect"].endswith("repo=acme/notes-kit&utm_source=hol-guard&utm_medium=cli&utm_campaign=plugin-kit")


def test_links_block_prints_only_the_readme_block(tmp_path: Path) -> None:
    _write_plugin(tmp_path)
    exit_code, _output, error = _run(["plugin", "links", str(tmp_path), "--block"])
    assert exit_code == 1
    assert "No install block" in error

    (tmp_path / ".claude-plugin" / "marketplace.json").write_text(
        json.dumps({"name": "acme", "plugins": [{"name": "notes-kit", "source": "./"}]}), encoding="utf-8"
    )
    exit_code, output, _error = _run(["plugin", "links", str(tmp_path), "--block"])
    assert exit_code == 0
    assert output.startswith("<!-- hol-install-block:v1 slug=acme/notes-kit -->\n")
    assert "hol-guard plugin install acme/notes-kit --apply" in output
    assert "Claim the HOL listing" not in output

    _exit_code, output, _error = _run(["plugin", "links", str(tmp_path), "--block", "--slug", "acme/notes"])
    assert "hol-guard plugin install acme/notes --apply" in output
    exit_code, _output, error = _run(["plugin", "links", str(tmp_path), "--block", "--slug", "../notes"])
    assert exit_code == 2
    assert "Use a HOL listing slug" in error


def test_convert_to_agent_plugins_writes_a_conforming_package(tmp_path: Path) -> None:
    source = tmp_path / "source"
    _write_plugin(source)
    out = tmp_path / "out"
    exit_code, output, error = _run(["plugin", "convert", str(source), "--to", "agent-plugins", "--out", str(out)])
    assert (exit_code, error) == (0, ""), output
    package = out / "agent-plugins"
    manifest = json.loads((package / "plugin.json").read_text(encoding="utf-8"))
    assert manifest["$schema"].startswith("https://agent-plugins.org/schemas/1.0.0/")
    assert json.loads((package / "mcp.json").read_text(encoding="utf-8"))["mcpServers"] == {
        "notes": {"type": "stdio", "command": "npx", "args": ["-y", "@acme/notes-mcp"]}
    }
    assert (package / "skills" / "notes" / "SKILL.md").is_file()
    assert "conforms to agent-plugins-1.0: 0 errors, 0 warnings" in output

    exit_code, output, error = _run(["plugin", "check", str(package), "--spec", "agent-plugins-1.0", "--json"])
    assert (exit_code, error) == (0, ""), output
    assert json.loads(output)["passed"] is True


def test_check_spec_names_the_section_a_plugin_breaks(tmp_path: Path) -> None:
    (tmp_path / "plugin.json").write_text(
        json.dumps({"$schema": "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json", "name": "Bad Name"}),
        encoding="utf-8",
    )
    exit_code, output, _error = _run(["plugin", "check", str(tmp_path), "--spec", "agent-plugins-1.0"])
    assert exit_code == 1
    assert "name_invalid" in output
    assert "(section " in output
    assert "Clients reject the whole plugin." in output
    assert "does not conform to agent-plugins-1.0" in output


def test_convert_rejects_an_unknown_target(tmp_path: Path) -> None:
    _write_plugin(tmp_path)
    exit_code, _output, error = _run(["plugin", "convert", str(tmp_path), "--to", "zed"])
    assert exit_code == 2
    assert "agent-plugins" in error


def test_card_prints_only_json_on_stdout_and_links_the_listing(tmp_path: Path) -> None:
    _write_plugin(tmp_path)
    exit_code, output, error = _run(["plugin", "card", str(tmp_path)])
    assert exit_code == 0
    card = json.loads(output)
    assert card["schema"] == "hol.plugin-card.v0-draft"
    assert card["identity"] == {"repository": "acme/notes-kit", "verified": False}
    assert card["permissions"]["startsPrograms"] == ["npx"]
    assert card["links"]["listing"] == "https://hol.org/registry/plugins/acme%2Fnotes-kit"
    assert ".well-known/hol-plugin-card.json" in error

    _exit_code, output, _error = _run(["plugin", "card", str(tmp_path), "--slug", "acme/notes"])
    assert json.loads(output)["links"]["listing"] == "https://hol.org/registry/plugins/acme%2Fnotes"
    exit_code, _output, error = _run(["plugin", "card", str(tmp_path), "--slug", "../notes"])
    assert exit_code == 2
    assert "Use a HOL listing slug" in error
