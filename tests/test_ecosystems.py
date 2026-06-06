"""Tests for multi-ecosystem adapter detection and scanning."""

import json
import shutil
from pathlib import Path

import pytest

from codex_plugin_scanner.checks.gemini import check_context_and_mcp
from codex_plugin_scanner.checks.opencode import check_opencode_config, check_opencode_plugins
from codex_plugin_scanner.cli import main
from codex_plugin_scanner.ecosystems.claude import ClaudeAdapter
from codex_plugin_scanner.ecosystems.detect import detect_packages
from codex_plugin_scanner.ecosystems.opencode import OpenCodeAdapter
from codex_plugin_scanner.ecosystems.types import Ecosystem, NormalizedPackage
from codex_plugin_scanner.models import ScanOptions
from codex_plugin_scanner.scanner import scan_plugin

FIXTURES = Path(__file__).parent / "fixtures"


def _symlink_or_skip(link_path: Path, target: Path) -> None:
    link_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        link_path.symlink_to(target, target_is_directory=target.is_dir())
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are not supported in this environment")


def test_detect_claude_package() -> None:
    packages = detect_packages(FIXTURES / "claude-plugin-good")
    ecosystems = {package.ecosystem for package in packages}
    assert Ecosystem.CLAUDE in ecosystems


def test_detect_gemini_package() -> None:
    packages = detect_packages(FIXTURES / "gemini-extension-good")
    ecosystems = {package.ecosystem for package in packages}
    assert Ecosystem.GEMINI in ecosystems


def test_detect_opencode_package() -> None:
    packages = detect_packages(FIXTURES / "opencode-good")
    ecosystems = {package.ecosystem for package in packages}
    assert Ecosystem.OPENCODE in ecosystems


def test_detect_packages_skips_symlinked_manifest_files_outside_root(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-ecosystem-manifests"
    shutil.rmtree(outside, ignore_errors=True)
    outside.mkdir(parents=True, exist_ok=True)
    (outside / "plugin.json").write_text("{}", encoding="utf-8")
    (outside / "marketplace.json").write_text("{}", encoding="utf-8")
    (outside / "gemini-extension.json").write_text("{}", encoding="utf-8")
    (outside / "opencode.json").write_text("{}", encoding="utf-8")

    _symlink_or_skip(tmp_path / "codex-plugin" / ".codex-plugin" / "plugin.json", outside / "plugin.json")
    _symlink_or_skip(tmp_path / "claude-plugin" / ".claude-plugin" / "plugin.json", outside / "plugin.json")
    _symlink_or_skip(tmp_path / "claude-market" / ".claude-plugin" / "marketplace.json", outside / "marketplace.json")
    _symlink_or_skip(tmp_path / "gemini-ext" / "gemini-extension.json", outside / "gemini-extension.json")
    _symlink_or_skip(tmp_path / "opencode-workspace" / "opencode.json", outside / "opencode.json")

    assert detect_packages(tmp_path) == []


def test_detect_packages_skips_nested_symlinked_directories_outside_root(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-ecosystem-dir"
    shutil.rmtree(outside, ignore_errors=True)
    (outside / "nested" / ".codex-plugin").mkdir(parents=True, exist_ok=True)
    (outside / "nested" / ".codex-plugin" / "plugin.json").write_text("{}", encoding="utf-8")

    _symlink_or_skip(tmp_path / "linked" / "outside", outside)

    assert detect_packages(tmp_path) == []


def test_detect_packages_ignores_unreadable_entries_without_crashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    good_manifest = tmp_path / "good-plugin" / ".codex-plugin" / "plugin.json"
    good_manifest.parent.mkdir(parents=True, exist_ok=True)
    good_manifest.write_text("{}", encoding="utf-8")
    blocked_dir = tmp_path / "blocked"
    blocked_dir.mkdir()

    original_iterdir = Path.iterdir

    def _guarded_iterdir(self: Path):
        if self == blocked_dir:
            raise OSError("denied")
        yield from original_iterdir(self)

    monkeypatch.setattr(Path, "iterdir", _guarded_iterdir)

    packages = detect_packages(tmp_path)

    assert len(packages) == 1
    assert packages[0].ecosystem == Ecosystem.CODEX


def test_claude_parse_skips_symlinked_component_files_outside_root(tmp_path: Path) -> None:
    manifest_path = tmp_path / ".claude-plugin" / "plugin.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text("{}", encoding="utf-8")
    commands_dir = tmp_path / "commands"
    commands_dir.mkdir()
    (commands_dir / "safe.md").write_text("safe", encoding="utf-8")
    outside = tmp_path.parent / "outside-command.md"
    outside.write_text("secret", encoding="utf-8")
    _symlink_or_skip(commands_dir / "escape.md", outside)

    candidate = ClaudeAdapter().detect(tmp_path)[0]
    package = ClaudeAdapter().parse(candidate)

    assert package.components["commands"] == ("commands/safe.md",)


def test_scan_claude_with_explicit_ecosystem() -> None:
    result = scan_plugin(
        FIXTURES / "claude-plugin-good",
        ScanOptions(ecosystem="claude", cisco_skill_scan="off"),
    )
    assert "claude" in result.ecosystems
    assert any(category.name.endswith("Claude Plugin") for category in result.categories)
    assert result.score > 0


def test_scan_gemini_with_explicit_ecosystem() -> None:
    result = scan_plugin(
        FIXTURES / "gemini-extension-good",
        ScanOptions(ecosystem="gemini", cisco_skill_scan="off"),
    )
    assert "gemini" in result.ecosystems
    assert any(category.name.endswith("Gemini Extension") for category in result.categories)
    assert result.score > 0


def test_scan_opencode_with_explicit_ecosystem() -> None:
    result = scan_plugin(
        FIXTURES / "opencode-good",
        ScanOptions(ecosystem="opencode", cisco_skill_scan="off"),
    )
    assert "opencode" in result.ecosystems
    assert any(category.name.endswith("OpenCode Plugin") for category in result.categories)
    assert result.score > 0


def test_scan_auto_detects_multiple_packages() -> None:
    result = scan_plugin(
        FIXTURES / "multi-ecosystem-repo",
        ScanOptions(ecosystem="auto", cisco_skill_scan="off"),
    )
    assert result.scope == "repository"
    assert set(result.ecosystems) >= {"codex", "gemini"}
    assert len(result.packages) >= 2
    assert any(category.name.startswith("[codex:") for category in result.categories)
    assert any(category.name.startswith("[gemini:") for category in result.categories)


def test_scan_auto_repository_includes_non_codex_packages(tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    shutil.copytree(FIXTURES / "multi-plugin-repo", repo_root)
    gemini_root = repo_root / "gemini-ext"
    gemini_root.mkdir(parents=True, exist_ok=True)
    (gemini_root / "README.md").write_text("Gemini extension", encoding="utf-8")
    (gemini_root / "gemini-extension.json").write_text(
        json.dumps(
            {
                "name": "demo-gemini",
                "version": "1.0.0",
                "commands": [{"name": "echo", "description": "Echo command", "prompt": "hi"}],
            }
        ),
        encoding="utf-8",
    )

    result = scan_plugin(repo_root, ScanOptions(ecosystem="auto", cisco_skill_scan="off"))

    assert result.scope == "repository"
    assert result.marketplace_file is not None
    assert len(result.plugin_results) == 2
    assert {plugin.plugin_name for plugin in result.plugin_results} == {"alpha-plugin", "beta-plugin"}
    assert any(skip.name == "remote-plugin" for skip in result.skipped_targets)
    assert set(result.ecosystems) >= {"codex", "gemini"}
    assert any(category.name.startswith("[gemini:") for category in result.categories)
    assert all(finding.rule_id != "PLUGIN_JSON_MISSING" for finding in result.findings)


def test_mixed_scan_rebases_findings_to_scan_root() -> None:
    result = scan_plugin(
        FIXTURES / "multi-ecosystem-repo",
        ScanOptions(ecosystem="auto", cisco_skill_scan="off"),
    )
    file_paths = {finding.file_path for finding in result.findings if finding.file_path}

    assert any(path.startswith("codex-plugin/") for path in file_paths)
    assert ".codex-plugin/plugin.json" not in file_paths
    assert "SECURITY.md" not in file_paths


def test_cli_lists_supported_ecosystems(capsys) -> None:
    rc = main(["--list-ecosystems"])
    captured = capsys.readouterr()
    assert rc == 0
    assert "codex" in captured.out
    assert "claude" in captured.out
    assert "gemini" in captured.out
    assert "opencode" in captured.out


def test_opencode_jsonc_allows_inline_comments(tmp_path: Path) -> None:
    (tmp_path / ".opencode" / "commands").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".opencode" / "commands" / "hello.md").write_text(
        "---\nname: hello\ndescription: test\n---\nrun\n",
        encoding="utf-8",
    )
    (tmp_path / "opencode.jsonc").write_text(
        '{\n  "name": "demo", // inline comment\n  "version": "1.0.0"\n}\n',
        encoding="utf-8",
    )

    result = scan_plugin(tmp_path, ScanOptions(ecosystem="opencode", cisco_skill_scan="off"))

    assert "opencode" in result.ecosystems
    assert all(finding.rule_id != "OPENCODE_CONFIG_INVALID" for finding in result.findings)


def test_opencode_empty_object_config_is_not_marked_invalid(tmp_path: Path) -> None:
    (tmp_path / "opencode.json").write_text("{}", encoding="utf-8")

    result = scan_plugin(tmp_path, ScanOptions(ecosystem="opencode", cisco_skill_scan="off"))

    assert all(finding.rule_id != "OPENCODE_CONFIG_INVALID" for finding in result.findings)


def test_opencode_jsonc_keeps_block_comment_literals_inside_strings(tmp_path: Path) -> None:
    (tmp_path / ".opencode" / "commands").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".opencode" / "commands" / "hello.md").write_text(
        "---\nname: hello\ndescription: test\n---\nrun\n",
        encoding="utf-8",
    )
    (tmp_path / "opencode.jsonc").write_text(
        '{\n  "name": "a/*b*/c",\n  "version": "1.0.0",\n  /* remove this comment */\n  "description": "demo"\n}\n',
        encoding="utf-8",
    )

    result = scan_plugin(tmp_path, ScanOptions(ecosystem="opencode", cisco_skill_scan="off"))

    assert all(finding.rule_id != "OPENCODE_CONFIG_INVALID" for finding in result.findings)
    assert result.packages and result.packages[0].name == "a/*b*/c"


def test_opencode_permission_error_sets_specific_parse_reason(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_path = tmp_path / "opencode.json"
    config_path.write_text('{"name":"demo"}', encoding="utf-8")

    def _deny_read(self: Path, encoding: str = "utf-8") -> str:  # pragma: no cover - monkeypatched path
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "read_text", _deny_read)
    candidate = OpenCodeAdapter().detect(tmp_path)[0]
    package = OpenCodeAdapter().parse(candidate)
    check = check_opencode_config(package)

    assert package.manifest_parse_error is True
    assert package.manifest_parse_error_reason == "permission-denied"
    assert check.passed is False
    assert "permissions" in check.message


def test_gemini_context_file_outside_repo_is_rejected_even_when_it_exists(tmp_path: Path) -> None:
    outside_file = tmp_path.parent / "outside-context.md"
    outside_file.write_text("secret", encoding="utf-8")
    package = NormalizedPackage(
        ecosystem=Ecosystem.GEMINI,
        package_kind="extension",
        root_path=tmp_path,
        raw_manifest={"contextFileName": "../outside-context.md"},
    )

    result = check_context_and_mcp(package)

    assert result.passed is False
    assert any("contextFileName" in finding.description for finding in result.findings)


def test_opencode_plugin_reference_outside_repo_is_rejected_even_when_it_exists(tmp_path: Path) -> None:
    outside_plugin = tmp_path.parent / "outside-plugin"
    outside_plugin.write_text("{}", encoding="utf-8")
    package = NormalizedPackage(
        ecosystem=Ecosystem.OPENCODE,
        package_kind="plugin",
        root_path=tmp_path,
        manifest_path=tmp_path / "opencode.json",
        raw_manifest={"plugins": ["../outside-plugin"]},
    )

    result = check_opencode_plugins(package)

    assert result.passed is False
    assert any("../outside-plugin" in finding.description for finding in result.findings)


def test_gemini_context_file_resolve_runtime_error_is_rejected_without_crashing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original_resolve = Path.resolve

    def _resolve(self: Path, strict: bool = False) -> Path:
        if self.name == "loop":
            raise RuntimeError("symlink loop")
        return original_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", _resolve)
    package = NormalizedPackage(
        ecosystem=Ecosystem.GEMINI,
        package_kind="extension",
        root_path=tmp_path,
        raw_manifest={"contextFileName": "./loop"},
    )

    result = check_context_and_mcp(package)

    assert result.passed is False
    assert any(finding.rule_id == "GEMINI_CONTEXT_FILE_UNSAFE" for finding in result.findings)
