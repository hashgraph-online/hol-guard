"""Tests for native Kimi plugin detection and scanning."""

import json
import shutil
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.ecosystems.detect import detect_packages
from codex_plugin_scanner.ecosystems.kimi import KimiAdapter
from codex_plugin_scanner.ecosystems.types import Ecosystem
from codex_plugin_scanner.models import ScanOptions
from codex_plugin_scanner.scanner import scan_plugin

FIXTURES = Path(__file__).parent / "fixtures"


def _symlink_or_skip(link_path: Path, target: Path) -> None:
    link_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        link_path.symlink_to(target, target_is_directory=target.is_dir())
    except (NotImplementedError, OSError):
        pytest.skip("symlinks are not supported in this environment")


def test_detect_kimi_package() -> None:
    packages = detect_packages(FIXTURES / "kimi-plugin-good")

    assert len(packages) == 1
    assert packages[0].ecosystem == Ecosystem.KIMI
    assert packages[0].manifest_path and packages[0].manifest_path.name == "kimi.plugin.json"


def test_scan_kimi_auto_detects_native_manifest() -> None:
    result = scan_plugin(
        FIXTURES / "kimi-plugin-good",
        ScanOptions(ecosystem="auto", cisco_skill_scan="off", cisco_mcp_scan="off"),
    )

    assert result.ecosystems == ("kimi",)
    assert len(result.packages) == 1
    assert result.packages[0].manifest_path
    assert result.packages[0].manifest_path.endswith("kimi.plugin.json")
    assert any(category.name.endswith("Kimi Plugin") for category in result.categories)
    assert all(finding.rule_id != "PLUGIN_JSON_MISSING" for finding in result.findings)
    assert result.score >= 90


def test_kimi_scan_excludes_unrelated_application_files(tmp_path: Path) -> None:
    shutil.copytree(FIXTURES / "kimi-plugin-good", tmp_path, dirs_exist_ok=True)
    unrelated = tmp_path / "src" / "application.py"
    unrelated.parent.mkdir()
    unrelated.write_text('api_key = "sk-proj-abcdefghijklmnopqrstuvwxyz123456"\n', encoding="utf-8")

    result = scan_plugin(
        tmp_path,
        ScanOptions(ecosystem="auto", cisco_skill_scan="off", cisco_mcp_scan="off"),
    )

    assert all(finding.rule_id != "HARDCODED_SECRET" for finding in result.findings)


def test_kimi_scan_checks_declared_bundle_files_for_secrets(tmp_path: Path) -> None:
    shutil.copytree(FIXTURES / "kimi-plugin-good", tmp_path, dirs_exist_ok=True)
    manifest_path = tmp_path / "kimi.plugin.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["mcpServers"] = {"local": {"command": "./server.js"}}
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    (tmp_path / "server.js").write_text(
        'api_key = "sk-proj-abcdefghijklmnopqrstuvwxyz123456"\n',
        encoding="utf-8",
    )

    result = scan_plugin(
        tmp_path,
        ScanOptions(ecosystem="kimi", cisco_skill_scan="off", cisco_mcp_scan="off"),
    )

    secrets = [finding for finding in result.findings if finding.rule_id == "HARDCODED_SECRET"]
    assert len(secrets) == 1
    assert secrets[0].file_path == "server.js"


def test_kimi_scan_checks_local_mcp_entrypoints_in_args(tmp_path: Path) -> None:
    shutil.copytree(FIXTURES / "kimi-plugin-good", tmp_path, dirs_exist_ok=True)
    manifest_path = tmp_path / "kimi.plugin.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["mcpServers"] = {"local": {"command": "node", "args": ["./server.js"]}}
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    (tmp_path / "server.js").write_text(
        'const apiKey = "sk-proj-abcdefghijklmnopqrstuvwxyz123456"; eval(apiKey);\n',
        encoding="utf-8",
    )

    result = scan_plugin(
        tmp_path,
        ScanOptions(ecosystem="kimi", cisco_skill_scan="off", cisco_mcp_scan="off"),
    )
    rule_ids = {finding.rule_id for finding in result.findings}

    assert "HARDCODED_SECRET" in rule_ids
    assert "DANGEROUS_DYNAMIC_EXECUTION" in rule_ids


def test_kimi_local_mcp_arg_symlink_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path / "outside.js"
    outside.write_text("eval('unsafe');", encoding="utf-8")
    _symlink_or_skip(tmp_path / "server.js", outside)
    (tmp_path / "kimi.plugin.json").write_text(
        json.dumps(
            {
                "name": "symlink-plugin",
                "mcpServers": {"local": {"command": "node", "args": ["./server.js"]}},
            }
        ),
        encoding="utf-8",
    )

    result = scan_plugin(
        tmp_path,
        ScanOptions(ecosystem="kimi", cisco_skill_scan="off", cisco_mcp_scan="off"),
    )

    assert any(finding.rule_id == "KIMI_MCP_ARG_PATH_INVALID" for finding in result.findings)


def test_kimi_root_manifest_takes_precedence_over_alternate_manifest(tmp_path: Path) -> None:
    (tmp_path / ".kimi-plugin").mkdir()
    (tmp_path / "kimi.plugin.json").write_text('{"name":"root-plugin"}', encoding="utf-8")
    (tmp_path / ".kimi-plugin" / "plugin.json").write_text('{"name":"alternate-plugin"}', encoding="utf-8")

    candidates = KimiAdapter().detect(tmp_path)
    package = KimiAdapter().parse(candidates[0])

    assert len(candidates) == 1
    assert package.name == "root-plugin"
    assert package.manifest_path == tmp_path / "kimi.plugin.json"


def test_kimi_alternate_manifest_is_scanned_when_root_manifest_is_absent(tmp_path: Path) -> None:
    (tmp_path / ".kimi-plugin").mkdir()
    (tmp_path / ".kimi-plugin" / "plugin.json").write_text(
        '{"name":"alternate-plugin","version":"1.0.0-beta.1+build.2"}',
        encoding="utf-8",
    )

    result = scan_plugin(
        tmp_path,
        ScanOptions(ecosystem="auto", cisco_skill_scan="off", cisco_mcp_scan="off"),
    )

    assert result.ecosystems == ("kimi",)
    assert result.packages[0].manifest_path
    assert result.packages[0].manifest_path.endswith(".kimi-plugin/plugin.json")
    assert all(finding.rule_id != "KIMI_VERSION_INVALID" for finding in result.findings)


def test_kimi_invalid_utf8_manifest_reports_parse_finding(tmp_path: Path) -> None:
    (tmp_path / "kimi.plugin.json").write_bytes(b'\xff\xfe{"name":"plugin"}')

    result = scan_plugin(
        tmp_path,
        ScanOptions(ecosystem="kimi", cisco_skill_scan="off", cisco_mcp_scan="off"),
    )

    finding = next(finding for finding in result.findings if finding.rule_id == "KIMI_MANIFEST_INVALID")
    assert "invalid-encoding" in finding.description


def test_kimi_declared_path_escape_is_rejected(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-kimi-skill"
    outside.mkdir(exist_ok=True)
    (outside / "SKILL.md").write_text("outside", encoding="utf-8")
    (tmp_path / "kimi.plugin.json").write_text(
        json.dumps({"name": "unsafe-plugin", "skills": "../outside-kimi-skill/"}),
        encoding="utf-8",
    )

    result = scan_plugin(
        tmp_path,
        ScanOptions(ecosystem="auto", cisco_skill_scan="off", cisco_mcp_scan="off"),
    )

    assert any(finding.rule_id == "KIMI_PATH_UNSAFE_OR_MISSING" for finding in result.findings)


def test_kimi_declared_symlink_path_is_rejected(tmp_path: Path) -> None:
    real_commands = tmp_path / "real-commands"
    real_commands.mkdir()
    (real_commands / "review.md").write_text("Review safely.", encoding="utf-8")
    _symlink_or_skip(tmp_path / "commands", real_commands)
    (tmp_path / "kimi.plugin.json").write_text(
        json.dumps({"name": "symlink-plugin", "commands": "./commands/"}),
        encoding="utf-8",
    )

    result = scan_plugin(
        tmp_path,
        ScanOptions(ecosystem="kimi", cisco_skill_scan="off", cisco_mcp_scan="off"),
    )

    assert any(finding.rule_id == "KIMI_PATH_SYMLINK_UNSUPPORTED" for finding in result.findings)


def test_kimi_explicit_agent_file_must_be_markdown(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text("print('not an agent')", encoding="utf-8")
    (tmp_path / "kimi.plugin.json").write_text(
        json.dumps({"name": "invalid-agent-plugin", "agents": "./agent.py"}),
        encoding="utf-8",
    )

    result = scan_plugin(
        tmp_path,
        ScanOptions(ecosystem="kimi", cisco_skill_scan="off", cisco_mcp_scan="off"),
    )

    assert any(finding.rule_id == "KIMI_MARKDOWN_PATH_INVALID" for finding in result.findings)


def test_kimi_dangerous_mcp_command_is_high_severity(tmp_path: Path) -> None:
    (tmp_path / "kimi.plugin.json").write_text(
        json.dumps(
            {
                "name": "unsafe-plugin",
                "mcpServers": {"unsafe": {"command": "sh", "args": ["-c", "printf unsafe"]}},
            }
        ),
        encoding="utf-8",
    )

    result = scan_plugin(
        tmp_path,
        ScanOptions(ecosystem="kimi", cisco_skill_scan="off", cisco_mcp_scan="off"),
    )

    finding = next(finding for finding in result.findings if finding.rule_id == "KIMI_MCP_COMMAND_DANGEROUS")
    assert finding.severity.value == "high"


def test_kimi_local_mcp_command_symlink_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "server-target.js"
    target.write_text("export {};", encoding="utf-8")
    _symlink_or_skip(tmp_path / "server.js", target)
    (tmp_path / "kimi.plugin.json").write_text(
        json.dumps({"name": "symlink-plugin", "mcpServers": {"local": {"command": "./server.js"}}}),
        encoding="utf-8",
    )

    result = scan_plugin(
        tmp_path,
        ScanOptions(ecosystem="kimi", cisco_skill_scan="off", cisco_mcp_scan="off"),
    )

    assert any(finding.rule_id == "KIMI_MCP_COMMAND_SYMLINK_UNSUPPORTED" for finding in result.findings)


@pytest.mark.parametrize("path_value", ["../outside.js", "/outside.js", "C:outside.js"])
@pytest.mark.parametrize("field", ["command", "args"])
def test_kimi_external_mcp_command_or_arg_path_is_rejected(tmp_path: Path, field: str, path_value: str) -> None:
    server: dict[str, object] = {"command": "node"}
    server[field] = [path_value] if field == "args" else path_value
    (tmp_path / "kimi.plugin.json").write_text(
        json.dumps({"name": "external-path-plugin", "mcpServers": {"local": server}}),
        encoding="utf-8",
    )

    result = scan_plugin(
        tmp_path,
        ScanOptions(ecosystem="kimi", cisco_skill_scan="off", cisco_mcp_scan="off"),
    )

    expected = "KIMI_MCP_ARG_PATH_INVALID" if field == "args" else "KIMI_MCP_COMMAND_PATH_INVALID"
    assert any(finding.rule_id == expected for finding in result.findings)


def test_kimi_mcp_cwd_must_be_directory(tmp_path: Path) -> None:
    (tmp_path / "cwd.txt").write_text("not a directory", encoding="utf-8")
    (tmp_path / "kimi.plugin.json").write_text(
        json.dumps(
            {
                "name": "invalid-cwd-plugin",
                "mcpServers": {"local": {"command": "node", "cwd": "./cwd.txt"}},
            }
        ),
        encoding="utf-8",
    )

    result = scan_plugin(
        tmp_path,
        ScanOptions(ecosystem="kimi", cisco_skill_scan="off", cisco_mcp_scan="off"),
    )

    assert any(finding.rule_id == "KIMI_MCP_CWD_INVALID" for finding in result.findings)


@pytest.mark.parametrize(
    "url",
    [
        "https:attacker.example/mcp",
        "https://user:secret@example.com/mcp",
        "https://example.com/mcp#fragment",
    ],
)
def test_kimi_malformed_or_credentialed_remote_mcp_url_is_rejected(tmp_path: Path, url: str) -> None:
    (tmp_path / "kimi.plugin.json").write_text(
        json.dumps({"name": "unsafe-plugin", "mcpServers": {"remote": {"url": url}}}),
        encoding="utf-8",
    )

    result = scan_plugin(
        tmp_path,
        ScanOptions(ecosystem="kimi", cisco_skill_scan="off", cisco_mcp_scan="off"),
    )

    assert any(finding.rule_id == "KIMI_MCP_URL_INSECURE" for finding in result.findings)


def test_cli_scans_kimi_ecosystem_explicitly(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(
        [
            "scan",
            str(FIXTURES / "kimi-plugin-good"),
            "--ecosystem",
            "kimi",
            "--cisco-skill-scan",
            "off",
            "--cisco-mcp-scan",
            "off",
            "--format",
            "json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)

    assert rc == 0
    assert payload["ecosystems"] == ["kimi"]
