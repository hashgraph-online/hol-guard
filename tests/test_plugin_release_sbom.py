from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from codex_plugin_scanner import plugin_release_runner, plugin_release_sbom
from codex_plugin_scanner.plugin_release_evidence import McpServerSurface
from codex_plugin_scanner.plugin_release_sbom import build_plugin_release_sbom
from tests.test_plugin_release_evidence import CHECK_REPORT, _runner_env

SHA512 = base64.b64encode(bytes(range(64))).decode("ascii")
PACKAGE_LOCK = {
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "weather-tools", "version": "1.2.0"},
        "node_modules/zod": {"version": "3.23.8", "integrity": f"sha512-{SHA512}"},
        "node_modules/@acme/weather-mcp": {"version": "1.0.0"},
        "node_modules/fsevents": {"version": "2.3.3", "optional": True},
        "node_modules/vitest": {"version": "2.0.0", "dev": True},
        "node_modules/local": {"resolved": "packages/local", "link": True},
        "node_modules/a/node_modules/old-zod": {"name": "zod", "version": "3.0.0"},
    },
}
REQUIREMENTS = "\n".join(
    [
        "# pinned",
        "Foo_Bar[extra]==1.0.0 ; python_version > '3.9'",
        "-r other.txt",
        "httpx>=0.27",
        "mcp==1.2.0 --hash=sha256:abc",
        "",
    ]
)
UV_LOCK = """
version = 1

[[package]]
name = "weather-tools"
version = "1.2.0"
source = { editable = "." }

[[package]]
name = "Pydantic_Core"
version = "2.27.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "mcp"
version = "1.2.0"
source = { git = "https://github.com/acme/mcp?rev=main#0123abc" }
"""
SERVERS = (
    McpServerSurface("weather", "stdio", "npx", "@acme/weather-mcp", None, ()),
    McpServerSurface("search", "stdio", "uvx", "mcp-server-fetch==2025.1.0", None, ()),
    McpServerSurface("latest", "stdio", "bunx", "left-pad", None, ()),
    McpServerSurface("tagged", "stdio", "npx", "zod@latest", None, ()),
    McpServerSurface("lint", "stdio", "uvx", "ruff@0.6.0", None, ()),
    McpServerSurface("local", "stdio", "node", None, None, ()),
)


def _plugin(tmp_path: Path) -> Path:
    plugin = tmp_path / "plugin"
    plugin.mkdir()
    (plugin / "package-lock.json").write_text(json.dumps(PACKAGE_LOCK), encoding="utf-8")
    (plugin / "requirements.txt").write_text(REQUIREMENTS, encoding="utf-8")
    (plugin / "uv.lock").write_text(UV_LOCK, encoding="utf-8")
    (plugin / "requirements-dev.txt").write_text("pytest==8.3.0\n", encoding="utf-8")
    nested = plugin / "examples"
    nested.mkdir()
    (nested / "requirements.txt").write_text("nested==9.9.9\n", encoding="utf-8")
    return plugin


def _sbom(plugin: Path, servers: tuple[McpServerSurface, ...] = SERVERS):
    return build_plugin_release_sbom(
        plugin_dir=plugin,
        servers=servers,
        repository="acme/weather-tools",
        commit_sha="a" * 40,
        plugin_name="weather-tools",
        plugin_version="1.2.0",
        guard_version="3.58.0",
    )


def test_sbom_lists_shipped_packages_from_lockfiles_and_launchers(tmp_path: Path) -> None:
    sbom = _sbom(_plugin(tmp_path))
    assert sbom is not None
    document = json.loads(sbom.document)
    purls = [component["purl"] for component in document["components"]]

    assert purls == [
        "pkg:npm/%40acme/weather-mcp@1.0.0",
        "pkg:npm/fsevents@2.3.3",
        "pkg:npm/left-pad",
        "pkg:npm/zod@3.0.0",
        "pkg:npm/zod@3.23.8",
        "pkg:pypi/foo-bar@1.0.0",
        "pkg:pypi/mcp-server-fetch@2025.1.0",
        "pkg:pypi/mcp@1.2.0",
        "pkg:pypi/mcp@1.2.0?vcs_url=git%2Bhttps%3A%2F%2Fgithub.com%2Facme%2Fmcp%3Frev%3Dmain%230123abc",
        "pkg:pypi/pydantic-core@2.27.1",
        "pkg:pypi/ruff@0.6.0",
    ]
    by_purl = {component["purl"]: component for component in document["components"]}
    assert by_purl["pkg:npm/zod@3.23.8"]["hashes"] == [{"alg": "SHA-512", "content": bytes(range(64)).hex()}]
    assert by_purl["pkg:npm/fsevents@2.3.3"]["scope"] == "optional"
    assert "version" not in by_purl["pkg:npm/left-pad"]
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.6"
    assert document["metadata"]["component"] == {
        "type": "application",
        "bom-ref": "plugin",
        "name": "weather-tools",
        "version": "1.2.0",
    }
    assert "timestamp" not in document["metadata"]
    assert sbom.summary.components == 11
    assert sbom.summary.sha256 == hashlib.sha256(sbom.document.encode("utf-8")).hexdigest()
    again = tmp_path / "again"
    again.mkdir()
    assert _sbom(_plugin(again)) == sbom


def test_sbom_reads_lockfile_version_one_trees(tmp_path: Path) -> None:
    plugin = tmp_path / "plugin"
    plugin.mkdir()
    lock = {
        "lockfileVersion": 1,
        "dependencies": {
            "express": {"version": "4.21.0", "dependencies": {"qs": {"version": "6.13.0"}}},
            "jest": {"version": "29.0.0", "dev": True},
        },
    }
    (plugin / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")

    sbom = _sbom(plugin, ())
    assert sbom is not None
    assert [item["purl"] for item in json.loads(sbom.document)["components"]] == [
        "pkg:npm/express@4.21.0",
        "pkg:npm/qs@6.13.0",
    ]


def test_sbom_skips_links_unreadable_files_and_empty_plugins(tmp_path: Path) -> None:
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps(PACKAGE_LOCK), encoding="utf-8")
    plugin = tmp_path / "plugin"
    plugin.mkdir()
    (plugin / "package-lock.json").symlink_to(outside)
    (plugin / "uv.lock").write_text("not = [toml", encoding="utf-8")
    (plugin / "requirements-dev.txt").write_bytes(b"\xff\xfe")

    assert _sbom(plugin, ()) is None


def test_sbom_is_left_out_rather_than_truncated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(plugin_release_sbom, "MAX_COMPONENTS", 3)
    assert _sbom(_plugin(tmp_path)) is None


def test_runner_binds_the_sbom_digest_into_the_attested_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    output = _runner_env(monkeypatch, tmp_path, CHECK_REPORT)
    monkeypatch.setenv("PLUGIN_DIR", str(_plugin(tmp_path)))
    monkeypatch.setenv("SBOM_PATH", str(tmp_path / "sbom.cdx.json"))

    assert plugin_release_runner.main(["evidence"]) == 0
    outputs = dict(line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines())
    sbom_bytes = (tmp_path / "sbom.cdx.json").read_bytes()
    evidence = json.loads((tmp_path / "evidence.json").read_text(encoding="utf-8"))
    assert outputs["sbom_path"] == str(tmp_path / "sbom.cdx.json")
    assert outputs["sbom_components"] == "8"
    assert evidence["sbom"] == {
        "format": "CycloneDX",
        "spec_version": "1.6",
        "sha256": hashlib.sha256(sbom_bytes).hexdigest(),
        "components": 8,
    }

    monkeypatch.setenv("RELEASE_STATUS", "disabled")
    assert plugin_release_runner.main(["summary"]) == 0
    summary = (tmp_path / "summary.md").read_text(encoding="utf-8")
    assert f"- SBOM: CycloneDX 1.6, 8 components, SHA-256 {evidence['sbom']['sha256']}" in summary


def test_runner_leaves_the_sbom_out_when_none_is_requested(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    output = _runner_env(monkeypatch, tmp_path, CHECK_REPORT)
    monkeypatch.setenv("PLUGIN_DIR", str(_plugin(tmp_path)))

    assert plugin_release_runner.main(["evidence"]) == 0
    assert "sbom" not in json.loads((tmp_path / "evidence.json").read_text(encoding="utf-8"))
    assert "sbom_path=" in output.read_text(encoding="utf-8").splitlines()


CHANGES = {
    "previousVersion": "1.1.0",
    "flags": [
        {"kind": "egress", "text": "New network destinations: upload.example.net"},
        {"kind": "env", "text": "New environment variables read: TOKEN\n::error::forged"},
        {"kind": "unknown", "text": "dropped"},
        {"kind": "check", "text": ""},
        {"kind": ["egress"], "text": "unhashable kind"},
    ]
    + [{"kind": "unknown", "text": "padding"}] * 25
    + [{"kind": "hooks", "text": "New hooks: SessionStart"}],
}


def test_registration_passes_on_only_known_change_flags(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    output = _runner_env(monkeypatch, tmp_path, CHECK_REPORT)
    assert plugin_release_runner.main(["evidence"]) == 0
    monkeypatch.setenv("REGISTER_RELEASE", "true")
    result = {"status": "recorded", "releaseUrl": "https://hol.org/registry/plugins/x/releases", "changes": CHANGES}
    monkeypatch.setattr(plugin_release_runner, "register_plugin_release_evidence", lambda **_: result)

    assert plugin_release_runner.main(["register"]) == 0
    line = next(item for item in output.read_text(encoding="utf-8").splitlines() if item.startswith("changes="))
    assert json.loads(line.removeprefix("changes=")) == {
        "previousVersion": "1.1.0",
        "flags": [
            {"kind": "egress", "text": "New network destinations: upload.example.net"},
            {"kind": "env", "text": "New environment variables read: TOKEN::error::forged"},
            {"kind": "hooks", "text": "New hooks: SessionStart"},
        ],
    }


def test_summary_lists_changes_and_annotates_each_flag(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _runner_env(monkeypatch, tmp_path, CHECK_REPORT)
    assert plugin_release_runner.main(["evidence"]) == 0
    capsys.readouterr()
    monkeypatch.setenv("RELEASE_STATUS", "recorded")
    flagged = {"previousVersion": "1.1.0", "flags": [{"kind": "egress", "text": "New hosts: a.example 100%\r\nx"}]}
    monkeypatch.setenv("CHANGES", json.dumps(flagged))

    assert plugin_release_runner.main(["summary"]) == 0
    summary = (tmp_path / "summary.md").read_text(encoding="utf-8")
    assert "- Changes since 1.1.0, review before upgrading:" in summary
    assert "  - New hosts: a.example 100%x" in summary
    assert capsys.readouterr().out.splitlines() == ["::warning title=HOL Plugin Release::New hosts: a.example 100%25x"]

    (tmp_path / "summary.md").unlink()
    monkeypatch.setenv("CHANGES", json.dumps({"previousVersion": "1.1.0", "flags": []}))
    assert plugin_release_runner.main(["summary"]) == 0
    assert "- Changes since 1.1.0: nothing new to review" in (tmp_path / "summary.md").read_text(encoding="utf-8")
    assert "::warning" not in capsys.readouterr().out
