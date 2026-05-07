"""Behavior tests for Guard MCP identity protection primitives."""

from __future__ import annotations

from pathlib import PurePosixPath

from codex_plugin_scanner.guard.adapters.mcp_servers import managed_stdio_servers
from codex_plugin_scanner.guard.mcp_tool_calls import build_tool_call_artifact
from codex_plugin_scanner.guard.models import GuardArtifact, HarnessDetection
from codex_plugin_scanner.guard.runtime.mcp_protection import build_mcp_server_identity, build_mcp_tool_identity


def test_mcp_server_identity_hashes_args_and_sorts_env_keys() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="npx",
        args=("--yes", "@modelcontextprotocol/server-filesystem@1.2.3", "."),
        transport="stdio",
        env={"TOKEN": "redacted", "PATH": "redacted"},
    )

    assert identity.config_path == ".mcp.json"
    assert identity.command == "npx"
    assert identity.transport == "stdio"
    assert identity.env_keys == ("PATH", "TOKEN")
    assert identity.package_name == "@modelcontextprotocol/server-filesystem"
    assert identity.package_version == "1.2.3"
    assert len(identity.args_hash) == 64


def test_managed_stdio_servers_emit_server_identity() -> None:
    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(".mcp.json",),
        artifacts=(
            GuardArtifact(
                artifact_id="codex:mcp:filesystem",
                name="filesystem",
                harness="codex",
                artifact_type="mcp_server",
                source_scope="project",
                config_path=".mcp.json",
                command="npx",
                args=("--yes", "@modelcontextprotocol/server-filesystem"),
                transport="stdio",
                metadata={"env": {"TOKEN": "redacted"}},
            ),
        ),
    )

    servers = managed_stdio_servers(detection)

    assert len(servers) == 1
    identity = servers[0].identity
    assert identity is not None
    assert identity.command == "npx"
    assert identity.env_keys == ("TOKEN",)
    assert identity.package_name == "@modelcontextprotocol/server-filesystem"


def test_tool_call_artifact_emits_tool_identity_metadata() -> None:
    server_identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="python",
        args=("server.py",),
        transport="stdio",
        env={},
    )

    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="filesystem",
        tool_name="read_file",
        source_scope="project",
        config_path=".mcp.json",
        transport="stdio",
        server_identity=server_identity,
        tool_schema={"properties": {"path": {"type": "string"}}},
        tool_description="Read files from an approved project folder.",
    )

    assert artifact.metadata["mcp_server_identity"]["args_hash"] == server_identity.args_hash
    tool_identity = artifact.metadata["mcp_tool_identity"]
    assert tool_identity["server_hash"] == server_identity.identity_hash
    assert tool_identity["tool_name"] == "read_file"
    assert len(tool_identity["schema_hash"]) == 64
    assert len(tool_identity["description_hash"]) == 64


def test_tool_call_artifact_prefers_stable_server_id_for_tool_identity() -> None:
    server_identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="python",
        args=("server.py",),
        transport="stdio",
        env={},
    )

    artifact = build_tool_call_artifact(
        harness="codex",
        server_name="filesystem",
        tool_name="read_file",
        source_scope="project",
        config_path=".mcp.json",
        transport="stdio",
        server_id="mcp_server:codex:project:filesystem:abc123",
        server_identity=server_identity,
    )

    assert artifact.metadata["mcp_tool_identity"]["server_hash"] == "mcp_server:codex:project:filesystem:abc123"


def test_mcp_server_identity_extracts_package_name_for_pipx_run() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="pipx",
        args=("run", "black", "--version"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "black"


def test_mcp_server_identity_skips_pipx_option_values_before_package() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="pipx",
        args=("run", "--python", "3.11", "black@24.4.2"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "black"
    assert identity.package_version == "24.4.2"


def test_mcp_server_identity_skips_pipx_short_index_value_before_package() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="pipx",
        args=("run", "-i", "https://pypi.example/simple", "black"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "black"


def test_mcp_server_identity_skips_pipx_with_dependency_value_before_package() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="pipx",
        args=("run", "--with", "requests", "black"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "black"


def test_mcp_server_identity_skips_npx_option_values_before_package() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="npx",
        args=("--registry", "https://registry.npmjs.org", "@scope/package@1.2.3"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "@scope/package"
    assert identity.package_version == "1.2.3"


def test_mcp_server_identity_keeps_npx_package_names_with_dot_suffixes() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="npx",
        args=("highlight.js",),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "highlight.js"
    assert identity.package_version is None


def test_mcp_server_identity_skips_npx_workspace_value_before_package() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="npx",
        args=("-w", "packages/a", "create-react-app"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "create-react-app"


def test_mcp_server_identity_normalizes_windows_launcher_suffixes() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command=r"C:\\Program Files\\nodejs\\npx.cmd",
        args=("--registry", "https://registry.npmjs.org", "@scope/package@1.2.3"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "@scope/package"
    assert identity.package_version == "1.2.3"


def test_mcp_server_identity_keeps_pipx_package_named_run() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="pipx",
        args=("run", "run"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "run"


def test_mcp_server_identity_keeps_pnpm_package_named_x() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="pnpm",
        args=("dlx", "x"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "x"


def test_mcp_server_identity_reads_pnpm_package_selector_flag() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="pnpm",
        args=("dlx", "--package=@pnpm/meta-updater", "meta-updater"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "@pnpm/meta-updater"
    assert identity.package_version is None


def test_mcp_server_identity_does_not_parse_pnpm_exec_command_as_package() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="pnpm",
        args=("exec", "jest", "--version"),
        transport="stdio",
        env={},
    )

    assert identity.package_name is None
    assert identity.package_version is None


def test_mcp_server_identity_does_not_parse_yarn_exec_command_as_package() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="yarn",
        args=("exec", "node", "--version"),
        transport="stdio",
        env={},
    )

    assert identity.package_name is None
    assert identity.package_version is None


def test_mcp_server_identity_reads_pipx_spec_package_selector() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="pipx",
        args=("run", "--spec", "esptool", "esp_rfc2217_server.py"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "esptool"


def test_mcp_server_identity_reads_uvx_from_package_selector() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="uvx",
        args=("--from", "httpie", "http"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "httpie"


def test_mcp_server_identity_skips_uvx_short_option_values_before_package() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="uvx",
        args=("-i", "https://registry.example/simple", "httpie"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "httpie"


def test_mcp_server_identity_skips_uvx_with_dependency_values_before_package() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="uvx",
        args=("--with", "rich", "ruff"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "ruff"


def test_mcp_server_identity_skips_uvx_constraints_values_before_package() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="uvx",
        args=("-c", "constraints.txt", "ruff"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "ruff"


def test_mcp_server_identity_skips_uvx_config_setting_values_before_package() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="uvx",
        args=("-C", "index-url=https://pypi.org/simple", "ruff"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "ruff"


def test_mcp_server_identity_skips_uvx_config_file_values_before_package() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="uvx",
        args=("--config-file", "uv.toml", "ruff"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "ruff"


def test_mcp_server_identity_skips_uvx_index_option_values_before_package() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="uvx",
        args=("--index", "https://registry.example/simple", "ruff"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "ruff"


def test_mcp_server_identity_skips_uvx_default_index_option_values_before_package() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="uvx",
        args=("--default-index", "https://registry.example/simple", "ruff"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "ruff"


def test_mcp_server_identity_skips_uvx_env_file_option_values_before_package() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="uvx",
        args=("--env-file", ".env.guard", "ruff"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "ruff"


def test_mcp_server_identity_skips_uvx_directory_option_values_before_package() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="uvx",
        args=("--directory", "tools", "ruff"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "ruff"


def test_mcp_server_identity_skips_uvx_keyring_provider_option_values_before_package() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="uvx",
        args=("--keyring-provider", "subprocess", "ruff"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "ruff"


def test_mcp_server_identity_skips_uvx_resolution_option_values_before_package() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="uvx",
        args=("--resolution", "highest", "ruff"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "ruff"


def test_mcp_server_identity_skips_uvx_prerelease_option_values_before_package() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="uvx",
        args=("--prerelease", "allow", "ruff"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "ruff"


def test_mcp_server_identity_skips_uvx_additional_value_flags_before_package() -> None:
    option_args = (
        ("--allow-insecure-host", "example.test"),
        ("--cache-dir", ".uv-cache"),
        ("--color", "never"),
        ("--config-settings-package", "ruff:build=1"),
        ("--exclude-newer", "2024-01-01"),
        ("--exclude-newer-package", "ruff=2024-01-01"),
        ("--fork-strategy", "fewest"),
        ("--index-strategy", "first-index"),
        ("--link-mode", "copy"),
        ("--no-binary-package", "ruff"),
        ("--no-build-isolation-package", "ruff"),
        ("--no-build-package", "ruff"),
        ("--no-sources-package", "ruff"),
        ("--python-platform", "linux"),
        ("--refresh-package", "ruff"),
        ("--reinstall-package", "ruff"),
        ("--torch-backend", "cpu"),
        ("--upgrade-package", "typing-extensions"),
    )
    for option, value in option_args:
        identity = build_mcp_server_identity(
            config_path=".mcp.json",
            command="uvx",
            args=(option, value, "ruff"),
            transport="stdio",
            env={},
        )

        assert identity.package_name == "ruff"


def test_mcp_server_identity_skips_uvx_overrides_option_values_before_package() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="uvx",
        args=("--overrides", "overrides.txt", "ruff"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "ruff"


def test_mcp_server_identity_skips_uvx_build_constraints_values_before_package() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="uvx",
        args=("-b", "build-constraints.txt", "ruff"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "ruff"


def test_mcp_server_identity_skips_uvx_python_short_option_value_before_package() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="uvx",
        args=("-p", "3.12", "ruff"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "ruff"


def test_mcp_server_identity_does_not_parse_pnpm_run_subcommand_as_package() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="pnpm",
        args=("run", "lint"),
        transport="stdio",
        env={},
    )

    assert identity.package_name is None


def test_mcp_server_identity_skips_pnpm_allow_build_option_values_before_package() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="pnpm",
        args=("dlx", "--allow-build", "esbuild", "@scope/pkg"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "@scope/pkg"
    assert identity.package_version is None


def test_mcp_server_identity_keeps_pnpm_shell_mode_flag_without_value() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="pnpm",
        args=("dlx", "-c", "cowsay", "hello"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "cowsay"
    assert identity.package_version is None


def test_mcp_server_identity_skips_pnpm_reporter_value_before_package() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="pnpm",
        args=("dlx", "--reporter", "ndjson", "cowsay"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "cowsay"
    assert identity.package_version is None


def test_mcp_server_identity_does_not_parse_yarn_run_subcommand_as_package() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="yarn",
        args=("run", "lint"),
        transport="stdio",
        env={},
    )

    assert identity.package_name is None


def test_mcp_server_identity_reads_npm_exec_package_selector() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="npm",
        args=("exec", "--", "@modelcontextprotocol/server-filesystem@1.2.3"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "@modelcontextprotocol/server-filesystem"
    assert identity.package_version == "1.2.3"


def test_mcp_server_identity_reads_npm_exec_package_flag_selector() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="npm",
        args=("exec", "--package=@scope/package@1.9.0", "--", "node", "--version"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "@scope/package"
    assert identity.package_version == "1.9.0"


def test_mcp_server_identity_skips_npm_workspace_option_values_before_package() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="npm",
        args=("exec", "-w", "packages/a", "@scope/package@2.4.0"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "@scope/package"
    assert identity.package_version == "2.4.0"


def test_mcp_server_identity_skips_npm_call_short_option_value_without_package() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="npm",
        args=("exec", "-c", "echo hi"),
        transport="stdio",
        env={},
    )

    assert identity.package_name is None


def test_mcp_server_identity_reads_npm_x_package_selector() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="npm",
        args=("x", "@scope/package@2.4.0"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "@scope/package"
    assert identity.package_version == "2.4.0"


def test_mcp_server_identity_does_not_parse_npm_run_subcommand_as_package() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="npm",
        args=("run", "lint"),
        transport="stdio",
        env={},
    )

    assert identity.package_name is None


def test_mcp_server_identity_does_not_parse_other_npm_script_subcommands_as_packages() -> None:
    subcommands = ("ci", "install", "start", "test")
    for subcommand in subcommands:
        identity = build_mcp_server_identity(
            config_path=".mcp.json",
            command="npm",
            args=(subcommand, "lint"),
            transport="stdio",
            env={},
        )

        assert identity.package_name is None
        assert identity.package_version is None


def test_mcp_server_identity_redacts_vcs_url_spec_userinfo() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="pipx",
        args=("run", "--spec", "git+ssh://git@github.com/psf/black", "black"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "git+ssh://github.com/psf/black"
    assert identity.package_version is None


def test_mcp_server_identity_redacts_http_url_spec_credentials() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="pipx",
        args=("run", "--spec", "https://user:token@example.com/simple/black", "black"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "https://example.com/simple/black"
    assert identity.package_version is None


def test_mcp_server_identity_redacts_http_url_spec_query_secrets() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="pipx",
        args=("run", "--spec", "https://example.com/simple/black?token=abc123", "black"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "https://example.com/simple/black"
    assert identity.package_version is None


def test_mcp_server_identity_splits_pip_style_specifier_versions() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="pipx",
        args=("run", "--spec", "mypackage==2.0.0", "my-app"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "mypackage"
    assert identity.package_version == "2.0.0"


def test_mcp_server_identity_splits_pip_style_single_equals_versions() -> None:
    identity = build_mcp_server_identity(
        config_path=".mcp.json",
        command="pipx",
        args=("run", "--spec", "mypackage=2.0.0", "my-app"),
        transport="stdio",
        env={},
    )

    assert identity.package_name == "mypackage"
    assert identity.package_version == "2.0.0"


def test_mcp_tool_identity_normalizes_set_and_path_schema_values() -> None:
    first = build_mcp_tool_identity(
        server_hash="server",
        tool_name="summarize",
        schema={"paths": {"beta", "alpha"}, "location": PurePosixPath("/tmp/workspace")},
        description=None,
    )
    second = build_mcp_tool_identity(
        server_hash="server",
        tool_name="summarize",
        schema={"paths": {"alpha", "beta"}, "location": PurePosixPath("/tmp/workspace")},
        description=None,
    )

    assert first.schema_hash == second.schema_hash
