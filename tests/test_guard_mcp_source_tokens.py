from __future__ import annotations

import pytest

from codex_plugin_scanner.guard.runtime.mcp_protection import (
    build_mcp_server_identity,
    package_source_token,
)


@pytest.mark.parametrize(
    "args",
    [
        ("--userconfig", "evil.npmrc", "-y", "mcp-mail-server"),
        ("--globalconfig=evil.npmrc", "-y", "mcp-mail-server"),
        ("--@scope:registry", "https://alternate.example.invalid", "-y", "mcp-mail-server"),
        ("--reg", "https://alternate.example.invalid", "-y", "mcp-mail-server"),
        ("--future-config=evil", "-y", "mcp-mail-server"),
    ],
)
def test_source_helper_uses_native_identity_classification(args: tuple[str, ...]) -> None:
    identity = build_mcp_server_identity(config_path="", command="npx", args=args, transport="stdio")
    assert identity.package_name == "mcp-mail-server"
    assert identity.package_source != "default"
    assert package_source_token("npx", args) == identity.package_source


def test_configuration_operand_changes_source_without_exposing_the_operand() -> None:
    first = package_source_token("npx", ("--userconfig", "secret-one.npmrc", "mcp-mail-server"))
    second = package_source_token("npx", ("--userconfig", "secret-two.npmrc", "mcp-mail-server"))
    assert first != second
    assert "secret-one" not in first
    assert "secret-two" not in second
