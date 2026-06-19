"""Phase 04 package spec parsing proofs for install-time protect."""

from __future__ import annotations

from codex_plugin_scanner.guard import protect


def test_parse_protect_command_records_npm_tarball_spec() -> None:
    request = protect.parse_protect_command(
        ["npm", "install", "guard-tarball@https://example.com/guard.tgz"],
    )

    target = request.targets[0]
    assert target.raw_spec == "guard-tarball@https://example.com/guard.tgz"
    assert target.source_url == "https://example.com/guard.tgz"
    assert target.package_name == "guard-tarball"
    assert target.version == "https://example.com/guard.tgz"


def test_parse_protect_command_records_npm_git_url_spec() -> None:
    request = protect.parse_protect_command(
        ["npm", "install", "guard-github@git+https://github.com/hashgraph-online/hol-guard.git"],
    )

    target = request.targets[0]
    assert target.raw_spec == "guard-github@git+https://github.com/hashgraph-online/hol-guard.git"
    assert target.source_url == "git+https://github.com/hashgraph-online/hol-guard.git"
    assert target.package_name == "guard-github"
    assert target.version == "git+https://github.com/hashgraph-online/hol-guard.git"


def test_parse_protect_command_records_npm_local_path_spec() -> None:
    request = protect.parse_protect_command(["npm", "install", "./fixtures/local-package"])

    target = request.targets[0]
    assert target.raw_spec == "./fixtures/local-package"
    assert target.source_url is None
    assert target.package_name == "local-package"


def test_parse_protect_command_records_npm_registry_override_before_package() -> None:
    request = protect.parse_protect_command(
        [
            "npm",
            "install",
            "--registry",
            "https://registry.example.com",
            "@scope/guard-safe@1.2.3",
        ],
    )

    target = request.targets[0]
    assert target.raw_spec == "@scope/guard-safe@1.2.3"
    assert target.package_name == "@scope/guard-safe"
    assert target.version == "1.2.3"


def test_parse_protect_command_records_npm_global_registry_override_before_install_subcommand() -> None:
    request = protect.parse_protect_command(
        [
            "npm",
            "--registry=https://registry.example.com",
            "install",
            "@scope/guard-safe@1.2.3",
        ],
    )

    target = request.targets[0]
    assert target.raw_spec == "@scope/guard-safe@1.2.3"
    assert target.package_name == "@scope/guard-safe"
    assert target.version == "1.2.3"


def test_parse_protect_command_records_pip_pep508_direct_url_spec() -> None:
    request = protect.parse_protect_command(
        ["pip", "install", "requests @ https://files.example.com/requests-2.32.3.tar.gz"],
    )

    target = request.targets[0]
    assert target.package_name == "requests"
    assert target.version == "https://files.example.com/requests-2.32.3.tar.gz"
    assert target.source_url == "https://files.example.com/requests-2.32.3.tar.gz"


def test_parse_protect_command_records_pip_registry_override_before_package() -> None:
    request = protect.parse_protect_command(
        [
            "pip",
            "install",
            "--index-url",
            "https://pypi.example/simple",
            "requests==2.32.3",
        ],
    )

    target = request.targets[0]
    assert target.raw_spec == "requests==2.32.3"
    assert target.package_name == "requests"
    assert target.version == "2.32.3"


def test_parse_protect_command_records_pip_global_flags_before_install_subcommand() -> None:
    request = protect.parse_protect_command(
        [
            "pip",
            "--isolated",
            "--index-url",
            "https://pypi.example/simple",
            "install",
            "requests==2.32.3",
        ],
    )

    target = request.targets[0]
    assert target.raw_spec == "requests==2.32.3"
    assert target.package_name == "requests"
    assert target.version == "2.32.3"
