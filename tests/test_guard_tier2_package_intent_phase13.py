"""Phase 13 tier2 parser and manifest-diff behavior tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.package_intent_parser import parse_package_intent


@pytest.fixture(autouse=True)
def _native_package_intent(package_intent_native):
    """Parse intents through the resident authority."""

    return package_intent_native


def test_parse_package_intent_supports_cargo_path_system_and_unsupported_package_managers() -> None:
    cargo_path = parse_package_intent("cargo add demo --path crates/demo")
    cargo_path_equals = parse_package_intent("cargo add demo --path=crates/demo")
    brew = parse_package_intent("brew install ripgrep fd")
    brew_cask = parse_package_intent("brew install --cask firefox")
    brew_tap = parse_package_intent("brew tap user/repository https://example.com/user/homebrew-repository.git")
    apt = parse_package_intent("apt-get install jq")
    pacman = parse_package_intent("pacman -Syu jq")
    helm = parse_package_intent("helm install ingress ingress-nginx/ingress-nginx")

    assert cargo_path is not None
    assert cargo_path.package_manager == "cargo"
    assert cargo_path.targets[0].package_name == "demo"
    assert cargo_path.targets[0].source_url == "file:crates/demo"
    assert cargo_path_equals is not None
    assert "<local-path>" in cargo_path_equals.redacted_command
    assert "crates/demo" not in cargo_path_equals.redacted_command

    assert brew is not None
    assert brew.package_manager == "brew"
    assert brew.targets[0].ecosystem == "homebrew"
    assert brew.targets[0].package_name == "ripgrep"
    assert brew.targets[1].package_name == "fd"
    assert brew_cask is not None
    assert brew_cask.targets[0].ecosystem == "homebrew-cask"
    assert brew_cask.targets[0].package_name == "firefox"
    assert brew_tap is not None
    assert brew_tap.targets[0].ecosystem == "homebrew-tap"
    assert brew_tap.targets[0].package_name == "user/repository"
    assert brew_tap.targets[0].source_url == "https://example.com/user/homebrew-repository.git"

    assert apt is not None
    assert apt.package_manager == "apt-get"
    assert apt.targets[0].ecosystem == "system"
    assert apt.targets[0].package_name == "jq"
    assert pacman is not None
    assert pacman.package_manager == "pacman"
    assert pacman.targets[0].package_name == "jq"

    assert helm is not None
    assert helm.package_manager == "helm"
    assert helm.targets[0].ecosystem == "unsupported"
    assert helm.targets[0].package_name == "ingress-nginx/ingress-nginx"


def test_parse_package_intent_supports_brew_bundle_brewfile(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "Brewfile").write_text(
        "\n".join(
            (
                'tap "user/repository", "https://example.com/user/homebrew-repository.git"',
                'brew "ruby"',
                'cask "firefox"',
            )
        ),
        encoding="utf-8",
    )

    intent = parse_package_intent("brew bundle install", workspace=workspace)

    assert intent is not None
    assert intent.package_manager == "brew"
    assert intent.intent_kind == "sync"
    assert intent.manifest_paths == ("Brewfile",)
    assert [(target.ecosystem, target.package_name) for target in intent.targets] == [
        ("homebrew-tap", "user/repository"),
        ("homebrew", "ruby"),
        ("homebrew-cask", "firefox"),
    ]
