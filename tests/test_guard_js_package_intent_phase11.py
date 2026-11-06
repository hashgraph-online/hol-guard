"""Phase 11 JavaScript package intent and lockfile parsing tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.package_intent_parser import parse_package_intent


@pytest.fixture(autouse=True)
def _native_package_intent(package_intent_native):
    """Parse intents through the resident authority."""

    return package_intent_native


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_parse_package_intent_npm_audit_fix_uses_manifest_and_lockfile_context(tmp_path: Path) -> None:
    _write_text(tmp_path / "package.json", '{"name":"demo"}\n')
    _write_text(tmp_path / "package-lock.json", '{"lockfileVersion":3}\n')

    intent = parse_package_intent("npm audit fix --package-lock-only", workspace=tmp_path)

    assert intent is not None
    assert intent.package_manager == "npm"
    assert intent.intent_kind == "sync"
    assert intent.targets == ()
    assert intent.manifest_paths == ("package.json",)
    assert intent.lockfile_paths == ("package-lock.json",)
    assert "--package-lock-only" in intent.flags


def test_parse_package_intent_js_named_source_specs_capture_source_urls() -> None:
    intent = parse_package_intent(
        "npm install guard-github@github:hashgraph-online/hol-guard "
        "guard-http@http://example.com/guard.tgz "
        "guard-https@https://example.com/guard.tgz"
    )

    assert intent is not None
    assert [target.package_name for target in intent.targets] == ["guard-github", "guard-http", "guard-https"]
    assert [target.source_url for target in intent.targets] == [
        "github:hashgraph-online/hol-guard",
        "http://example.com/guard.tgz",
        "https://example.com/guard.tgz",
    ]


def test_parse_package_intent_js_file_source_specs_capture_local_sources() -> None:
    intent = parse_package_intent("npm install guard-local@file:../fixtures/guard-local")

    assert intent is not None
    assert intent.targets[0].package_name == "guard-local"
    assert intent.targets[0].source_url == "file:../fixtures/guard-local"


def test_parse_package_intent_npm_exec_keeps_explicit_version_when_positional_token_is_bare() -> None:
    intent = parse_package_intent("npm exec --package=create-vite@5.1.0 create-vite")

    assert intent is not None
    assert intent.package_manager == "npm"
    assert intent.intent_kind == "execute"
    assert intent.targets[0].package_name == "create-vite"
    assert intent.targets[0].requested_specifier == "5.1.0"
