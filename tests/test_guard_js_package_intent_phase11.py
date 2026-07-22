"""Phase 11 JavaScript package intent and lockfile parsing tests."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.package_intent import (
    parse_manifest_dependency_changes,
    parse_package_intent,
)


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


def test_parse_manifest_dependency_changes_supports_package_lock_v1_nested_dependencies() -> None:
    before_text = (
        '{"dependencies":{"minimist":{"version":"1.2.7","dependencies":{"brace-expansion":{"version":"1.1.11"}}}}}'
    )
    after_text = (
        '{"dependencies":{"minimist":{"version":"1.2.8","dependencies":{"brace-expansion":{"version":"1.1.12"}}}}}'
    )

    result = parse_manifest_dependency_changes(
        path="package-lock.json",
        before_text=before_text,
        after_text=after_text,
    )

    actual = {change.package_name: (change.before, change.after) for change in result.changes}
    assert result.parse_errors == ()
    assert actual == {
        "brace-expansion": ("1.1.11", "1.1.12"),
        "minimist": ("1.2.7", "1.2.8"),
    }


def test_parse_manifest_dependency_changes_supports_pnpm_lock_snapshots() -> None:
    before_text = """
lockfileVersion: '9.0'
packages:
  minimist@1.2.7:
    resolution: {integrity: sha512-old}
  brace-expansion@1.1.11:
    resolution: {integrity: sha512-old}
snapshots:
  minimist@1.2.7:
    dependencies:
      brace-expansion: 1.1.11
"""
    after_text = """
lockfileVersion: '9.0'
packages:
  minimist@1.2.8:
    resolution: {integrity: sha512-new}
  brace-expansion@1.1.12:
    resolution: {integrity: sha512-new}
snapshots:
  minimist@1.2.8:
    dependencies:
      brace-expansion: 1.1.12
"""

    result = parse_manifest_dependency_changes(
        path="pnpm-lock.yaml",
        before_text=before_text,
        after_text=after_text,
    )

    actual = {change.package_name: (change.before, change.after) for change in result.changes}
    assert result.parse_errors == ()
    assert actual == {
        "brace-expansion": ("1.1.11", "1.1.12"),
        "minimist": ("1.2.7", "1.2.8"),
    }


def test_parse_manifest_dependency_changes_supports_yarn_classic_and_berry_entries() -> None:
    classic_before = '"minimist@^1.2.7":\n  version "1.2.7"\n'
    classic_after = '"minimist@^1.2.8":\n  version "1.2.8"\n"brace-expansion@^1.1.12":\n  version "1.1.12"\n'
    classic_result = parse_manifest_dependency_changes(
        path="yarn.lock",
        before_text=classic_before,
        after_text=classic_after,
    )
    classic_actual = {change.package_name: (change.before, change.after) for change in classic_result.changes}

    berry_before = """
__metadata:
  version: 4
  cacheKey: 8

"minimist@npm:^1.2.7":
  version: 1.2.7
  resolution: "minimist@npm:1.2.7"
"""
    berry_after = """
__metadata:
  version: 4
  cacheKey: 8

"minimist@npm:^1.2.8":
  version: 1.2.8
  resolution: "minimist@npm:1.2.8"

"brace-expansion@npm:^1.1.12":
  version: 1.1.12
  resolution: "brace-expansion@npm:1.1.12"
"""
    berry_result = parse_manifest_dependency_changes(
        path="yarn.lock",
        before_text=berry_before,
        after_text=berry_after,
    )
    berry_actual = {change.package_name: (change.before, change.after) for change in berry_result.changes}

    assert classic_result.parse_errors == ()
    assert classic_actual == {
        "brace-expansion": (None, "1.1.12"),
        "minimist": ("1.2.7", "1.2.8"),
    }
    assert berry_result.parse_errors == ()
    assert berry_actual == {
        "brace-expansion": (None, "1.1.12"),
        "minimist": ("1.2.7", "1.2.8"),
    }


def test_parse_manifest_dependency_changes_ignores_yarn_berry_metadata_sections() -> None:
    result = parse_manifest_dependency_changes(
        path="yarn.lock",
        before_text="__metadata:\n  version: 4\n  cacheKey: 8\n",
        after_text="__metadata:\n  version: 5\n  cacheKey: 9\n",
    )

    assert result.parse_errors == ()
    assert result.changes == ()


def test_parse_manifest_dependency_changes_supports_bun_text_lock() -> None:
    before_text = """{
      "lockfileVersion": 1,
      "packages": {
        "minimist": ["minimist@1.2.7", "", {"brace-expansion": "^1.1.11"}],
        "brace-expansion": ["brace-expansion@1.1.11", "", {}],
      },
    }
    """
    after_text = """{
      "lockfileVersion": 1,
      "packages": {
        "minimist": ["minimist@1.2.8", "", {"brace-expansion": "^1.1.12"}],
        "brace-expansion": ["brace-expansion@1.1.12", "", {}],
      },
    }
    """

    result = parse_manifest_dependency_changes(
        path="bun.lock",
        before_text=before_text,
        after_text=after_text,
    )

    actual = {change.package_name: (change.before, change.after) for change in result.changes}
    assert result.parse_errors == ()
    assert actual == {
        "brace-expansion": ("1.1.11", "1.1.12"),
        "minimist": ("1.2.7", "1.2.8"),
    }
