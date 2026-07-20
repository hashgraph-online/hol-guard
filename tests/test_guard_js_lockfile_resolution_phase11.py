"""Phase 11 lockfile resolution regressions for JavaScript package evaluation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.runtime.lockfile_parse_result as lockfile_parse_module
import codex_plugin_scanner.guard.runtime.supply_chain_package_eval as evaluator_module
from codex_plugin_scanner.guard.runtime.lockfile_parse_result import LOCKFILE_MAX_BYTES
from codex_plugin_scanner.guard.runtime.package_manifest_diff import _DeadlineExceededError
from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import evaluate_package_request_artifact
from codex_plugin_scanner.guard.stable_digest import stable_digest_hex
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_js_supply_chain_phase11 import (
    WORKSPACE_ID,
    _artifact_from_command,
    _bundle_response,
    _package,
    _write_text,
)


def test_evaluate_package_request_artifact_preserves_direct_version_when_package_lock_contains_nested_duplicate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(
        workspace_dir / "package.json",
        '{"name":"demo","dependencies":{"minimist":"^1.2.0","react":"17.0.0"}}\n',
    )
    _write_text(
        workspace_dir / "package-lock.json",
        (
            '{"dependencies":{"minimist":{"version":"1.2.9"},"react":{"version":"17.0.0",'
            '"dependencies":{"minimist":{"version":"1.2.8"}}}}}\n'
        ),
    )
    store = GuardStore(home_dir)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        _bundle_response(packages=[_package(name="minimist", version="1.2.8", default_action="block")]),
        "2026-05-19T00:00:00Z",
    )

    artifact = _artifact_from_command("npm install minimist@^1.2.0", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "block"
    assert result.packages[0]["dependencyPath"] == "react/node_modules/minimist"
    assert any(package["resolvedVersion"] == "1.2.9" and package["decision"] == "allow" for package in result.packages)


def test_evaluate_package_request_artifact_resolves_alias_range_from_package_lock_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(workspace_dir / "package.json", '{"name":"demo","dependencies":{"guard-safe":"npm:minimist@^1.2.0"}}\n')
    _write_text(
        workspace_dir / "package-lock.json",
        (
            '{"lockfileVersion":3,"packages":{"":{"dependencies":{"guard-safe":"npm:minimist@^1.2.0"}},'
            '"node_modules/guard-safe":{"name":"minimist","version":"1.2.8"}}}\n'
        ),
    )
    store = GuardStore(home_dir)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        _bundle_response(packages=[_package(name="minimist", version="1.2.8", default_action="block")]),
        "2026-05-19T00:00:00Z",
    )

    artifact = _artifact_from_command("npm install guard-safe@npm:minimist@^1.2.0", workspace=workspace_dir)
    result = evaluate_package_request_artifact(artifact=artifact, store=store, workspace_dir=workspace_dir)

    assert result.decision == "block"
    assert result.packages[0]["resolvedVersion"] == "1.2.8"
    assert result.user_copy.next_step == "npm install guard-safe@npm:minimist@1.2.9"


def test_recursive_package_lock_deadline_raises_instead_of_returning_partial_entries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ticks = iter((0.0, 1.0))
    monkeypatch.setattr(evaluator_module.time, "monotonic", lambda: next(ticks))
    lockfile_text = json.dumps(
        {
            "dependencies": {
                "safe-first": {
                    "version": "1.0.0",
                    "dependencies": {"risky-last": {"version": "9.9.9"}},
                }
            }
        }
    )

    with pytest.raises(_DeadlineExceededError, match="deadline_exceeded"):
        evaluator_module._package_lock_entries(lockfile_text, deadline=0.5)


@pytest.mark.parametrize(
    ("lockfile_name", "lockfile_text", "error_reason"),
    [
        ("package-lock.json", "{broken", "syntax_error"),
        ("package-lock.json", '{"packages":{"node_modules/a":{"version":"1.0.0"}}', "syntax_error"),
        (
            "package-lock.json",
            '{"packages":{"node_modules/a":{"version":"1"},"node_modules/a":{"version":"2"}}}',
            "duplicate_key",
        ),
        ("package-lock.json", '{"lockfileVersion":99,"packages":{}}', "unsupported_version"),
        ("package-lock.json", '{"lockfileVersion":3,"packages":[]}', "unsupported_shape"),
        ("bun.lock", '{"lockfileVersion":99,"packages":{}}', "unsupported_version"),
        ("bun.lock", '{"lockfileVersion":1,"packages":[]}', "unsupported_shape"),
        ("bun.lock", '{"lockfileVersion":1,"packages":{"demo":[]}}', "parse_error"),
        ("Cargo.lock", "version = [\n", "syntax_error"),
        ("poetry.lock", "[[package]\nname = 'demo'\n", "syntax_error"),
        ("pnpm-lock.yaml", "packages:\n  truncated-entry\n", "syntax_error"),
        ("yarn.lock", '"demo@1.0.0"\n  version "1.0.0"\n', "syntax_error"),
        ("yarn.lock", "#" * (LOCKFILE_MAX_BYTES + 1), "byte_limit_exceeded"),
    ],
)
def test_lockfile_parse_result_rejects_incomplete_or_unsupported_inputs(
    lockfile_name: str,
    lockfile_text: str,
    error_reason: str,
) -> None:
    result = evaluator_module._parse_lockfile_text_result(lockfile_name, lockfile_text)

    assert result.complete is False
    assert result.entries == ()
    assert result.error_reason == error_reason
    assert result.source_hash == stable_digest_hex(lockfile_text.encode("utf-8"))
    assert result.parser_version == "complete-v1"
    assert result.budget_ms == 200


def test_lockfile_parse_result_rejects_excessive_json_depth() -> None:
    nested: object = "leaf"
    for _index in range(130):
        nested = {"next": nested}
    lockfile_text = json.dumps({"lockfileVersion": 3, "packages": {}, "metadata": nested})

    result = evaluator_module._parse_lockfile_text_result("package-lock.json", lockfile_text)

    assert result.complete is False
    assert result.error_reason == "depth_limit_exceeded"


def test_lockfile_parse_result_rejects_dependency_count_over_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lockfile_parse_module, "LOCKFILE_MAX_ENTRIES", 1)
    lockfile_text = json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {
                "node_modules/first": {"version": "1.0.0"},
                "node_modules/second": {"version": "2.0.0"},
            },
        }
    )

    result = evaluator_module._parse_lockfile_text_result("package-lock.json", lockfile_text)

    assert result.complete is False
    assert result.entries == ()
    assert result.error_reason == "entry_limit_exceeded"


def test_lockfile_parse_result_fail_closes_on_unexpected_dependency_parser_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_parser_failure(*args: object, **kwargs: object) -> dict[str, str]:
        del args, kwargs
        raise RuntimeError("unexpected parser failure")

    monkeypatch.setattr(evaluator_module, "_dependency_map_for_path", unexpected_parser_failure)

    result = evaluator_module._parse_lockfile_text_result("Cargo.lock", "")

    assert result.complete is False
    assert result.entries == ()
    assert result.error_reason == "parse_error"


def test_bun_jsonc_lockfile_is_parsed_completely() -> None:
    lockfile_text = """{
      // Bun's text lockfile supports JSONC.
      "lockfileVersion": 1,
      "packages": {
        "left-pad": ["left-pad@1.3.0", "", {}, "sha512-demo",],
        "@scope/demo": ["@scope/demo@2.4.1", "", {},],
        "local": ["local@workspace:packages/local"],
      },
    }
    """

    result = evaluator_module._parse_lockfile_text_result("bun.lock", lockfile_text)

    assert result.complete is True
    assert {(entry.package_name, entry.version) for entry in result.entries} == {
        ("@scope/demo", "2.4.1"),
        ("left-pad", "1.3.0"),
    }


@pytest.mark.parametrize(
    "lockfile_name",
    [
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "bun.lock",
        "Cargo.lock",
        "composer.lock",
        "Gemfile.lock",
        "poetry.lock",
        "uv.lock",
        "Pipfile.lock",
    ],
)
def test_lockfile_parse_result_distinguishes_valid_empty_lockfile_from_failure(lockfile_name: str) -> None:
    result = evaluator_module._parse_lockfile_text_result(lockfile_name, "")

    assert result.complete is True
    assert result.entries == ()
    assert result.error_reason is None


def test_incomplete_lockfile_evidence_contains_hash_and_reason_without_contents(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(workspace_dir / "package.json", '{"name":"demo","dependencies":{"minimist":"^1.2.0"}}\n')
    malformed_lockfile = '{"lockfileVersion":3,"packages":{"node_modules/secret-fixture":'
    _write_text(workspace_dir / "package-lock.json", malformed_lockfile)
    store = GuardStore(home_dir)

    result = evaluate_package_request_artifact(
        artifact=_artifact_from_command("npm install minimist@^1.2.0", workspace=workspace_dir),
        store=store,
        workspace_dir=workspace_dir,
    )

    assert result.decision == "ask"
    assert result.policy_action == "require-reapproval"
    package = result.packages[0]
    assert package["lockfileParseError"] == "syntax_error"
    assert package["lockfileHash"] == stable_digest_hex(malformed_lockfile.encode("utf-8"))
    evidence_payload = json.dumps(store.list_evidence(), sort_keys=True)
    assert package["lockfileHash"] in evidence_payload
    assert "lockfile_parse_incomplete" in evidence_payload
    assert malformed_lockfile not in evidence_payload


def test_incomplete_lockfile_blocks_in_strict_mode(tmp_path: Path) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    _write_text(workspace_dir / "package.json", '{"name":"demo","dependencies":{"minimist":"^1.2.0"}}\n')
    _write_text(workspace_dir / "package-lock.json", '{"lockfileVersion":99,"packages":{}}\n')
    store = GuardStore(home_dir)
    store.guard_home.mkdir(parents=True, exist_ok=True)
    _write_text(store.guard_home / "config.toml", 'security_level = "strict"\n')

    result = evaluate_package_request_artifact(
        artifact=_artifact_from_command("npm install minimist@^1.2.0", workspace=workspace_dir),
        store=store,
        workspace_dir=workspace_dir,
    )

    assert result.decision == "block"
    assert result.policy_action == "block"
    assert result.packages[0]["lockfileParseError"] == "unsupported_version"


def test_late_incomplete_lockfile_result_is_not_deduplicated_against_direct_package(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    lockfile_text = json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"react": "18.0.0"}},
                "node_modules/react": {"version": "18.0.0"},
            },
        }
    )
    _write_text(workspace_dir / "package-lock.json", lockfile_text)
    store = GuardStore(home_dir)
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        _bundle_response(packages=[_package(name="react", version="18.0.0", default_action="allow")]),
        "2026-05-19T00:00:00Z",
    )
    real_parser = evaluator_module._parse_lockfile_text_result
    parse_calls = 0

    def changing_parser(path: str, text: str):
        nonlocal parse_calls
        parse_calls += 1
        if parse_calls == 3:
            return lockfile_parse_module.incomplete_lockfile_result(
                path,
                text.encode("utf-8"),
                error_reason="parse_error",
                budget_ms=200,
            )
        return real_parser(path, text)

    monkeypatch.setattr(evaluator_module, "_parse_lockfile_text_result", changing_parser)

    result = evaluate_package_request_artifact(
        artifact=_artifact_from_command("npm install react@18.0.0", workspace=workspace_dir),
        store=store,
        workspace_dir=workspace_dir,
        now="2026-05-19T00:00:00Z",
    )

    assert parse_calls >= 3
    assert result.decision == "ask"
    assert any(package.get("lockfileParseComplete") is False for package in result.packages)
    assert any(reason["code"] == "lockfile_parse_incomplete" for reason in result.reasons)
