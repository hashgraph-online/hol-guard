"""Independent supported text projections and complete-result admission tests."""

from __future__ import annotations

import random
import time
from pathlib import Path

import pytest

import codex_plugin_scanner.guard.runtime.lockfile_parse_result as parse_module
import codex_plugin_scanner.guard.runtime.package_manifest_diff as manifest_module
import codex_plugin_scanner.guard.runtime.supply_chain_package_eval as evaluator
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_supply_chain_evaluator import WORKSPACE_ID, _artifact_for_targets, _bundle_response, _package


def _parse(name: str, text: str | bytes):
    return parse_module.parse_lockfile_text(
        name,
        text,
        deadline=time.monotonic() + 2,
        budget_ms=2000,
        dependency_parser=manifest_module._dependency_map_for_path,
        package_lock_parser=evaluator._package_lock_entries,
    )


def _target(name: str, requested: str, alias: str | None = None):
    return {"normalized_name": name, "name": name, "namespace": None, "range": requested, "alias": alias}


@pytest.mark.parametrize("seed", range(40))
def test_text_views_preserve_legacy_order_aliases_and_versions(seed: int) -> None:
    rng = random.Random(seed)
    names = ["minimist", "@scope/demo", "unicode-\u03b1", "alias", "root-only", "transitive"]
    rng.shuffle(names)
    versions = ["1.2.3", "2.0.0-beta.1", "3.0.0+build", "4.0.0(peer@1.0.0)"]
    pnpm = ["lockfileVersion: '9.0'", "importers:", "  .:", "    dependencies:"]
    for name in names:
        pnpm += [f"      '{name}':", "        specifier: ^1.0.0", f"        version: {rng.choice(versions)}"]
    pnpm += ["  packages/child:", "    dependencies:", "      root-only: 9.9.9", "packages:"]
    for name in names:
        pnpm += [f"  '{name}@{rng.choice(versions)}':", "    resolution: {integrity: test}"]
    pnpm += ["snapshots:", "  root-only@1.0.0:", "    dependencies:", "      transitive: 2.3.4"]
    yarn = ["# synthetic classic and Berry declaration-order cases", "__metadata:", "  version: 8"]
    for name in names + names[:2]:
        version = rng.choice(versions)
        yarn += [f'"{name}@^1.0.0", "{name}@npm:^1.0.0":', f'  version "{version}"']
        yarn += [f'"{name}@^2.0.0":', '  version: "2.3.4"']
    yarn += ['"alias@npm:minimist@^1.0.0":', '  version "5.6.7"']
    targets = tuple(_target(name, requested) for name in names for requested in ("^1.0.0", "^2.0.0"))
    targets += (_target("minimist", "^1.0.0", "alias"),)
    for filename, lines, legacy_map, legacy_targets in (
        ("pnpm-lock.yaml", pnpm, manifest_module._pnpm_lock_dependency_map, evaluator._pnpm_lock_target_versions),
        ("yarn.lock", yarn, manifest_module._yarn_lock_dependency_map, evaluator._yarn_lock_target_versions),
    ):
        text = "\r\n".join(lines) + "\r\n"
        result = _parse(filename, text)
        assert result.complete, result.error_reason
        assert result.dependency_map() == legacy_map(text, float("inf"))
        actual = (
            evaluator._target_versions_from_direct_map(targets, dict(result.direct_version_candidates))
            if filename == "pnpm-lock.yaml"
            else evaluator._yarn_lock_target_versions_from_entries(result, targets)
        )
        assert actual == legacy_targets(text, targets)


@pytest.mark.parametrize(
    ("name", "text", "expected"),
    [
        (
            "package-lock.json",
            '{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.2.3"}}}',
            {"a": "1.2.3"},
        ),
        ("pnpm-lock.yaml", "packages:\n  a@1.2.3:\n    resolution: {}\n", {"a": "1.2.3"}),
        ("yarn.lock", '"a@^1.0.0":\n  version "1.2.3"\n', {"a": "1.2.3"}),
        ("bun.lock", '{// comment\n"packages":{"a":["a@1.2.3", "", {},],},}', {"a": "1.2.3"}),
        ("Cargo.lock", '[[package]]\nname="a"\nversion="1.2.3"\n', {"a": "1.2.3"}),
        ("composer.lock", '{"packages":[{"name":"a","version":"1.2.3"}]}', {"a": "1.2.3"}),
        ("Gemfile.lock", "GEM\n  specs:\n    a (1.2.3)\n      indirect (~> 1)\nDEPENDENCIES\n  a\n", {"a": "1.2.3"}),
        ("poetry.lock", '[[package]]\nname="a"\nversion="1.2.3"\n', {"a": "1.2.3"}),
        ("uv.lock", '[[package]]\nname="a"\nversion="1.2.3"\n', {"a": "1.2.3"}),
        ("Pipfile.lock", '{"default":{"a":{"version":"==1.2.3"}}}', {"a": "1.2.3"}),
    ],
)
def test_all_supported_formats_keep_dependency_completeness(name: str, text: str, expected: dict[str, str]) -> None:
    result = _parse(name, text.encode())
    assert result.complete
    assert result.dependency_map() == expected
    assert result.manifest_dependency_map() == expected
    assert result.parser_version == "complete-v1"
    assert _parse(name, text.encode() + b"\xff").error_reason == "decode_error"


@pytest.mark.parametrize("name", ["pnpm-lock.yaml", "yarn.lock", "Gemfile.lock"])
def test_text_validation_and_every_projection_share_one_source_traversal(name: str) -> None:
    class CountedText(str):
        calls = 0

        def splitlines(self, *args, **kwargs):
            self.calls += 1
            return super().splitlines(*args, **kwargs)

    text = CountedText(
        {
            "pnpm-lock.yaml": "dependencies:\n  a: 1.2.3\npackages:\n  a@1.2.3:\n",
            "yarn.lock": '"a@^1":\n  version "1.2.3"\n',
            "Gemfile.lock": "GEM\n  specs:\n    a (1.2.3)\n",
        }[name]
    )
    result = _parse(name, text)
    assert result.complete
    assert result.dependency_map() == {"a": "1.2.3"}
    assert text.calls == 1


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("pnpm-lock.yaml", "packages:\n  safe@1.0.0:\ntruncated\n"),
        ("yarn.lock", '"safe@^1":\n  version "1.0.0"\ntruncated\n'),
        ("Gemfile.lock", "GEM\n  specs:\n    safe (1.0.0)\n[truncated\n"),
    ],
)
def test_late_text_validation_failure_discards_every_view(name: str, text: str) -> None:
    result = _parse(name, text)
    assert not result.complete
    assert result.error_reason == "syntax_error"
    assert result.entries == result.direct_version_candidates == result.yarn_selector_versions == ()
    assert result.dependency_map() == result.manifest_dependency_map() == {}


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("pnpm-lock.yaml", "dependencies:\n  a: 1.0.0\n  b: 2.0.0\n"),
        ("yarn.lock", '"a@^1", "a@^2":\n  version "1.0.0"\n'),
        ("Gemfile.lock", "GEM\n  specs:\n    a (1.0.0)\n    b (2.0.0)\n"),
    ],
)
def test_all_new_text_views_share_entry_bound(monkeypatch: pytest.MonkeyPatch, name: str, text: str) -> None:
    monkeypatch.setattr(parse_module, "LOCKFILE_MAX_ENTRIES", 1)
    result = _parse(name, text)
    assert not result.complete
    assert result.error_reason == "entry_limit_exceeded"
    assert result.entries == result.direct_version_candidates == result.yarn_selector_versions == ()


@pytest.mark.parametrize(
    ("filename", "text", "package_manager"),
    [
        ("pnpm-lock.yaml", "dependencies:\n  minimist: 1.2.8\npackages:\n  minimist@1.2.8:\n", "pnpm"),
        ("yarn.lock", '"minimist@^1.2.0":\n  version "1.2.8"\n', "yarn"),
    ],
)
def test_production_target_resolution_reuses_text_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, filename: str, text: str, package_manager: str
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / filename).write_text(text)
    store = GuardStore(tmp_path / "guard")
    monkeypatch.setattr(store, "get_cloud_workspace_id", lambda: WORKSPACE_ID)
    store.cache_supply_chain_bundle(
        WORKSPACE_ID,
        _bundle_response(
            packages=[_package(ecosystem="npm", name="minimist", version="1.2.8", default_action="block")]
        ),
        "2026-05-19T00:00:00Z",
    )
    calls = []
    original = parse_module.parse_text_lockfile

    def capture(*args, **kwargs):
        calls.append(args[0])
        return original(*args, **kwargs)

    def reject_reparse(*args, **kwargs):
        raise AssertionError("Production reparsed an already captured text input")

    monkeypatch.setattr(parse_module, "parse_text_lockfile", capture)
    for name in ("_pnpm_lock_target_versions", "_yarn_lock_target_versions"):
        monkeypatch.setattr(evaluator, name, reject_reparse)
    artifact = _artifact_for_targets("minimist@^1.2.0", package_manager=package_manager, lockfile_paths=(filename,))
    result = evaluator.evaluate_package_request_artifact(
        artifact=artifact, store=store, workspace_dir=workspace, now="2026-05-19T00:00:00Z"
    )
    assert result.decision == "block"
    assert result.packages[0]["resolvedVersion"] == "1.2.8"
    assert calls == [filename]


def test_versionless_yarn_header_enforces_selector_limit_before_deduplication(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(parse_module, "LOCKFILE_MAX_ENTRIES", 10)
    header = ", ".join(f'"package-{index}@^1"' for index in range(10_000)) + ":\n"
    result = _parse("yarn.lock", header)
    assert not result.complete
    assert result.error_reason == "entry_limit_exceeded"
    assert result.entries == result.yarn_selector_versions == ()


def test_yarn_header_checks_deadline_within_one_long_line(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.runtime import lockfile_text_projection as text_parser

    ticks = iter((0.0, 0.0, 0.0, 2.0))
    monkeypatch.setattr(text_parser.time, "monotonic", lambda: next(ticks))
    header = ", ".join(f'"package-{index}@^1"' for index in range(100)) + ":\n"
    with pytest.raises(manifest_module._DeadlineExceededError):
        text_parser.parse_text_lockfile("yarn.lock", header, deadline=1.0, max_entries=1000)


def test_repeated_versionless_yarn_headers_share_selector_admission_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(parse_module, "LOCKFILE_MAX_ENTRIES", 1)
    result = _parse("yarn.lock", '"first@^1":\n"second@^2":\n')
    assert not result.complete
    assert result.error_reason == "entry_limit_exceeded"
    assert result.entries == result.yarn_selector_versions == ()
