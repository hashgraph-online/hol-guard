"""Regression tests for native DeepSeek Harness package validation."""

from pathlib import Path

import pytest

from codex_plugin_scanner.deepseek_harness_support import (
    DSH_SEMVER_RE,
    _exports_apply,
    _runtime_path,
    validate_dsh_package,
)
from codex_plugin_scanner.ecosystems.types import Ecosystem, NormalizedPackage


def test_dsh_semver_accepts_preview_versions() -> None:
    assert DSH_SEMVER_RE.fullmatch("0.1.0-preview.5")
    assert DSH_SEMVER_RE.fullmatch("0.1.0-rc.8+build.1")


def test_dsh_apply_detection_ignores_non_code_literals() -> None:
    assert not _exports_apply("// export function apply(ctx) {}")
    assert not _exports_apply("const text = 'exports.apply = fake'")
    assert not _exports_apply("const pattern = /export function apply/")


def test_dsh_apply_detection_respects_exported_alias() -> None:
    assert _exports_apply("const handler = () => {}; export { handler as apply }")
    assert not _exports_apply("const apply = () => {}; export { apply as handler }")
    assert not _exports_apply("export type { apply }")


def test_dsh_apply_detection_supports_commonjs_objects() -> None:
    assert _exports_apply("module.exports = { apply }")
    assert _exports_apply("module.exports = { apply: handler }")
    assert _exports_apply("module.exports = { apply(ctx) {} }")
    assert _exports_apply("module.exports = { async apply(ctx) {} }")
    assert not _exports_apply("module.exports = { handler: apply }")


def test_dsh_runtime_resolution_rejects_subpath_only_exports() -> None:
    manifest = {
        "main": "./legacy.js",
        "exports": {
            "./client": "./client.js",
            "./package.json": "./package.json",
        },
    }
    assert _runtime_path(manifest) is None


def _patch_only_package(tmp_path: Path, manifest: dict[str, object]) -> NormalizedPackage:
    patch = tmp_path / "cordis.patch.yml"
    patch.write_text("skills:\n  - ./skills\n", encoding="utf-8")
    return NormalizedPackage(
        ecosystem=Ecosystem.DEEPSEEK_HARNESS,
        package_kind="cordis-plugin",
        root_path=tmp_path,
        raw_manifest=manifest,
    )


def test_dsh_patch_mode_skips_runtime_when_no_entry_point(tmp_path: Path) -> None:
    package = _patch_only_package(
        tmp_path,
        {
            "name": "dsh-patch-bundle",
            "version": "1.0.0",
            "dsh": {"bundle": {"patch": "cordis.patch.yml", "mode": "patch"}},
        },
    )
    validation = validate_dsh_package(package)
    assert validation.bundle_ok is True
    assert validation.patch_ok is True
    assert validation.runtime_required is False
    assert validation.runtime_ok is True


def test_dsh_patch_mode_still_requires_apply_when_entry_point_exists(tmp_path: Path) -> None:
    (tmp_path / "index.js").write_text("export const name = 'missing-apply'\n", encoding="utf-8")
    package = _patch_only_package(
        tmp_path,
        {
            "name": "dsh-patch-bundle",
            "version": "1.0.0",
            "main": "index.js",
            "dsh": {"bundle": {"patch": "cordis.patch.yml", "mode": "patch"}},
        },
    )
    validation = validate_dsh_package(package)
    assert validation.runtime_required is True
    assert validation.runtime_ok is False


@pytest.mark.parametrize(
    "runtime_fields",
    [
        {"main": ""},
        {"main": 1},
        {"exports": None},
        {"exports": {}},
        {"exports": {"./client": "./client.js"}},
    ],
)
def test_dsh_patch_mode_requires_runtime_when_entry_fields_are_declared(
    tmp_path: Path, runtime_fields: dict[str, object]
) -> None:
    package = _patch_only_package(
        tmp_path,
        {
            "name": "dsh-patch-bundle",
            "version": "1.0.0",
            "dsh": {"bundle": {"patch": "cordis.patch.yml", "mode": "patch"}},
            **runtime_fields,
        },
    )
    validation = validate_dsh_package(package)
    assert validation.runtime_required is True
    assert validation.runtime_ok is False


def test_dsh_unknown_bundle_mode_is_invalid(tmp_path: Path) -> None:
    package = _patch_only_package(
        tmp_path,
        {
            "name": "dsh-patch-bundle",
            "version": "1.0.0",
            "dsh": {"bundle": {"patch": "cordis.patch.yml", "mode": "skills"}},
        },
    )
    validation = validate_dsh_package(package)
    assert validation.bundle_ok is False
