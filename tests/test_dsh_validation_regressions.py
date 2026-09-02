"""Regression tests for native DeepSeek Harness package validation."""

from codex_plugin_scanner.deepseek_harness_support import (
    DSH_SEMVER_RE,
    _exports_apply,
    _runtime_path,
)


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
