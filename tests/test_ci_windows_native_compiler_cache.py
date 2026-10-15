"""The Windows release build must reuse trusted compiler objects on cache misses."""

from __future__ import annotations

from tests.support.ci_workflow import composite_action_steps


def _steps() -> list[dict]:
    return composite_action_steps("ci-job-windows-native-runtime")


def test_windows_runtime_cache_miss_still_builds_the_exact_release_binary() -> None:
    steps = _steps()
    miss = "steps.runtime-cache.outputs.cache-hit != 'true'"
    restore = next(step for step in steps if step.get("id") == "runtime-cache")
    rust = next(step for step in steps if step.get("uses") == "./.github/actions/setup-rust")
    cache = next(step for step in steps if step.get("name") == "Install content-addressed compiler cache")
    build = next(step for step in steps if step.get("name") == "Build the Windows native runtime")
    upload = next(step for step in steps if step.get("name") == "Upload the Windows native runtime")

    assert steps.index(restore) < steps.index(rust) < steps.index(cache) < steps.index(build) < steps.index(upload)
    assert rust["if"] == cache["if"] == build["if"] == miss
    assert cache["uses"] == "mozilla-actions/sccache-action@fc920bf0ec8de6ee65d409111f7ec508035751ba"
    assert cache["with"]["version"] == "v0.18.0"
    assert not any(step.get("continue-on-error", False) for step in (cache, build, upload))
    assert (
        "cargo build --manifest-path rust/Cargo.toml --locked --release "
        "-p hol-guard-runtime --bin hol-guard-runtime"
    ) in build["run"]
    assert upload["with"]["path"] == "rust/target/release/hol-guard-runtime.exe"
    assert upload["with"]["if-no-files-found"] == "error"


def test_only_trusted_main_pushes_write_windows_compiler_cache() -> None:
    steps = _steps()
    build = next(step for step in steps if step.get("name") == "Build the Windows native runtime")
    env = build["env"]
    assert env["RUSTC_WRAPPER"] == "sccache"
    assert env["SCCACHE_GHA_ENABLED"] == "on"
    assert env["SCCACHE_GHA_VERSION"] == "windows-ci-runtime-fast-v1"
    assert env["SCCACHE_GHA_RW_MODE"] == (
        "${{ (github.event_name == 'push' && github.ref == 'refs/heads/main') && 'READ_WRITE' || 'READ_ONLY' }}"
    )
    assert env["SCCACHE_IGNORE_SERVER_IO_ERROR"] == "1"

    saved = next(step for step in steps if step.get("uses", "").startswith("actions/cache/save@"))
    assert saved["if"] == (
        "steps.runtime-cache.outputs.cache-hit != 'true' && "
        "github.event_name == 'push' && github.ref == 'refs/heads/main'"
    )
    restore = next(step for step in steps if step.get("id") == "runtime-cache")
    assert "hashFiles('rust/**', 'contributions/**', 'contracts/**', 'spec/**'" in restore["with"]["key"]
    assert "env.CARGO_PROFILE_RELEASE_LTO" in restore["with"]["key"]
    assert "env.CARGO_PROFILE_RELEASE_CODEGEN_UNITS" in restore["with"]["key"]
