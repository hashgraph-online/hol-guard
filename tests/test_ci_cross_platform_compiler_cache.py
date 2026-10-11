"""The macOS runtime build must reuse content-addressed objects."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / ".github/actions/ci-job-cross-platform/action.yml"


def _steps() -> list[dict]:
    return yaml.load(ACTION.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)["runs"]["steps"]


def _index(steps: list[dict], needle: str) -> int:
    return next(i for i, step in enumerate(steps) if needle in step.get("name", ""))


def test_runtime_builds_run_after_the_compiler_cache_is_routed() -> None:
    steps = _steps()
    routed = _index(steps, "Route the runtime build through the compiler cache")
    assert _index(steps, "Install content-addressed compiler cache") < routed
    assert routed < _index(steps, "Build the native runtime for skill-directory identity")
    script = steps[routed]["run"]
    assert "RUSTC_WRAPPER=sccache" in script
    assert "SCCACHE_GHA_VERSION=cross-platform-runtime" in script


def test_only_main_pushes_write_the_cross_platform_compiler_cache() -> None:
    step = _steps()[_index(_steps(), "Route the runtime build through the compiler cache")]
    assert step["env"]["SCCACHE_MODE"] == (
        "${{ (github.event_name == 'push' && github.ref == 'refs/heads/main') && 'READ_WRITE' || 'READ_ONLY' }}"
    )
    assert "SCCACHE_GHA_RW_MODE=${SCCACHE_MODE}" in step["run"]
