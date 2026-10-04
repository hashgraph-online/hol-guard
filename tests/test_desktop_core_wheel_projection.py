"""Desktop Python data and native code must come from the same attested wheel."""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    ("workflow", "job", "wheel"),
    [
        ("desktop-core-alpha-feed.yml", "publish-macos-arm64", "attested-macos-arm64.whl"),
        ("desktop-core-linux-feed.yml", "publish-linux-x64", "attested-linux-x64.whl"),
    ],
)
def test_freezing_collects_the_attested_wheel_not_editable_source(workflow: str, job: str, wheel: str) -> None:
    payload = yaml.safe_load((ROOT / ".github" / "workflows" / workflow).read_text())
    steps = payload["jobs"][job]["steps"]
    run = next(step["run"] for step in steps if step.get("name") == "Build standalone Core executable")
    install = 'uv pip install --python "$SOURCE/.venv/bin/python" --no-deps --force-reinstall "${WHEELS[0]}"'
    comparison = f'cmp "${{WHEELS[0]}}" "$RUNNER_TEMP/{wheel}"'
    assert 'test "${#WHEELS[@]}" -eq 1' in run
    assert run.index("stage_native_runtime_for_desktop_core.py") < run.index(comparison) < run.index(install)
    assert run.index(install) > run.rindex("uv sync")
    assert run.index(install) < run.index("uv run --no-sync pyinstaller")
    assert "uv sync" not in run[run.index(install) :]


@pytest.mark.parametrize(
    ("workflow", "wheel"),
    [
        ("desktop-core-alpha-feed.yml", "attested-macos-arm64.whl"),
        ("desktop-core-linux-feed.yml", "attested-linux-x64.whl"),
    ],
)
def test_build_regenerates_missing_native_projections_from_attested_wheel(workflow: str, wheel: str) -> None:
    payload = yaml.safe_load((ROOT / ".github" / "workflows" / workflow).read_text())
    steps = payload["jobs"]["publish-macos-arm64" if "alpha" in workflow else "publish-linux-x64"]["steps"]
    run = next(step["run"] for step in steps if step.get("name") == "Build standalone Core executable")
    compiler = "\n".join(
        (
            'unzip -p "$RUNNER_TEMP/' + wheel + '" \\',
            '  codex_plugin_scanner/_native/guard-command-source > "$SOURCE_COMPILER"',
        )
    )
    generate = "\n".join(
        (
            'python3 -I "$SOURCE/scripts/build_native_command_program.py" \\',
            '  --compiler "$SOURCE_COMPILER"',
        )
    )
    assert compiler in run
    assert 'SOURCE_COMPILER="$RUNNER_TEMP/guard-command-source"' in run
    assert 'chmod 0755 "$SOURCE_COMPILER"' in run
    assert generate in run
    assert run.index(generate) < run.index("stage_guard_cloud_review_artifacts.py")
