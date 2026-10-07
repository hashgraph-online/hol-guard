"""Desktop Python data and native code must come from the same attested wheel."""

import json
import runpy
import shutil
import stat
import sys
from pathlib import Path
from zipfile import ZipFile

import pytest
import yaml

from codex_plugin_scanner.guard.runtime.extension_trust import trust_map_from_bindings

ROOT = Path(__file__).resolve().parents[1]


def test_generation_and_staging_use_attested_compiler_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    generator = runpy.run_path(str(ROOT / "scripts/build_native_command_program.py"))
    stage = runpy.run_path(str(ROOT / "scripts/release/stage_guard_cloud_review_artifacts.py"))
    source_root = tmp_path / "source"
    (source_root / "contributions/command-sources").mkdir(parents=True)
    (source_root / "contracts/extensions").mkdir(parents=True)
    shutil.copyfile(
        ROOT / "contributions/command-sources/command.blitcp.json",
        source_root / "contributions/command-sources/command.blitcp.json",
    )
    shutil.copytree(
        ROOT / "contracts/extensions/trust",
        source_root / "contracts/extensions/trust",
    )
    trust = trust_map_from_bindings(source_root / "contracts/extensions/trust")
    for source_name in stage["_STATIC_ARTIFACTS"]:
        if source_name in {
            "contracts/extensions/native-command-program.v1.json",
            "contracts/extensions/trust-class-map.v1.json",
        }:
            continue
        source = ROOT / source_name
        destination = source_root / source_name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    for family in ("extensions", "mcp-servers"):
        (source_root / "contributions" / family).mkdir(parents=True, exist_ok=True)
    shutil.copyfile(
        ROOT / "contributions/extensions/command.blitcp.json",
        source_root / "contributions/extensions/command.blitcp.json",
    )
    shutil.copyfile(
        ROOT / "contributions/mcp-servers/mcp.filesystem.json",
        source_root / "contributions/mcp-servers/mcp.filesystem.json",
    )

    implementation_digest = "i" * 64
    descriptor_ids = (
        "command.blitcp",
        "command.noodle",
        "command.ollama",
        "command.probe",
        "command.repo2nb",
        "command.skill-sunset",
        "command.tui-runner",
        "command.uivoid",
    )
    compiled = {
        "catalog": [],
        "descriptors": [{"id": identity, "fixture": True} for identity in descriptor_ids],
        "program": {
            "catalog_digest": "c" * 64,
            "program_digest": "p" * 64,
        },
        "source_digest": "s" * 64,
        "implementation_digest": implementation_digest,
        "catalog_projection_kind": "complete",
    }
    compiler = tmp_path / "guard-command-source"
    compiler.write_text(
        "#!/usr/bin/env python3\n"
        "import json\n"
        "import sys\n"
        "sys.stdin.read()\n"
        f"payload = {trust!r} if sys.argv[1] == 'export-trust' else {compiled!r}\n"
        "print(json.dumps(payload, sort_keys=True, separators=(',', ':')))\n",
        encoding="utf-8",
    )
    compiler.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    wheel = tmp_path / "attested-platform.whl"
    member = "codex_plugin_scanner/_native/guard-command-source"
    with ZipFile(wheel, "w") as archive:
        archive.write(compiler, member)
    extracted_compiler = tmp_path / "extracted-guard-command-source"
    with ZipFile(wheel) as archive:
        extracted_compiler.write_bytes(archive.read(member))
    extracted_compiler.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    generator_globals = generator["main"].__globals__
    generator_globals["ROOT"] = source_root
    generator_globals["ARTIFACT"] = source_root / "contracts/extensions/native-command-program.v1.json"
    generator_globals["implementation_digest"] = lambda: implementation_digest
    monkeypatch.setattr(
        sys,
        "argv",
        ["build_native_command_program.py", "--compiler", str(extracted_compiler)],
    )
    assert generator["main"]() == 0

    staged_root = tmp_path / "staged"
    stage["stage_artifacts"](source_root, destination_root=staged_root)
    generated = source_root / "contracts/extensions/native-command-program.v1.json"
    staged = staged_root / "extensions/native-command-program.v1.json"
    assert json.loads(generated.read_text(encoding="utf-8"))["program_digest"] == "p" * 64
    assert staged.read_bytes() == generated.read_bytes()
    staged_trust = staged_root / "extensions/trust-class-map.v1.json"
    assert json.loads(staged_trust.read_bytes()) == trust
    assert staged_trust.read_bytes() == (source_root / "contracts/extensions/trust-class-map.v1.json").read_bytes()
    assert (staged_root / "extensions/contributions/command.blitcp.json").is_file()


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
