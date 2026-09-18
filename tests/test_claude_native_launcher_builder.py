"""The private launcher investigation must use its supported installed wheel."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from scripts import build_native_qualification_artifacts as builder


@pytest.mark.parametrize(
    "target, expected_count, expected_provision_count",
    [
        ("x86_64-unknown-linux-musl", 1, 1),
        ("x86_64-apple-darwin", 0, 1),
        ("aarch64-apple-darwin", 0, 1),
        ("x86_64-pc-windows-msvc", 0, 0),
    ],
)
@pytest.mark.parametrize("failure_stage", ["paired_sampling", "qualification_interpreters"])
def test_supported_installed_pilot_remains_independent_of_earlier_failures(
    tmp_path, monkeypatch, target, expected_count, expected_provision_count, failure_stage
):
    baseline = tmp_path / "baseline"
    candidate = tmp_path / "candidate"
    baseline.mkdir()
    candidate.mkdir()
    (candidate / "uv.lock").write_text('[[package]]\nname = "psutil"\nversion = "7.2.2"\n')
    installed_python = candidate / "installed-python"
    wheel = candidate / "candidate.whl"
    seen = []

    def build(source, **_kwargs):
        return source / "installed-python", wheel, {"source_sha": "a" * 40}

    def run(argv, **kwargs):
        if argv[0] == "uv":
            return ""
        seen.append(argv)
        assert kwargs["cwd"] == candidate
        failure_script = {
            "paired_sampling": "qualify_guard_native.py",
            "qualification_interpreters": "provision_native_qualification_interpreters.py",
        }[failure_stage]
        if Path(argv[2 if argv[1] == "-I" else 1]).name == failure_script:
            raise subprocess.CalledProcessError(1, argv)
        return ""

    monkeypatch.setattr(builder, "_build", build)
    monkeypatch.setattr(builder, "_run", run)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "builder",
            "--baseline",
            str(baseline),
            "--candidate",
            str(candidate),
            "--target",
            target,
            "--platform-tag",
            "test",
            "--output-dir",
            str(tmp_path / "evidence"),
        ],
    )
    if failure_stage == "paired_sampling" or expected_provision_count:
        with pytest.raises(RuntimeError) as failed:
            builder.main()
        assert str(failed.value) == "installed qualification failed: " + failure_stage
    else:
        assert builder.main() == 0
    pilot_calls = [argv for argv in seen if any("bench_claude_native_launcher_pilot.py" in arg for arg in argv)]
    assert len(pilot_calls) == expected_count
    provision_calls = [
        argv for argv in seen if any("provision_native_qualification_interpreters.py" in arg for arg in argv)
    ]
    assert len(provision_calls) == expected_provision_count
    if provision_calls:
        assert provision_calls[0] == [
            str(installed_python),
            "-I",
            str(candidate / "scripts/provision_native_qualification_interpreters.py"),
            "--baseline-python",
            str(baseline / "installed-python"),
            "--candidate-python",
            str(installed_python),
            "--json",
            str(tmp_path / "evidence/aggregate/qualification-interpreters.json"),
        ]
        assert seen[0] == provision_calls[0]
    if pilot_calls:
        assert pilot_calls[0] == [
            str(installed_python),
            "-I",
            str(candidate / "scripts/bench_claude_native_launcher_pilot.py"),
            "--wheel",
            str(wheel),
            "--blocks",
            "5",
            "--samples",
            "30",
            "--json",
            str(tmp_path / "evidence/aggregate/installed-claude-launcher-pilot.json"),
        ]
        assert seen[-1] == pilot_calls[0]
