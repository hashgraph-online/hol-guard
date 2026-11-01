"""Normalize only disposable hosted compiler inventories before cache hashing."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from scripts.ci import normalize_rust_toolchains as normalize

ROOT = Path(__file__).resolve().parents[1]
PINNED = "1.88.0-x86_64-unknown-linux-gnu"
ACTIVE = f"{PINNED} (default)\n"
UNUSED = "stable-x86_64-unknown-linux-gnu"
WINDOWS_HOST = "x86_64-pc-windows-msvc"
WINDOWS_PINNED = f"1.88.0-{WINDOWS_HOST}"


@pytest.mark.parametrize("flags", ["default", "active, default", "default, active"])
def test_retains_host_qualified_pinned_default(flags: str) -> None:
    installed = f"1.99.1-x86_64-unknown-linux-gnu\n{PINNED} ({flags})\n{UNUSED}\n"
    assert normalize.removals("1.88.0", installed, ACTIVE) == [
        "1.99.1-x86_64-unknown-linux-gnu",
        UNUSED,
    ]
    assert normalize.removals("1.88.0", ACTIVE, ACTIVE) == []


@pytest.mark.parametrize(
    ("requested", "installed", "active"),
    [
        ("stable", ACTIVE, ACTIVE),
        ("1.88.0", "", ACTIVE),
        ("1.88.0", ACTIVE + ACTIVE, ACTIVE),
        ("1.88.0", ACTIVE + "unexpected output with spaces\n", ACTIVE),
        ("1.88.0", ACTIVE + "--help\n", ACTIVE),
        ("1.88.0", f"{UNUSED} (default)\n", f"{UNUSED} (default)\n"),
        ("1.88.0", ACTIVE, f"{PINNED} (active)\n"),
        ("1.88.0", ACTIVE, ACTIVE + ACTIVE),
        ("1.88.0", f"{PINNED}\n{UNUSED} (default)\n", ACTIVE),
        ("1.88.0", ACTIVE + f"{UNUSED} (default)\n", ACTIVE),
        ("1.88.0", ACTIVE, "1.88.0 (default)\n"),
    ],
)
def test_rejects_ambiguous_inventory_before_removing_anything(
    requested: str,
    installed: str,
    active: str,
) -> None:
    with pytest.raises(ValueError):
        normalize.removals(requested, installed, active)


@pytest.mark.parametrize(
    ("actions", "environment", "runner_os"),
    [
        ("", "", ""),
        ("true", "self-hosted", "Linux"),
        ("false", "github-hosted", "Linux"),
        ("true", "", "Linux"),
        ("true", "github-hosted", "macOS"),
        ("true", "self-hosted", "Windows"),
        ("false", "github-hosted", "Windows"),
    ],
)
def test_never_invokes_rustup_outside_supported_hosted_runner(
    monkeypatch: pytest.MonkeyPatch,
    actions: str,
    environment: str,
    runner_os: str,
) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", actions)
    monkeypatch.setenv("RUNNER_ENVIRONMENT", environment)
    monkeypatch.setenv("RUNNER_OS", runner_os)
    monkeypatch.setattr(sys, "argv", ["normalize", "--toolchain", "1.88.0"])

    def unexpected(*_args: object, **_kwargs: object) -> None:
        pytest.fail("local/self-hosted normalization must not invoke rustup")

    monkeypatch.setattr(normalize.subprocess, "run", unexpected)
    normalize.main()


@pytest.mark.parametrize("malformed", [False, True])
def test_validates_inventory_and_default_before_any_uninstall(
    monkeypatch: pytest.MonkeyPatch,
    malformed: bool,
) -> None:
    for name, value in {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "Linux"}.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "argv", ["normalize", "--toolchain", "1.88.0"])
    calls: list[list[str]] = []

    def rustup(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert kwargs["check"] is True
        calls.append(arguments)
        if arguments == ["rustup", "toolchain", "list"]:
            output = ACTIVE + ("bad inventory line" if malformed else UNUSED)
        elif arguments == ["rustup", "show", "active-toolchain"]:
            output = ACTIVE
        else:
            assert arguments == ["rustup", "toolchain", "uninstall", UNUSED]
            output = ""
        return subprocess.CompletedProcess(arguments, 0, output)

    monkeypatch.setattr(normalize.subprocess, "run", rustup)
    if malformed:
        with pytest.raises(ValueError):
            normalize.main()
    else:
        normalize.main()
    assert calls[:2] == [["rustup", "toolchain", "list"], ["rustup", "show", "active-toolchain"]]
    assert calls[2:] == ([] if malformed else [["rustup", "toolchain", "uninstall", UNUSED]])


def test_windows_runner_patch_drift_leaves_identical_compiler_key_inputs() -> None:
    normalized = []
    for version in ("1.99.0", "1.99.1"):
        active = f"{WINDOWS_PINNED} (default)\n"
        installed = f"{version}-{WINDOWS_HOST}\n{active}"
        removed = normalize.removals("1.88.0", installed, active, expected_host=WINDOWS_HOST)
        assert removed == [f"{version}-{WINDOWS_HOST}"]
        normalized.append(
            {name: flags for name, flags in normalize.parse_toolchains(installed).items() if name not in removed}
        )
    assert normalized[0] == normalized[1] == {WINDOWS_PINNED: {"default"}}


@pytest.mark.parametrize(
    ("architecture", "active", "unused", "allowed"),
    [
        ("X64", f"{WINDOWS_PINNED} (default)\n", f"1.99.1-{WINDOWS_HOST}", True),
        ("X64", ACTIVE, f"1.99.1-{WINDOWS_HOST}", False),
        ("X64", "1.88.0-x86_64-pc-windows-gnu (default)\n", f"1.99.1-{WINDOWS_HOST}", False),
        ("X64", f"{WINDOWS_PINNED} (active)\n", f"1.99.1-{WINDOWS_HOST}", False),
        ("X64", f"{WINDOWS_PINNED} (default)\n", "bad inventory line", False),
        ("ARM64", f"{WINDOWS_PINNED} (default)\n", f"1.99.1-{WINDOWS_HOST}", False),
    ],
)
def test_windows_validates_pinned_host_and_inventory_before_uninstall(
    monkeypatch: pytest.MonkeyPatch, architecture: str, active: str, unused: str, allowed: bool
) -> None:
    for name, value in {
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Windows",
        "RUNNER_ARCH": architecture,
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "argv", ["normalize", "--toolchain", "1.88.0"])
    calls = []

    def rustup(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert kwargs["check"] is True
        calls.append(arguments)
        if arguments == ["rustup", "toolchain", "list"]:
            output = active + unused + "\n"
        elif arguments == ["rustup", "show", "active-toolchain"]:
            output = active
        else:
            assert allowed and arguments == ["rustup", "toolchain", "uninstall", unused]
            output = ""
        return subprocess.CompletedProcess(arguments, 0, output)

    monkeypatch.setattr(normalize.subprocess, "run", rustup)
    if allowed:
        normalize.main()
        assert calls[-1] == ["rustup", "toolchain", "uninstall", unused]
    else:
        with pytest.raises(ValueError):
            normalize.main()
        assert all(command[:3] != ["rustup", "toolchain", "uninstall"] for command in calls)


@pytest.mark.skipif(shutil.which("bash") is None, reason="normalization uses Bash")
@pytest.mark.parametrize("interpreters,valid", [("python", True), ("python3", True), ("both", True), ("python", False)])
def test_normalization_shell_uses_available_python_and_propagates_failure(tmp_path, interpreters, valid):
    action = yaml.safe_load((ROOT / ".github/actions/setup-rust/action.yml").read_text())
    step = next(
        step for step in action["runs"]["steps"] if step["name"] == "Normalize the hosted Rust compiler inventory"
    )
    commands = tmp_path / "commands"
    commands.mkdir()
    selected = tmp_path / "selected-interpreter"
    calls = tmp_path / "rustup-calls"
    for name in ["python", "python3"] if interpreters == "both" else [interpreters]:
        executable = commands / name
        executable.write_text('#!/bin/bash\nprintf "%s\\n" "$0" >> "$SELECTED_INTERPRETER"\nexec "$TEST_PYTHON" "$@"\n')
        executable.chmod(0o755)
    active = WINDOWS_PINNED if valid else PINNED
    unused = f"1.99.1-{WINDOWS_HOST}"
    # Hook only the child's rustup boundary: native Windows CreateProcess cannot
    # execute an extensionless Bash stub. The selected Python still runs the CLI.
    (commands / "sitecustomize.py").write_text(
        "import os, subprocess\nfrom pathlib import Path\n"
        "def rustup(arguments, **kwargs):\n"
        "    assert arguments[0] == 'rustup' and kwargs['check'] is True\n"
        "    with Path(os.environ['RUSTUP_CALLS']).open('a') as output:\n"
        "        output.write(' '.join(arguments[1:]) + '\\n')\n"
        "    if arguments == ['rustup', 'toolchain', 'list']:\n"
        f"        result = '{active} (default)\\n{unused}\\n'\n"
        "    elif arguments == ['rustup', 'show', 'active-toolchain']:\n"
        f"        result = '{active} (default)\\n'\n"
        f"    elif arguments == ['rustup', 'toolchain', 'uninstall', '{unused}']:\n"
        "        result = ''\n"
        "    else:\n        raise AssertionError(arguments)\n"
        "    return subprocess.CompletedProcess(arguments, 0, stdout=result)\n"
        "subprocess.run = rustup\n"
    )
    completed = subprocess.run(
        [shutil.which("bash"), "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", step["run"]],
        cwd=ROOT,
        env={
            **os.environ,
            "PATH": str(commands),
            "PYTHONPATH": str(commands),
            "TEST_PYTHON": sys.executable,
            "SELECTED_INTERPRETER": str(selected),
            "RUSTUP_CALLS": str(calls),
            "RUST_TOOLCHAIN": "1.88.0",
            "GITHUB_ACTIONS": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Windows",
            "RUNNER_ARCH": "X64",
        },
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert (completed.returncode == 0) == valid, completed.stderr
    expected = "python3" if interpreters in {"python3", "both"} else "python"
    assert [Path(line).name for line in selected.read_text().splitlines()] == [expected]
    assert calls.read_text().splitlines() == [
        "toolchain list",
        "show active-toolchain",
        *([f"toolchain uninstall {unused}"] if valid else []),
    ]


def test_normalization_is_opt_in_and_precedes_full_environment_hashing() -> None:
    action = yaml.safe_load((ROOT / ".github/actions/setup-rust/action.yml").read_text())
    assert action["inputs"]["normalize-toolchains"]["default"] == "false"
    steps = action["runs"]["steps"]
    install = next(step for step in steps if step["name"] == "Install pinned Rust toolchain")
    normalize_step = next(step for step in steps if step["name"] == "Normalize the hosted Rust compiler inventory")
    cache = next(step for step in steps if step.get("id") == "rust-cache")
    assert steps.index(install) < steps.index(normalize_step) < steps.index(cache)
    assert 'rustup default "$RUST_TOOLCHAIN"' in install["run"]
    assert install["run"].index("rustup toolchain install") < install["run"].index("rustup default")
    assert normalize_step["if"] == (
        "inputs.normalize-toolchains == 'true' && runner.environment == 'github-hosted' && "
        "(runner.os == 'Linux' || runner.os == 'Windows')"
    )
    assert "add-rust-environment-hash-key" not in cache["with"]
    assert "cache-workspace-crates" in cache["with"]
    assert "refs/heads/main" in cache["with"]["save-if"]
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    setup = next(
        step
        for step in workflow["jobs"]["native-workspace"]["steps"]
        if step.get("uses") == "./.github/actions/setup-rust"
    )
    assert setup["with"]["normalize-toolchains"] == "true"
    assert setup["with"]["components"] == "${{ matrix.check == 'clippy' && 'clippy rustfmt' || 'clippy' }}"
    windows = yaml.safe_load((ROOT / ".github/actions/ci-job-windows-native-runtime/action.yml").read_text())
    windows_setup = next(
        step for step in windows["runs"]["steps"] if step.get("uses") == "./.github/actions/setup-rust"
    )
    assert windows_setup["with"] == {"normalize-toolchains": "true"}


def test_release_normalization_is_hosted_windows_only_after_install_before_cache() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/release-native-prepare.yml").read_text())
    assert "scripts/ci/normalize_rust_toolchains.py" in workflow[True]["push"]["paths"]
    steps = workflow["jobs"]["compile"]["steps"]
    normalizers = [step for step in steps if "normalize_rust_toolchains.py" in step.get("run", "")]
    assert len(normalizers) == 1
    normalize_step = normalizers[0]
    install = next(step for step in steps if step.get("name") == "Install pinned Rust target")
    cache = next(step for step in steps if step.get("uses", "").startswith("Swatinem/rust-cache@"))
    assert steps.index(install) < steps.index(normalize_step) < steps.index(cache)
    miss_guard = (
        "env.UNSHIPPED_TARGET != 'true' && steps.native-cache.outputs.cache-hit != 'true' && "
        "steps.native-artifact.outputs.accepted != 'true'"
    )
    assert install["if"] == cache["if"] == miss_guard
    assert normalize_step["if"] == (
        "runner.environment == 'github-hosted' && runner.os == 'Windows' && runner.arch == 'X64' && " + miss_guard
    )
    assert normalize_step["shell"] == "bash"
    assert normalize_step["run"] == "python scripts/ci/normalize_rust_toolchains.py --toolchain 1.88.0"
    assert normalize_step.get("continue-on-error", False) is False
    commands = install["run"]
    assert commands.index("rustup toolchain install 1.88.0") < commands.index("rustup default 1.88.0")
    assert commands.index("rustup default 1.88.0") < commands.index('rustup target add "$RUST_TARGET"')


def test_windows_normalization_preserves_pinned_cross_target_components(monkeypatch) -> None:
    for name, value in {
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Windows",
        "RUNNER_ARCH": "X64",
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "argv", ["normalize", "--toolchain", "1.88.0"])
    components = {"rustc", "rust-std-x86_64-pc-windows-msvc", "rust-std-aarch64-pc-windows-msvc"}
    unused = f"1.99.1-{WINDOWS_HOST}"
    toolchains = {WINDOWS_PINNED: components.copy(), unused: {"rustc"}}

    def rustup(arguments, **kwargs):
        assert kwargs["check"] is True
        if arguments == ["rustup", "toolchain", "list"]:
            output = f"{WINDOWS_PINNED} (default)\n{unused}\n"
        elif arguments == ["rustup", "show", "active-toolchain"]:
            output = f"{WINDOWS_PINNED} (default)\n"
        else:
            assert arguments == ["rustup", "toolchain", "uninstall", unused]
            del toolchains[unused]
            output = ""
        return subprocess.CompletedProcess(arguments, 0, output)

    monkeypatch.setattr(normalize.subprocess, "run", rustup)
    normalize.main()
    assert toolchains == {WINDOWS_PINNED: components}
