"""Normalize only disposable hosted compiler inventories before cache hashing."""

from __future__ import annotations

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
        ("true", "github-hosted", "Windows"),
    ],
)
def test_never_invokes_rustup_outside_opted_in_linux_hosted_runner(
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
        "inputs.normalize-toolchains == 'true' && runner.environment == 'github-hosted' && runner.os == 'Linux'"
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
    assert setup["with"]["components"] == "clippy"
