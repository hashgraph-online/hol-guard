"""The Rust Sonar analysis must run real Clippy with the repository's toolchain."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_sonar_installs_pinned_clippy_and_fails_on_compilation_errors() -> None:
    """Keep toolchain setup, compilation checks, and analysis in the required order."""
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    job = workflow["jobs"]["sonar"]
    steps = job["steps"]
    setup_index = next(i for i, step in enumerate(steps) if step.get("name") == "Set up pinned Rust and Clippy")
    scan_index = next(i for i, step in enumerate(steps) if step.get("name") == "Analyze with SonarQube Cloud")
    setup = steps[setup_index]
    run = setup["run"]
    install = 'rustup toolchain install "$toolchain" --profile minimal --component clippy'
    default = 'rustup default "$toolchain"'
    clippy = "cargo clippy --manifest-path rust/Cargo.toml --locked --workspace"

    assert job["timeout-minutes"] == 20
    assert setup_index < scan_index
    assert '"rust/rust-toolchain.toml"' in run
    assert run.index(install) < run.index(default) < run.index(clippy)
    assert setup["shell"] == "bash"
    assert not job.get("continue-on-error", False)
    assert not setup.get("continue-on-error", False)
    assert "SONAR_TOKEN" not in setup.get("env", {})
