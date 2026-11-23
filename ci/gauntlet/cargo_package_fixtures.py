"""Disposable synthetic Cargo package fixtures for Guard Gauntlet."""

from __future__ import annotations

from pathlib import Path

CARGO_MANIFEST_CASE = "omp-native-shell-cargo-manifest-question"
CARGO_PACKAGE_NAME = "storefront-portal"
CARGO_PACKAGE_FILES = {
    "Cargo.toml": (
        "[package]\n"
        f'name = "{CARGO_PACKAGE_NAME}"\n'
        'version = "0.1.0"\n'
        'edition = "2021"\n'
        "\n"
        "[dependencies]\n"
    ),
    # A resolved lockfile for a package with no dependencies. Writing it here
    # means the two questions answer out of what the directory already holds:
    # neither resolves against a registry, and neither leaves a file behind.
    "Cargo.lock": (
        "version = 3\n"
        "\n"
        "[[package]]\n"
        f'name = "{CARGO_PACKAGE_NAME}"\n'
        'version = "0.1.0"\n'
    ),
    # Cargo refuses a manifest that declares no target, so the package needs
    # an entry point before it can name itself.
    "src/main.rs": "fn main() {\n    println!(\"synthetic\");\n}\n",
}


def add_cargo_package(workspace: Path, scenario_id: str | None) -> None:
    """Make the fixture checkout a Cargo package.

    The manifest questions are local only while a `Cargo.toml` sits at or
    above the working directory inside the workspace, which is the check the
    containment route makes before it admits either verb. The fixture
    checkout is a TypeScript project, so without this the case would measure
    a missing manifest rather than the decision it is written for.
    """
    if scenario_id != CARGO_MANIFEST_CASE:
        return
    for relative, text in CARGO_PACKAGE_FILES.items():
        target = workspace / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="\n")
