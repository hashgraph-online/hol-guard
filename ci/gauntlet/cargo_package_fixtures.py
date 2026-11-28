"""Disposable synthetic Cargo package fixtures for Guard Gauntlet."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import tomllib

CARGO_MANIFEST_CASE = "omp-native-shell-cargo-manifest-question"
# Cases whose cargo commands run on the host with the fixture HOME, where the
# rustup proxy looks for its toolchain.
RUSTUP_HOME_CASES = frozenset({CARGO_MANIFEST_CASE, "omp-native-shell-cargo-manifest-queries"})
CARGO_PACKAGE_NAME = "storefront-portal"
CARGO_PACKAGE_FILES = {
    "Cargo.toml": (
        f'[package]\nname = "{CARGO_PACKAGE_NAME}"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\n'
    ),
    # A resolved lockfile for a package with no dependencies. Writing it here
    # means the two questions answer out of what the directory already holds:
    # neither resolves against a registry, and neither leaves a file behind.
    "Cargo.lock": (f'version = 3\n\n[[package]]\nname = "{CARGO_PACKAGE_NAME}"\nversion = "0.1.0"\n'),
    # Cargo refuses a manifest that declares no target, so the package needs
    # an entry point before it can name itself.
    "src/main.rs": 'fn main() {\n    println!("synthetic");\n}\n',
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


def _host_rustup_home() -> Path:
    configured = os.environ.get("RUSTUP_HOME")
    return Path(configured) if configured else Path.home() / ".rustup"


def add_rustup_home(home: Path, scenario_id: str | None) -> None:
    """Give the fixture HOME the rustup state a Rust developer's home holds.

    ``cargo`` on PATH is usually the rustup proxy, which reads
    ``~/.rustup/settings.toml`` to pick a toolchain. With the fixture HOME it
    finds none and exits with "no default is configured" before cargo runs, so
    the case would measure a missing install rather than Guard. The fixture
    names the host's default toolchain and links only that toolchain's
    directory, which rustup reads and never writes; the host's own settings,
    overrides and download state stay out of the fixture. A host without
    rustup, or one whose default is missing, gets nothing.
    """
    if scenario_id not in RUSTUP_HOME_CASES:
        return
    host = _host_rustup_home()
    try:
        settings = tomllib.loads((host / "settings.toml").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return
    default = settings.get("default_toolchain")
    if not isinstance(default, str) or not default or Path(default).name != default:
        return
    toolchain = host / "toolchains" / default
    if not toolchain.is_dir():
        return
    rustup = home / ".rustup"
    (rustup / "toolchains").mkdir(parents=True, exist_ok=True)
    (rustup / "settings.toml").write_text(
        f'version = "12"\ndefault_toolchain = "{default}"\nprofile = "default"\n',
        encoding="utf-8",
        newline="\n",
    )
    try:
        (rustup / "toolchains" / default).symlink_to(toolchain.resolve(), target_is_directory=True)
    except OSError:
        # Windows without symlink rights: leave no half-built rustup home.
        shutil.rmtree(rustup)
