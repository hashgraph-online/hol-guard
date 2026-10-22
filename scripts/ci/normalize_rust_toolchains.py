"""Keep unused hosted-runner compilers out of the Rust dependency cache key."""

from __future__ import annotations

import argparse
import os
import re
import subprocess

TOOLCHAIN = re.compile(r"([A-Za-z0-9][A-Za-z0-9_.-]*)(?: \((active|default)(?:, (active|default))?\))?")
PINNED = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")


def parse_toolchains(output: str) -> dict[str, set[str]]:
    """Reject unexpected rustup output before planning any removals."""
    installed: dict[str, set[str]] = {}
    for line in output.splitlines():
        match = TOOLCHAIN.fullmatch(line)
        if match is None or match[1] in installed:
            raise ValueError("unexpected installed Rust toolchain list")
        installed[match[1]] = {value for value in match.groups()[1:] if value}
    if not installed:
        raise ValueError("installed Rust toolchain list is empty")
    return installed


def removals(toolchain: str, installed_output: str, active_output: str) -> list[str]:
    """Retain the exact host-qualified pinned default and all its components."""
    if PINNED.fullmatch(toolchain) is None:
        raise ValueError("normalization requires an exact Rust version")
    installed = parse_toolchains(installed_output)
    active = parse_toolchains(active_output.strip())
    if len(active) != 1:
        raise ValueError("expected one active Rust toolchain")
    retained = next(iter(active))
    if (
        not retained.startswith(f"{toolchain}-")
        or "default" not in active[retained]
        or "default" not in installed.get(retained, set())
        or any("default" in flags for name, flags in installed.items() if name != retained)
    ):
        raise ValueError("pinned Rust toolchain must be the active default")
    return [name for name in installed if name != retained]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toolchain", required=True)
    args = parser.parse_args()
    # Never enumerate or uninstall compilers on local or self-hosted machines.
    if not (
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("RUNNER_OS") == "Linux"
    ):
        return
    installed = subprocess.run(
        ["rustup", "toolchain", "list"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    active = subprocess.run(
        ["rustup", "show", "active-toolchain"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    # Validate the complete list and default selection before the first mutation.
    for name in removals(args.toolchain, installed, active):
        subprocess.run(["rustup", "toolchain", "uninstall", name], check=True)


if __name__ == "__main__":
    main()
