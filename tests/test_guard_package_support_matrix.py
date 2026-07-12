"""Drift test: _PACKAGE_SHIM_COMMANDS keys match _PACKAGE_SHIM_PROBE_ARGS keys.

This test documents the relationship between the two source-of-truth dicts
that define package manager support in hol-guard:

  - _PACKAGE_SHIM_COMMANDS (shims.py): managers that can have shims installed
  - _PACKAGE_SHIM_PROBE_ARGS (shim_probe.py): managers with dedicated probe commands

Managers in _PACKAGE_SHIM_COMMANDS but NOT in _PACKAGE_SHIM_PROBE_ARGS fall
back to `--version` for probe testing, which proves the shim exists on PATH
but does not prove install interception. These managers are documented here
so the portal support matrix can accurately report interceptTest=False.
"""

from __future__ import annotations

from codex_plugin_scanner.guard.shim_probe import _PACKAGE_SHIM_PROBE_ARGS
from codex_plugin_scanner.guard.shims import package_shim_supported_managers


def test_supported_managers_are_sorted() -> None:
    """package_shim_supported_managers() returns sorted tuple."""
    managers = package_shim_supported_managers()
    assert managers == tuple(sorted(managers))


def test_supported_managers_match_shim_commands() -> None:
    """_PACKAGE_SHIM_COMMANDS keys produce the supported managers list."""
    from codex_plugin_scanner.guard.shims import _PACKAGE_SHIM_COMMANDS

    expected = tuple(sorted(_PACKAGE_SHIM_COMMANDS.keys()))
    assert package_shim_supported_managers() == expected


def test_probe_args_cover_protected_managers() -> None:
    """Managers without dedicated probe args are documented.

    gradle, mvn, and uvx are in _PACKAGE_SHIM_COMMANDS but not in
    _PACKAGE_SHIM_PROBE_ARGS. They fall back to `--version` which
    proves the shim is on PATH but does not prove install interception.
    """
    managers = set(package_shim_supported_managers())
    probe_managers = set(_PACKAGE_SHIM_PROBE_ARGS.keys())

    missing_probes = managers - probe_managers
    # These are the known gaps. If a new manager is added without a probe,
    # this test will fail and the developer must either add probe args
    # or add the manager to KNOWN_NO_PROBE_MANAGERS.
    known_no_probe = {"gradle", "mvn", "uvx"}
    assert missing_probes == known_no_probe, (
        f"Managers without probe args changed: {missing_probes}. "
        f"Expected: {known_no_probe}. Either add probe args to "
        f"_PACKAGE_SHIM_PROBE_ARGS or update KNOWN_NO_PROBE_MANAGERS."
    )


def test_probe_args_only_reference_supported_managers() -> None:
    """Every probe arg key must be a supported manager."""
    managers = set(package_shim_supported_managers())
    probe_managers = set(_PACKAGE_SHIM_PROBE_ARGS.keys())

    unknown_probes = probe_managers - managers
    assert unknown_probes == set(), (
        f"Probe args reference unknown managers: {unknown_probes}. "
        f"Add them to _PACKAGE_SHIM_COMMANDS or remove the probe args."
    )


def test_supported_managers_snapshot() -> None:
    """Snapshot of supported managers for portal drift detection.

    The portal's package-shim-supported-managers.snapshot.json must match
    this list. If managers change, update the snapshot in the portal.
    """
    expected = (
        "brew",
        "bun",
        "bundle",
        "bunx",
        "cargo",
        "composer",
        "go",
        "gradle",
        "mvn",
        "npm",
        "npx",
        "pip",
        "pip3",
        "pipenv",
        "pipx",
        "pnpm",
        "poetry",
        "uv",
        "uvx",
        "yarn",
    )
    assert package_shim_supported_managers() == expected
