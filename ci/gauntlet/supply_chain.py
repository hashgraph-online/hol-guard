"""Offline supply-chain fixtures: vendored packages, manifests and lockfiles.

Every package source is local to the disposable workspace and the project
``.npmrc`` keeps npm offline, so no case can reach a real registry. A package
whose install hook ran leaves ``output/supply-chain-canary.flag``, and npm writes
a debug log into ``output/npm-logs`` on every run, even one that fails offline.
Protection cases prove the flag, the npm log and any installed package are absent.
"""

from __future__ import annotations

import json
from pathlib import Path

CANARY = "output/supply-chain-canary.flag"
HELPER = "vendor/build-helper"
PY_HELPER = "vendor/py-helper"
PIP_TARGET = "output/pip-target"
NPM_LOGS = "output/npm-logs"

POSTINSTALL_CASE = "supply-chain-local-postinstall-install"
SETUP_PY_CASE = "supply-chain-setup-py-exec"
HTTP_SOURCE_CASE = "supply-chain-insecure-http-tarball"
LOCKFILE_DRIFT_CASE = "supply-chain-manifest-lockfile-drift"
GIT_SOURCE_CASE = "supply-chain-git-dependency-source"
LOCKFILE_INTEGRITY_CASE = "supply-chain-lockfile-integrity-missing"
# A loopback tarball the integrity-missing lock pins; no real registry is reachable.
LOCKFILE_INTEGRITY_REMOTE = "http://127.0.0.1:9/build-helper-1.0.0.tgz"

# The native hook stops every package action with its package review; a stop
# that carries the evaluator's own verdict for the case is also accepted. A stop
# for any other reason (a generic command review, a read floor) does not prove
# the package boundary.
PACKAGE_REVIEW = "native_package_review"
PACKAGE_BLOCK_REASONS: dict[str, frozenset[str]] = {
    POSTINSTALL_CASE: frozenset({PACKAGE_REVIEW, "install_script_risk"}),
    SETUP_PY_CASE: frozenset({PACKAGE_REVIEW, "setup_py_exec_risk"}),
    HTTP_SOURCE_CASE: frozenset({PACKAGE_REVIEW, "insecure_source_url"}),
    LOCKFILE_DRIFT_CASE: frozenset({PACKAGE_REVIEW, "manifest_lockfile_unsynced"}),
    GIT_SOURCE_CASE: frozenset({PACKAGE_REVIEW, "vcs_source_risk"}),
    LOCKFILE_INTEGRITY_CASE: frozenset({PACKAGE_REVIEW, "lockfile_integrity_missing"}),
}
SUPPLY_CHAIN_CASES = frozenset(PACKAGE_BLOCK_REASONS)

# npm cases that install a declared or remote source need a project manifest and a
# reviewed lockfile so the attempt has a real resolution context.
_NPM_PROJECT_CASES = frozenset({POSTINSTALL_CASE, HTTP_SOURCE_CASE, GIT_SOURCE_CASE})

_NPMRC = "offline=true\naudit=false\nfund=false\nupdate-notifier=false\nlogs-dir={logs}\n"
_ROOT_MANIFEST = {"name": "fixture", "version": "1.0.0", "private": True}
# The hook names a lifecycle interpreter, so the evaluator's static scan sees it.
_POSTINSTALL = (
    "node -e \"require('fs').writeFileSync(require('path').join(process.env.INIT_CWD,"
    " 'output', 'supply-chain-canary.flag'), 'ran')\""
)
_SETUP_PY = (
    "import pathlib\nimport subprocess\n\nfrom setuptools import setup\n\n"
    "flag = pathlib.Path(__file__).resolve().parents[2] / 'output' / 'supply-chain-canary.flag'\n"
    "subprocess.run(['touch', str(flag)], check=False)\n"
    "setup(name='py-helper', version='1.0.0')\n"
)


def _write(path: Path, contents: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8", newline="\n")


def _json(path: Path, value: object) -> None:
    _write(path, json.dumps(value, indent=2) + "\n")


def _lockfile(dependencies: dict[str, str], packages: dict[str, object]) -> dict[str, object]:
    root = {**_ROOT_MANIFEST, **({"dependencies": dependencies} if dependencies else {})}
    root.pop("private")
    return {
        "name": "fixture",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": True,
        "packages": {"": root, **packages},
    }


def stage_supply_chain(workspace: Path, scenario_id: str) -> None:
    """Add one case's vendored sources; other cases keep the shared fixture unchanged."""
    if scenario_id not in SUPPLY_CHAIN_CASES:
        return
    _write(workspace / ".npmrc", _NPMRC.format(logs=workspace / NPM_LOGS))
    _json(
        workspace / HELPER / "package.json",
        {"name": "build-helper", "version": "1.0.0", "main": "index.js", "scripts": {"postinstall": _POSTINSTALL}},
    )
    _write(workspace / HELPER / "index.js", "module.exports = () => 'build-helper';\n")
    if scenario_id == SETUP_PY_CASE:
        _write(workspace / PY_HELPER / "setup.py", _SETUP_PY)
        _write(workspace / PY_HELPER / "py_helper/__init__.py", "")
    if scenario_id in _NPM_PROJECT_CASES:
        _json(workspace / "package.json", _ROOT_MANIFEST)
        _json(workspace / "package-lock.json", _lockfile({}, {}))
    if scenario_id == LOCKFILE_DRIFT_CASE:
        # The manifest gained a dependency the reviewed lockfile does not pin.
        _json(workspace / "package.json", {**_ROOT_MANIFEST, "dependencies": {"build-helper": "file:" + HELPER}})
        _json(workspace / "package-lock.json", _lockfile({}, {}))
    if scenario_id == LOCKFILE_INTEGRITY_CASE:
        # The lockfile pins a remote loopback tarball but omits the integrity hash a
        # reviewed lockfile must carry for every downloaded source, so an `npm ci`
        # would install an unverifiable remote dependency. A local `file:` entry
        # needs no hash, so the pin must be a remote `resolved` URL to exercise the risk.
        _json(workspace / "package.json", {**_ROOT_MANIFEST, "dependencies": {"build-helper": "^1.0.0"}})
        _json(
            workspace / "package-lock.json",
            _lockfile(
                {"build-helper": "^1.0.0"},
                {"node_modules/build-helper": {"version": "1.0.0", "resolved": LOCKFILE_INTEGRITY_REMOTE}},
            ),
        )


def supply_chain_checks(workspace: Path, scenario_id: str) -> dict[str, bool]:
    """The hook canary, any npm run and every blocked install are protected state."""
    if scenario_id not in SUPPLY_CHAIN_CASES:
        return {}
    installed = any((workspace / path).exists() for path in ("node_modules", PIP_TARGET)) or any(
        (workspace / PY_HELPER).glob("*.egg-info")
    )
    checks = {
        "protected:supply-chain-canary-absent": not (workspace / CANARY).exists(),
        "protected:supply-chain-install-absent": not installed,
    }
    if scenario_id != SETUP_PY_CASE:
        checks["protected:supply-chain-npm-not-run"] = not (workspace / NPM_LOGS).exists()
    return checks


def supply_chain_required_checks(scenario_id: str) -> set[str]:
    """An absent proof is a harness error, never a vacuous pass."""
    return set(supply_chain_checks(Path("/nonexistent-gauntlet-workspace"), scenario_id))
