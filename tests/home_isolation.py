"""Point the test session's user home at a private directory.

Guard code defaults to ``Path.home()`` for harness configuration (``~/.codex``,
``~/.claude``, package shims) and ``~/.hol-guard`` for its own state. A test that
omits ``--home`` would otherwise install hooks into the developer's real
configuration, which can leave Codex pointing at a deleted checkout. This runs
at conftest import time so module-level defaults and spawned subprocesses see
the private home too.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

# Toolchains under the real home are linked into the private one rather than
# exported: Guard reads an inherited RUSTUP_HOME as a toolchain override.
_TOOL_HOMES = {
    "CARGO_HOME": ".cargo",
    "RUSTUP_HOME": ".rustup",
}
_CACHE_HOMES = {"UV_CACHE_DIR": ".cache/uv"}

# Inherited overrides would send writes back to the real installation.
_HOME_OVERRIDES = (
    "CODEX_HOME",
    "HOL_GUARD_HOME",
    "CLAUDE_CONFIG_DIR",
    "OPENCODE_CONFIG_DIR",
    "HERMES_HOME",
    "HERMES_HOST_HOME",
    "PASEO_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
)


def isolate_user_home() -> Path:
    existing = os.environ.get("HOL_GUARD_TEST_PRIVATE_HOME")
    if existing and os.environ.get("HOME") == existing:
        return Path(existing)
    real_home = Path.home()
    for variable, relative in _CACHE_HOMES.items():
        candidate = real_home / relative
        if variable not in os.environ and candidate.is_dir():
            os.environ[variable] = str(candidate)
    for variable in _HOME_OVERRIDES:
        os.environ.pop(variable, None)
    # Outside the temp root: path-trust code treats the two differently, as on a real machine.
    # Some parametrize IDs embed the home, and CI plans shards in a separate job,
    # so the path must be the same for every session in this checkout.
    checkout = str(Path(__file__).resolve().parents[1])
    name = "home-" + hashlib.sha256(checkout.encode()).hexdigest()[:12]
    base_override = os.environ.get("HOL_GUARD_TEST_HOME_BASE")
    home_base = Path(base_override) if base_override else real_home / ".cache" / "hol-guard-tests"
    if not home_base.is_absolute():
        raise ValueError("HOL_GUARD_TEST_HOME_BASE must be an absolute test-only directory")
    private_home = home_base / name
    private_home.mkdir(parents=True, exist_ok=True)
    private_home = private_home.resolve()
    for variable, relative in _TOOL_HOMES.items():
        _link_tool_home(variable, real_home / relative, private_home / relative)
    os.environ["HOME"] = str(private_home)
    if os.name == "nt":
        os.environ["USERPROFILE"] = str(private_home)
        # Some harness configuration lives in the roaming profile, not the home.
        roaming = private_home / "AppData" / "Roaming"
        roaming.mkdir(parents=True, exist_ok=True)
        os.environ["APPDATA"] = str(roaming)
    os.environ["HOL_GUARD_TEST_PRIVATE_HOME"] = str(private_home)
    return private_home


def _link_tool_home(variable: str, real: Path, private: Path) -> None:
    if variable in os.environ or not real.is_dir() or private.is_symlink() or private.exists():
        return
    try:
        private.symlink_to(real, target_is_directory=True)
    except OSError:
        # Windows without symlink privilege: fall back to the variable.
        os.environ[variable] = str(real)
