"""Every reader of the packaged runtime admits what a development wheel ships.

Gauntlet development wheels build the runtime at opt-level 0, several times the
published size, and the wheel scripts name a larger bound for them. The resident
identifies itself by hashing its own executable, so a reader bound below that
one leaves a development wheel with no native runtime at all.
"""

from __future__ import annotations

import re
from pathlib import Path

from codex_plugin_scanner.guard import native_resident_update_lock
from codex_plugin_scanner.guard.extension_builder import native_source_compiler

ROOT = Path(__file__).resolve().parents[1]
RUST_READERS = (
    "rust/crates/guard-runtime/src/resident_process_identity.rs",
    "rust/crates/guard-runtime/src/resident_state.rs",
    "rust/crates/guard-runtime/src/pack_lifecycle/release.rs",
    "rust/crates/guard-command/src/bundle_metadata.rs",
)
PUBLISHED_RUNTIME_CHECKS = (
    "scripts/build_native_hol_guard_wheel.py",
    "scripts/ci/validate_release_artifacts.py",
    "scripts/release/stage_native_runtime_for_desktop_core.py",
    "scripts/verify_native_runtime_release.py",
)
DEVELOPMENT_WHEEL_BUILDS = (
    "scripts/ci/build-native-wheel-macos.sh",
    ".github/workflows/gauntlet-full-task-runtime.yml",
    ".github/workflows/gauntlet-installed-acceptance.yml",
)


def _mebibytes(expression: str) -> int:
    factors = [int(part) for part in re.split(r"\s*\*\s*", expression.strip())]
    product = 1
    for factor in factors:
        product *= factor
    return product


def _development_wheel_bound(path: str) -> int:
    match = re.search(r"--max-runtime-bytes \$\(\(([\d\s*]+)\)\)", (ROOT / path).read_text(encoding="utf-8"))
    assert match, path
    return _mebibytes(match.group(1))


def _rust_bound(path: str) -> int:
    match = re.search(r"const MAX_RUNTIME_BYTES: u64 = ([\d\s*]+);", (ROOT / path).read_text(encoding="utf-8"))
    assert match, path
    return _mebibytes(match.group(1))


def test_runtime_readers_admit_the_development_wheel_runtime() -> None:
    development = {_development_wheel_bound(path) for path in DEVELOPMENT_WHEEL_BUILDS}
    assert len(development) == 1
    bound = development.pop()

    readers = {path: _rust_bound(path) for path in RUST_READERS}
    readers["native_resident_update_lock"] = native_resident_update_lock._MAX_RUNTIME_BYTES
    readers["native_source_compiler"] = native_source_compiler._MAX_COMPILER_BYTES

    assert readers == dict.fromkeys(readers, bound)


def _published_bound(path: str) -> int:
    pattern = r"^_MAX_RUNTIME_BYTES(?:: Final)? = ([\d\s*]+)$"
    match = re.search(pattern, (ROOT / path).read_text(encoding="utf-8"), re.MULTILINE)
    assert match, path
    return _mebibytes(match.group(1))


def test_release_checks_share_one_published_runtime_bound() -> None:
    published = {path: _published_bound(path) for path in PUBLISHED_RUNTIME_CHECKS}
    bound = published[PUBLISHED_RUNTIME_CHECKS[0]]

    assert published == dict.fromkeys(published, bound)
    # An alpha build of the static Linux runtime is above 128 MiB.
    assert bound >= 192 * 1024 * 1024
    assert bound <= _rust_bound(RUST_READERS[0])
