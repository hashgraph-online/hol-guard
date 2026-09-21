"""Exercise an installed wheel's real identity and child lifetime boundaries.

Run with the wheel interpreter and -I, outside pytest. Fixed-count checks use
the actual bundled executable, manifest and capabilities. Mutations are local
to the disposable CI installation and restored in finally. No hook frame or
resident socket is used. Restoration covers the same artifact, not a signed
upgrade or rollback between different release versions.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import stat
import sys
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

_MAX_EXECUTABLE_BYTES = 64 * 1024 * 1024
_MAX_MANIFEST_BYTES = 16 * 1024
_STATUS_SAMPLES = 3


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise RuntimeError("installed_runtime_identity_failed:" + reason)


def _read_bounded(path: Path, maximum: int) -> bytes:
    with path.open("rb") as handle:
        content = handle.read(maximum + 1)
    _require(0 < len(content) <= maximum, "artifact_size")
    return content


def _replace_file(path: Path, content: bytes, metadata: os.stat_result) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=".identity-probe-", dir=path.parent)
    candidate = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        candidate.chmod(stat.S_IMODE(metadata.st_mode))
        os.utime(candidate, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
        os.replace(candidate, path)
    finally:
        candidate.unlink(missing_ok=True)


@contextmanager
def _count_full_validation(runtime: Any) -> Iterator[dict[str, int]]:
    original_validate = runtime._validate_binary
    original_sha256 = runtime.hashlib.sha256
    active = False
    counts = {"validation_calls": 0, "hashed_bytes": 0}

    class Digest:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self._digest = original_sha256(*args, **kwargs)

        def update(self, content: bytes) -> None:
            if active:
                counts["hashed_bytes"] += len(content)
            self._digest.update(content)

        def __getattr__(self, name: str) -> Any:
            return getattr(self._digest, name)

    def validate(path: Path) -> Any:
        nonlocal active
        counts["validation_calls"] += 1
        previous = active
        active = True
        try:
            return original_validate(path)
        finally:
            active = previous

    runtime._validate_binary = validate
    runtime.hashlib.sha256 = Digest
    try:
        yield counts
    finally:
        runtime._validate_binary = original_validate
        runtime.hashlib.sha256 = original_sha256


def run_probe() -> dict[str, object]:
    forbidden = (
        "HOL_GUARD_",
        "GUARD_NATIVE",
        "GUARD_TEST_",
        "GUARD_ORACLE",
        "GUARD_DIAGNOSTIC",
        "GUARD_BINARY",
        "GUARD_FAST_PATH",
        "GUARD_HOOK_BINARY",
        "GUARD_HOOK_FAST_PATH",
        "GUARD_HOOK_SOURCE_REF",
        "GUARD_PYTHON_ORACLE",
        "GUARD_PYTEST_",
        "PYTEST_",
    )
    _require(
        not any(name.startswith(forbidden) or name == "PYTHONPATH" for name in os.environ),
        "environment_override",
    )
    _require(bool(sys.flags.isolated), "isolated_interpreter_required")
    from codex_plugin_scanner.guard import native_runtime as runtime
    from codex_plugin_scanner.guard import native_runtime_identity as identities
    from codex_plugin_scanner.guard.native_resident_stream import _PersistentNativeClient

    distribution = importlib.metadata.distribution("hol-guard")
    expected_module = Path(str(distribution.locate_file("codex_plugin_scanner/guard/native_runtime.py"))).resolve()
    _require(Path(runtime.__file__).resolve() == expected_module, "wheel_import_required")
    _require("site-packages" in expected_module.parts, "wheel_location_required")
    _require(
        Path(identities.__file__).resolve() == expected_module.with_name("native_runtime_identity.py"),
        "identity_module_wheel_import_required",
    )
    python_module_digest = hashlib.sha256(_read_bounded(expected_module, 1024 * 1024)).hexdigest()
    identity_module_digest = hashlib.sha256(_read_bounded(Path(identities.__file__), 1024 * 1024)).hexdigest()
    direct_url = distribution.read_text("direct_url.json")
    if direct_url is not None:
        origin = json.loads(direct_url)
        _require(not origin.get("dir_info", {}).get("editable", False), "editable_install")
    initial = runtime.native_runtime_status()
    _require(initial.mode == "auto" and initial.compatible, "initial_admission")
    _require(initial.identity is not None and initial.capabilities is not None, "initial_identity")
    assert initial.identity is not None and initial.capabilities is not None
    executable = initial.identity.path
    _require(executable == runtime._bundled_runtime_candidate().resolve(), "bundled_identity")
    manifest = executable.with_name("runtime-manifest.json")
    original_binary = _read_bounded(executable, _MAX_EXECUTABLE_BYTES)
    original_manifest = _read_bounded(manifest, _MAX_MANIFEST_BYTES)
    binary_metadata, manifest_metadata = executable.stat(), manifest.stat()
    _require(
        os.name == "nt" or (binary_metadata.st_uid == os.getuid() and manifest_metadata.st_uid == os.getuid()),
        "probe_requires_owned_artifacts",
    )
    expected_digest = hashlib.sha256(original_binary).hexdigest()
    _require(expected_digest == initial.identity.sha256, "exact_installed_bytes")
    cases: list[dict[str, object]] = []
    client = None
    binary_replaced = False
    manifest_replaced = False

    def measure(name: str, operation: Callable[[], None]) -> dict[str, int]:
        with _count_full_validation(runtime) as observed:
            operation()
        cases.append({"case": name, "result": "passed", **observed})
        return observed

    def admitted() -> None:
        status = runtime.native_runtime_status()
        _require(status.compatible and status.identity is not None, "restored_admission")
        assert status.identity is not None
        _require(status.identity.sha256 == expected_digest, "restored_digest")

    def steady_status() -> None:
        for _ in range(_STATUS_SAMPLES):
            admitted()

    def expect_full(observed: dict[str, int], count: int) -> None:
        _require(observed["validation_calls"] == count, "full_validation_count")
        _require(observed["hashed_bytes"] == len(original_binary) * count, "full_validation_bytes")

    try:
        expect_full(measure("steady_without_client", steady_status), _STATUS_SAMPLES)
        with tempfile.TemporaryDirectory(prefix="guard-installed-identity-") as temporary:
            client = _PersistentNativeClient(
                executable=executable,
                state_dir=Path(temporary) / "runtime",
                environment=runtime._isolated_environment(),
            )

            def start() -> None:
                assert client is not None
                _require(client._start(), "real_client_start")
                _require(client._process is not None and client._process.poll() is None, "real_client_live")

            expected_launch_hashes = 2 if sys.platform == "linux" else 0
            expect_full(measure("fresh_child", start), expected_launch_hashes)
            proof = client._attestation
            if sys.platform != "linux":
                _require(proof is None, "unsupported_platform_reuse")
            expect_full(measure("steady_with_client", steady_status), 0 if proof is not None else _STATUS_SAMPLES)

            # Cache a status immediately before exit, then restart the same
            # transport. The cached identity cannot admit its replacement.
            admitted()
            previous_child = client._process
            assert previous_child is not None
            previous_child.terminate()
            previous_child.wait(timeout=2)
            expect_full(measure("death_before_restart", start), expected_launch_hashes)
            _require(client._process is not previous_child, "child_generation_changed")

            # A real same-byte replacement is allowed on POSIX. Windows may
            # deny replacing the executing image; after containment it must
            # still perform fresh validation of the replacement artifact.
            proof = client._attestation
            replaced_child = client._process
            try:
                _replace_file(executable, original_binary, binary_metadata)
            except PermissionError:
                _require(os.name == "nt", "unexpected_replace_denial")
                cases.append({"case": "live_replacement", "result": "blocked_by_os"})
                client.close()
                _replace_file(executable, original_binary, binary_metadata)
            else:
                cases.append({"case": "live_replacement", "result": "replaced"})
            binary_replaced = True
            expect_full(measure("replacement_first_status", admitted), 1)
            if proof is not None:
                _require(not runtime.native_process_attestation_is_current(proof), "replacement_retired_proof")
                _require(not client._start(), "replacement_stale_child_rejected")
                _require(
                    client._process is None and replaced_child is not None and replaced_child.poll() is not None,
                    "replacement_stale_child_contained",
                )
            client.close()
            expect_full(measure("replacement_fresh_child", start), expected_launch_hashes)

            for field, replacement, reason in (
                ("source_sha", "0" * 40, "native_manifest_build_mismatch"),
                ("package_version", "0.0.0", "native_manifest_version_mismatch"),
            ):
                changed = json.loads(original_manifest)
                changed[field] = replacement
                _replace_file(manifest, json.dumps(changed).encode("utf-8"), manifest_metadata)
                manifest_replaced = True

                def rejected(expected_reason: str = reason) -> None:
                    status = runtime.native_runtime_status()
                    _require(not status.compatible and status.reason == expected_reason, "manifest_rejection")

                expect_full(measure(field + "_mismatch", rejected), 1)
                client.close()
                _replace_file(manifest, original_manifest, manifest_metadata)
                expect_full(measure(field + "_restoration", admitted), 1)
                expect_full(measure(field + "_restoration_child", start), expected_launch_hashes)

            client.close()
            changed_binary = bytearray(original_binary)
            changed_binary[-1] ^= 1
            _replace_file(executable, bytes(changed_binary), binary_metadata)

            def corrupted_rejected() -> None:
                status = runtime.native_runtime_status()
                _require(
                    not status.compatible and status.reason == "native_manifest_runtime_mismatch",
                    "same_size_corruption_rejection",
                )

            expect_full(measure("same_size_restored_mtime_corruption", corrupted_rejected), 1)
            _replace_file(executable, original_binary, binary_metadata)
            expect_full(measure("original_artifact_restoration", admitted), 1)
            expect_full(measure("restoration_fresh_child", start), expected_launch_hashes)
            client.close()
            expect_full(measure("retired_client_status", steady_status), _STATUS_SAMPLES)
    finally:
        if client is not None:
            client.close()
        if binary_replaced:
            _replace_file(executable, original_binary, binary_metadata)
        if manifest_replaced:
            _replace_file(manifest, original_manifest, manifest_metadata)
        identities.retire_native_path(executable)
        runtime._capabilities_for_identity.cache_clear()
    admitted()
    return {
        "schema": "hol-guard.installed-runtime-identity.v1",
        "platform": sys.platform,
        "machine": platform.machine(),
        "package_version": distribution.version,
        "build_sha": initial.capabilities.build_sha,
        "runtime_sha256": expected_digest,
        "runtime_size": len(original_binary),
        "runtime_module_sha256": python_module_digest,
        "identity_module_sha256": identity_module_digest,
        "manifest_sha256": hashlib.sha256(original_manifest).hexdigest(),
        "scope": "installed_status_and_real_stdio_child",
        "cross_release_upgrade_rollback": "not_exercised",
        "signing_qualification": "not_exercised",
        "cases": cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", required=True, type=Path)
    arguments = parser.parse_args()
    receipt = run_probe()
    rendered = json.dumps(receipt, sort_keys=True, indent=2) + "\n"
    arguments.json.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
