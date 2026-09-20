"""Fixture-only forwarding to an admitted Linux native diagnostic receiver.

Production environment allowlists remain unchanged. The private daemon opts
in before starting its AdapterSession and restores every provider on exit.
Only the exact installed runtime and three receiver identity fields qualify.
"""

from __future__ import annotations

import importlib
import os
import stat
import sys
from collections.abc import Iterator, Mapping
from contextlib import ExitStack, contextmanager
from pathlib import Path
from unittest.mock import patch

from scripts.native_slo_contract import clear_proof_environment
from scripts.native_slo_rust_phase_process import Executable

PHASE_ENVIRONMENT_KEYS = frozenset(
    {"HOL_GUARD_NATIVE_PHASE_SOCKET", "HOL_GUARD_NATIVE_PHASE_DEVICE", "HOL_GUARD_NATIVE_PHASE_INODE"}
)
_PROVIDER_MODULES = (
    "native_runtime",
    "native_hook_edge",
    "native_pretool",
    "native_command_model",
    "native_approval_bridge_v3",
)


def _identity(path: Path, *, directory: bool) -> tuple[int, int, int, int]:
    metadata = path.lstat()
    correct_type = stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISSOCK(metadata.st_mode)
    mode = stat.S_IMODE(metadata.st_mode)
    if not correct_type or metadata.st_uid != os.geteuid() or mode != (0o700 if directory else 0o600):
        raise ValueError("native_phase_endpoint_refused")
    return metadata.st_dev, metadata.st_ino, metadata.st_uid, mode


def attested_phase_environment(environment: Mapping[str, str]) -> dict[str, str]:
    """Copy exactly three fields after bounded private-path identity checks.

    These pathname checks do not prove an atomic datagram peer identity. The
    separate receiver still checks kernel credentials and owned generations.
    """
    if sys.platform != "linux" or set(environment) != PHASE_ENVIRONMENT_KEYS:
        raise ValueError("native_phase_environment_refused")
    values = dict(environment)
    if any(not isinstance(value, str) for value in values.values()):
        raise ValueError("native_phase_environment_refused")
    path = Path(values["HOL_GUARD_NATIVE_PHASE_SOCKET"])
    parent = path.parent
    if (
        not path.is_absolute()
        or str(path) != values["HOL_GUARD_NATIVE_PHASE_SOCKET"]
        or len(os.fsencode(path)) >= 108
        or path.name != "phase.sock"
        or parent.parent != Path("/tmp")
        or not parent.name.startswith("guard-native-phase-")
        or parent.resolve(strict=True) != parent
    ):
        raise ValueError("native_phase_endpoint_refused")
    numbers: list[int] = []
    for key in ("HOL_GUARD_NATIVE_PHASE_DEVICE", "HOL_GUARD_NATIVE_PHASE_INODE"):
        value = values[key]
        if not 1 <= len(value) <= 20 or not value.isascii() or not value.isdecimal() or int(value) > 2**64 - 1:
            raise ValueError("native_phase_environment_refused")
        numbers.append(int(value))
    before = _identity(parent, directory=True)
    endpoint = _identity(path, directory=False)
    if endpoint[:2] != tuple(numbers) or _identity(parent, directory=True) != before:
        raise ValueError("native_phase_endpoint_changed")
    return values


def _installed_identity(runtime: Path, executable: Executable) -> None:
    from scripts.bench_guard_native_installed_slo_runtime import _runtime_summary

    identity = _runtime_summary(runtime)
    if identity["runtime_sha256"] != executable.sha256 or not executable.current():
        raise ValueError("native_phase_runtime_changed")


def fixture_environment(phase_environment: Mapping[str, str] | None) -> dict[str, str]:
    environment = dict(os.environ)
    clear_proof_environment(environment)
    if phase_environment is not None:
        environment.update(attested_phase_environment(phase_environment))
    return environment


@contextmanager
def native_phase_fixture(runtime: Path, *, enabled: bool) -> Iterator[None]:
    if not enabled:
        yield
        return
    fields = {key: os.environ[key] for key in PHASE_ENVIRONMENT_KEYS if key in os.environ}
    with forward_native_phase_environment(runtime, fields):
        yield


@contextmanager
def forward_native_phase_environment(runtime: Path, environment: Mapping[str, str]) -> Iterator[None]:
    """Forward admitted diagnostics only inside this private daemon lifetime."""
    admitted = attested_phase_environment(environment)
    with ExitStack() as lifetime:
        executable = Executable(runtime)
        lifetime.callback(executable.close)
        _installed_identity(runtime, executable)
        modules = [importlib.import_module("codex_plugin_scanner.guard." + name) for name in _PROVIDER_MODULES]
        stream_module = importlib.import_module("codex_plugin_scanner.guard.native_resident_stream")
        original = modules[0]._isolated_environment
        original_stream = stream_module.isolated_hook_environment
        if any(module._isolated_environment is not original for module in modules):
            raise ValueError("native_phase_environment_provider_changed")

        def checked_fields() -> dict[str, str]:
            try:
                if executable.current():
                    return attested_phase_environment(admitted)
            except (OSError, ValueError):
                pass
            # Lost diagnostic admission cannot fail an original hook request.
            # Existing production providers still return their exact result.
            return {}

        def isolated_environment() -> dict[str, str]:
            result: dict[str, str] = original()
            result.update(checked_fields())
            return result

        def isolated_stream_environment(source: Mapping[str, str] | None = None) -> dict[str, str]:
            result: dict[str, str] = original_stream(source)
            result.update(checked_fields())
            return result

        for module in modules:
            lifetime.enter_context(patch.object(module, "_isolated_environment", isolated_environment))
        lifetime.enter_context(patch.object(stream_module, "isolated_hook_environment", isolated_stream_environment))
        yield
