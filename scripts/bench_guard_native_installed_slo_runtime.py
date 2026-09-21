"""Runtime-environment checks shared by the installed native SLO benchmark."""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.append(str(_REPO_ROOT))

import codex_plugin_scanner  # noqa: E402
from codex_plugin_scanner.guard.config import hook_fast_path_enabled  # noqa: E402
from codex_plugin_scanner.guard.native_runtime import native_mode, native_runtime_status  # noqa: E402
from scripts.native_slo_contract import (  # noqa: E402
    clear_proof_environment,
    proof_environment_violations,
)
from scripts.native_slo_session import AdapterSession  # noqa: E402


def _require(condition: bool, reason: object) -> None:
    if not condition:
        raise RuntimeError(f"native_installed_slo_failed: {reason}")


def _clear_proof_overrides() -> None:
    """Run the proof with product defaults, without test/oracle overrides."""

    _ = clear_proof_environment()
    _require(not proof_environment_violations(), "native/test override remained in proof environment")


def _readiness_samples(runtime: Path, count: int) -> list[float]:
    values: list[float] = []
    for _ in range(count):
        with AdapterSession(runtime) as session:
            values.append(session.readiness_ms)
    return values


def _runtime_summary(runtime: Path) -> dict[str, object]:
    status = native_runtime_status()
    _require(native_mode() == "auto", "native runtime is not using the default auto mode")
    _require(status.available and status.compatible, "native runtime unavailable")
    _require(status.reason == "native_ready", "native runtime is not ready")
    identity = status.identity
    if identity is None:
        raise RuntimeError("native_installed_slo_failed: native runtime identity unavailable")
    _require(runtime.resolve() == identity.path.resolve(), "benchmark runtime is not the bundled default runtime")
    capabilities = status.capabilities
    if capabilities is None:
        raise RuntimeError("native_installed_slo_failed: native capabilities unavailable")
    package_path = Path(codex_plugin_scanner.__file__).resolve()
    source_package = (_REPO_ROOT / "src" / "codex_plugin_scanner").resolve()
    package_origin = "source_tree" if package_path.is_relative_to(source_package) else "installed"
    _require(package_origin == "installed", "benchmark imported the source tree")
    _require(hook_fast_path_enabled(), "native hook fast path is disabled")
    return {
        "mode": status.mode,
        "target": capabilities.target,
        "runtime_version": capabilities.runtime_version,
        "protocol_version": capabilities.protocol_version,
        "package_origin": package_origin,
    }
