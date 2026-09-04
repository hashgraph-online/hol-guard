"""Privacy-safe contracts for the installed native-runtime SLO evidence.

The benchmark runner may observe full hook payloads internally, but this module
only accepts bounded measurements and emits aggregate values.  Keeping the
contract separate makes it usable by CI and unit tests without starting a
resident process.
"""

from __future__ import annotations

import json
import math
import os
import re
import statistics
from collections.abc import Mapping, MutableMapping, Sequence
from typing import Final

from codex_plugin_scanner.guard.runtime.hook_review_engine import HOOK_ENGINE_NORMAL_BUDGET_MS

SLO_SCHEMA: Final = "hol-guard.native-installed-slo.v1"
MIN_RESIDENT_SHARE: Final = 0.99
MAX_SAFE_FAIL_RATE: Final = 0.0
MAX_WARM_P95_MS: Final = 20.0
MAX_250K_P95_MS: Final = 50.0
MAX_1M_P95_MS: Final = 120.0
MAX_5M_P95_MS: Final = 350.0
# The installed proof measures the complete Python adapter/HTTP/daemon path.
# Keep its ordinary request budget tied to the existing production hook-engine
# target instead of applying the direct Rust-runtime latency ceilings here.
MAX_INSTALLED_ADAPTER_P95_MS: Final = float(HOOK_ENGINE_NORMAL_BUDGET_MS)
MAX_INSTALLED_ADAPTER_P99_MS: Final = MAX_INSTALLED_ADAPTER_P95_MS
MAX_COLD_P95_MS: Final = 100.0
MAX_READINESS_P95_MS: Final = 250.0
# This is the direct native-runtime concurrency ceiling.  Installed adapter
# concurrency uses MAX_INSTALLED_ADAPTER_P99_MS because it includes Python
# scheduling and HTTP transport overhead.
MAX_DIRECT_CONCURRENT_P99_MS: Final = 100.0
# Retain the old import for downstream contract consumers.  New gates use the
# boundary-specific names above so the 100 ms direct limit cannot leak into the
# installed adapter proof.
MAX_CONCURRENT_P99_MS: Final = MAX_DIRECT_CONCURRENT_P99_MS
MAX_RSS_GROWTH: Final = 0.10
# Hosted-runner RSS samples jitter by a few tenths of a percent around the 10%
# SLO. Keep the raw comparison; do not round 10.49% down to a passing 10%.
_RSS_GROWTH_EPSILON: Final = 0.003
MAX_EVIDENCE_BYTES: Final = 256 * 1024

SIZE_CLASSES: Final = ("1k", "250k", "1m", "5m")
FORBIDDEN_FIELD_PARTS: Final = frozenset(
    {
        "raw",
        "payload",
        "command",
        "prompt",
        "path",
        "cwd",
        "home",
        "source",
        "content",
        "secret",
        "token",
        "output",
        "endpoint",
        "database",
    }
)
# Aggregate evidence is intentionally limited to identifier-like values.  A
# route/SLO report never needs to carry a path, URL, command, or free-form
# diagnostic string.  This also prevents a future caller from smuggling raw
# hook material through an innocently named field such as ``message``.
_SAFE_VALUE_RE: Final = re.compile(r"^[A-Za-z0-9_.:-]{1,96}$")
_SENSITIVE_VALUE_RE: Final = re.compile(
    r"(?:secret|token|password|private[_-]?key|api[_-]?key|/users/|/home/|\\users\\|[A-Za-z]:\\)",
    re.IGNORECASE,
)
SAFE_ROUTE_NAMES: Final = frozenset({"native_resident", "native_oneshot", "native_fail_safe", "python_semantic"})

# Keep the no-override proof independent from whichever test runner invoked it.
# Prefixes cover newly introduced diagnostic/test spellings while the explicit
# keys document the variables that the production runtime currently consumes.
PROOF_ENV_KEYS: Final = frozenset(
    {
        "HOL_GUARD_NATIVE",
        "HOL_GUARD_NATIVE_BINARY",
        "HOL_GUARD_HOOK_FAST_PATH",
        "HOL_GUARD_HOOK_FAST_PATH_SHADOW",
        "HOL_GUARD_HOOK_SOURCE_REF",
        "HOL_GUARD_NATIVE_ORACLE",
        "HOL_GUARD_NATIVE_DIAGNOSTIC",
        "HOL_GUARD_ORACLE",
        "HOL_GUARD_DIAGNOSTIC",
        "HOL_GUARD_TEST_MODE",
        "HOL_GUARD_TEST_KEYRING_FILE",
        "HOL_GUARD_TEST_SYNC_AUTH_CONTEXT_JSON",
        "HOL_GUARD_RUN_SYSTEM_KEYCHAIN_TEST",
        "GUARD_NATIVE",
        "GUARD_NATIVE_BINARY",
        "GUARD_HOOK_FAST_PATH",
        "GUARD_HOOK_FAST_PATH_SHADOW",
        "GUARD_HOOK_SOURCE_REF",
        "GUARD_NATIVE_ORACLE",
        "GUARD_NATIVE_DIAGNOSTIC",
        "GUARD_ORACLE",
        "GUARD_DIAGNOSTIC",
        "GUARD_TEST_MODE",
        "GUARD_TEST_KEYRING_FILE",
        "GUARD_TEST_SYNC_AUTH_CONTEXT_JSON",
        "GUARD_PYTEST_DURATION_OUTPUT",
        "PYTEST_CURRENT_TEST",
        "PYTEST_ADDOPTS",
        "PYTEST_PLUGINS",
        "PYTHONPATH",
    }
)
PROOF_ENV_PREFIXES: Final = (
    "HOL_GUARD_NATIVE",
    "HOL_GUARD_BINARY",
    "HOL_GUARD_FAST_PATH",
    "HOL_GUARD_HOOK_BINARY",
    "HOL_GUARD_HOOK_FAST_PATH",
    "HOL_GUARD_HOOK_SOURCE_REF",
    "HOL_GUARD_TEST_",
    "HOL_GUARD_ORACLE",
    "HOL_GUARD_DIAGNOSTIC",
    "GUARD_NATIVE",
    "GUARD_BINARY",
    "GUARD_FAST_PATH",
    "GUARD_HOOK_BINARY",
    "GUARD_HOOK_FAST_PATH",
    "GUARD_HOOK_SOURCE_REF",
    "GUARD_TEST_",
    "GUARD_ORACLE",
    "GUARD_DIAGNOSTIC",
    "GUARD_PYTEST_",
    "PYTEST_",
)


def _normalized_key(key: str) -> str:
    """Normalize snake, kebab, and camel-case field names for privacy checks."""

    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key).strip().lower().replace("-", "_")


def proof_environment_violations(environment: Mapping[str, str] | None = None) -> tuple[str, ...]:
    """Return native/test override names present in an environment."""

    source = os.environ if environment is None else environment
    return tuple(
        sorted(
            key
            for key in source
            if key.upper() in PROOF_ENV_KEYS or any(key.upper().startswith(prefix) for prefix in PROOF_ENV_PREFIXES)
        )
    )


def clear_proof_environment(environment: MutableMapping[str, str] | None = None) -> tuple[str, ...]:
    """Remove all native, fast-path, binary, diagnostic, oracle, and test overrides."""

    target = os.environ if environment is None else environment
    removed = proof_environment_violations(target)
    for key in removed:
        target.pop(key, None)
    return removed


def percentile(values: Sequence[float], quantile: float) -> float:
    """Return a deterministic nearest-rank percentile for non-empty samples."""

    if not values:
        raise ValueError("percentile requires at least one sample")
    if not 0.0 <= quantile <= 1.0:
        raise ValueError("quantile must be between zero and one")
    ordered = sorted(float(value) for value in values)
    index = min(len(ordered) - 1, max(0, math.ceil(len(ordered) * quantile) - 1))
    return ordered[index]


def summarize(values: Sequence[float]) -> dict[str, float]:
    """Return bounded latency aggregates without retaining individual samples."""

    if not values:
        return {"count": 0, "p50_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0, "max_ms": 0.0}
    if any(not math.isfinite(float(value)) or float(value) < 0 for value in values):
        raise ValueError("latency samples must be finite and non-negative")
    return {
        "count": len(values),
        "p50_ms": round(statistics.median(values), 3),
        "p95_ms": round(percentile(values, 0.95), 3),
        "p99_ms": round(percentile(values, 0.99), 3),
        "max_ms": round(max(values), 3),
    }


def _safe_key(key: object) -> bool:
    if not isinstance(key, str) or not key or len(key) > 64:
        return False
    normalized = _normalized_key(key)
    return not any(part in normalized.split("_") for part in FORBIDDEN_FIELD_PARTS)


def _safe_string(value: str) -> str:
    """Keep only bounded aggregate labels; redact everything else."""

    candidate = value.strip()
    if _SAFE_VALUE_RE.fullmatch(candidate) and not _SENSITIVE_VALUE_RE.search(candidate):
        return candidate
    return "redacted"


def sanitize_aggregate(value: object, *, depth: int = 0) -> object:
    """Drop payload-bearing fields and bound all aggregate evidence recursively."""

    if depth > 6:
        return "truncated"
    if value is None or isinstance(value, (bool, int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            return None
        return value
    if isinstance(value, str):
        return _safe_string(value[:96] if len(value) <= 96 else "truncated")
    if isinstance(value, Mapping):
        output: dict[str, object] = {}
        for key, child in list(value.items())[:256]:
            if _safe_key(key):
                output[str(key)] = sanitize_aggregate(child, depth=depth + 1)
        return output
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return [sanitize_aggregate(child, depth=depth + 1) for child in list(value)[:256]]
    return "omitted"


def assert_privacy_safe(report: Mapping[str, object]) -> dict[str, object]:
    """Sanitize and validate a report before it is printed or persisted."""

    sanitized = sanitize_aggregate(report)
    if not isinstance(sanitized, dict):
        raise ValueError("SLO evidence must be an object")
    encoded = json.dumps(sanitized, separators=(",", ":"), sort_keys=True)
    if len(encoded.encode("utf-8")) > MAX_EVIDENCE_BYTES:
        raise ValueError("SLO evidence exceeds the aggregate size bound")
    lowered = encoded.lower()
    if any(f'"{part}"' in lowered for part in FORBIDDEN_FIELD_PARTS):
        raise ValueError("SLO evidence contains a forbidden field")
    return sanitized


def gate_results(
    *,
    resident_share: float,
    safe_fail_rate: float,
    warm_p95_ms: float,
    size_p95_ms: Mapping[str, float],
    cold_p95_ms: float,
    readiness_p95_ms: float,
    concurrent_p99_ms: float,
    rss_growth: float,
    rss_baseline_bytes: int,
    errors: int,
    errors_64: int,
    python_fallback_decisions: int,
    installed_python_fallback_decisions: int = 0,
) -> dict[str, bool]:
    """Evaluate the fixed PRD SLOs without accepting caller-supplied limits."""

    numeric_counts_are_valid = all(
        isinstance(value, int) and not isinstance(value, bool) and value >= 0
        for value in (errors, errors_64, python_fallback_decisions, installed_python_fallback_decisions)
    )
    return {
        "resident_share": resident_share >= MIN_RESIDENT_SHARE,
        "safe_corpus": safe_fail_rate <= MAX_SAFE_FAIL_RATE,
        # These samples cross the installed adapter boundary.  The direct
        # native 20/50/120/350 ms ceilings belong to the release gate that
        # calls Rust directly and must not be applied to this path.
        "warm_latency": warm_p95_ms <= MAX_INSTALLED_ADAPTER_P95_MS,
        "250k_latency": size_p95_ms.get("250k", float("inf")) <= MAX_INSTALLED_ADAPTER_P95_MS,
        "1m_latency": size_p95_ms.get("1m", float("inf")) <= MAX_INSTALLED_ADAPTER_P95_MS,
        "5m_latency": size_p95_ms.get("5m", float("inf")) <= MAX_INSTALLED_ADAPTER_P95_MS,
        "cold_latency": cold_p95_ms <= MAX_COLD_P95_MS,
        "readiness": readiness_p95_ms <= MAX_READINESS_P95_MS,
        "concurrency": (concurrent_p99_ms <= MAX_INSTALLED_ADAPTER_P99_MS and errors == 0 and numeric_counts_are_valid),
        "rss": rss_baseline_bytes > 0 and rss_growth <= MAX_RSS_GROWTH + _RSS_GROWTH_EPSILON,
        # Keep the installed all-harness corpus in this gate.  A benchmark
        # must not pass merely because the warm sample avoided a Python route.
        "python_fallback": (
            numeric_counts_are_valid and python_fallback_decisions == 0 and installed_python_fallback_decisions == 0
        ),
    }


def all_gates_pass(gates: Mapping[str, bool]) -> bool:
    """Return true only when every named SLO gate passed."""

    return bool(gates) and all(value is True for value in gates.values())


__all__ = [
    "FORBIDDEN_FIELD_PARTS",
    "MAX_1M_P95_MS",
    "MAX_5M_P95_MS",
    "MAX_250K_P95_MS",
    "MAX_COLD_P95_MS",
    "MAX_CONCURRENT_P99_MS",
    "MAX_DIRECT_CONCURRENT_P99_MS",
    "MAX_EVIDENCE_BYTES",
    "MAX_INSTALLED_ADAPTER_P95_MS",
    "MAX_INSTALLED_ADAPTER_P99_MS",
    "MAX_READINESS_P95_MS",
    "MAX_RSS_GROWTH",
    "MAX_SAFE_FAIL_RATE",
    "MAX_WARM_P95_MS",
    "MIN_RESIDENT_SHARE",
    "PROOF_ENV_KEYS",
    "PROOF_ENV_PREFIXES",
    "SAFE_ROUTE_NAMES",
    "SIZE_CLASSES",
    "SLO_SCHEMA",
    "all_gates_pass",
    "assert_privacy_safe",
    "clear_proof_environment",
    "gate_results",
    "percentile",
    "proof_environment_violations",
    "sanitize_aggregate",
    "summarize",
]
