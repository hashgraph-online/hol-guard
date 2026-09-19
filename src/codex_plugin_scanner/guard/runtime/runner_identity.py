"""Identity.

Shared state and replaceable dependencies belong to the runner facade.
"""

from __future__ import annotations

from . import runner


def _hol_guard_runtime_source_sha256(package_root: runner.Path | None = None) -> str:
    resolved_package_root = package_root or runner.Path(runner.__file__).parents[2]
    digest = runner.hashlib.sha256()
    for source_path in sorted(resolved_package_root.rglob("*.py")):
        relative_path = source_path.relative_to(resolved_package_root).as_posix().encode("utf-8")
        source_bytes = source_path.read_bytes()
        digest.update(len(relative_path).to_bytes(8, "big"))
        digest.update(relative_path)
        digest.update(len(source_bytes).to_bytes(8, "big"))
        digest.update(source_bytes)
    return digest.hexdigest()


def _hol_guard_runtime_package_identity() -> tuple[str | None, str] | None:
    try:
        source_sha256 = runner._hol_guard_runtime_source_sha256()
    except OSError:
        return None
    try:
        distribution_version = runner.importlib.metadata.version("hol-guard")
    except runner.importlib.metadata.PackageNotFoundError:
        distribution_version = None
    return distribution_version, source_sha256


def _canonical_policy_rollout_percentage() -> int:
    raw = runner.os.environ.get(runner._POLICY_CANONICAL_ENFORCEMENT_ENV, "").strip().lower()
    if raw in {"", "0", "false", "off", "legacy"}:
        return 0
    if raw in {"1", "true", "on", "canonical"}:
        return 100
    try:
        percentage = int(raw)
    except ValueError:
        return 0
    return percentage if 1 <= percentage <= 100 else 0


def _canonical_policy_enforcement_enabled(
    *,
    device_id: str,
    workspace_id: str | None,
) -> bool:
    percentage = runner._canonical_policy_rollout_percentage()
    if percentage in {0, 100}:
        return percentage == 100
    cohort_key = f"{workspace_id or 'local'}:{device_id}".encode()
    # This is an in-memory rollout bucket for opaque installation IDs, not a password verifier.
    # codeql[py/weak-sensitive-data-hashing]
    cohort = int.from_bytes(runner.hashlib.sha256(cohort_key).digest()[:8], "big") % 100
    return cohort < percentage


def detect_harness(harness: str, context: runner.HarnessContext) -> runner.HarnessDetection:
    from ..consumer import detect_harness as _detect_harness

    return _detect_harness(harness, context)


def evaluate_detection(
    detection: runner.HarnessDetection,
    store: runner.GuardStore,
    config: runner.GuardConfig,
    *,
    default_action: str | None = None,
    persist: bool = True,
    trusted_request_overrides: runner.Mapping[str, str] | None = None,
    trusted_request_override_labels: runner.Mapping[str, str] | None = None,
    pending_approval_claims: list[tuple[runner.Mapping[str, object], str, str]] | None = None,
    claimed_saved_approval_overrides: runner.Mapping[str, str] | None = None,
    retained_saved_approval_overrides: runner.Mapping[str, str] | None = None,
    runtime_detector_context: runner.Mapping[str, object] | None = None,
    runtime_detector_block_reason: str | None = None,
):
    from ..consumer.service import evaluate_detection as _evaluate_detection

    return _evaluate_detection(
        detection,
        store,
        config,
        default_action=default_action,
        persist=persist,
        trusted_request_overrides=trusted_request_overrides,
        trusted_request_override_labels=trusted_request_override_labels,
        pending_approval_claims=pending_approval_claims,
        claimed_saved_approval_overrides=claimed_saved_approval_overrides,
        retained_saved_approval_overrides=retained_saved_approval_overrides,
        runtime_detector_context=runtime_detector_context,
        runtime_detector_block_reason=runtime_detector_block_reason,
    )


def get_adapter(harness: str) -> runner.HarnessAdapter:
    from ..adapters import get_adapter as _get_adapter

    return _get_adapter(harness)


def _computed_policy_bundle_hash(policy_bundle: dict[str, object]) -> str:
    return runner.computed_policy_bundle_hash(policy_bundle)
