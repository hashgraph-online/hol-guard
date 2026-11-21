"""Guard wrapper-mode runtime execution."""

from __future__ import annotations

import errno
import hashlib
import importlib.metadata
import io
import json
import logging
import math
import os
import socket
import time
import urllib.error
from collections.abc import Callable, Iterable, Mapping
from contextlib import contextmanager, suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ...version import __version__
from ..approval_gate import ApprovalGateError
from ..cli.oauth_client import (
    GuardDpopKeyMaterial,
    resolve_guard_oauth_client_config,
    validate_guard_sync_endpoint,
)
from ..config import VALID_RECEIPT_REDACTION_LEVELS
from ..dpop_key_binding import signed_dpop_proof
from ..edge_events import build_runtime_session_event
from ..harness_context import HarnessContext
from ..managed_controls_policy_fields import ParsedManagedControlsPolicy
from ..models import PolicyDecision
from ..native_policy_bundle import (
    NATIVE_UNAVAILABLE_REJECTION,
    PolicyBundleNativeError,
    PolicyBundleNativeUnavailableError,
    native_rejection_code,
)
from ..native_prompt import request_from_dict as _prompt_request_from_dict  # noqa: F401
from ..native_runner_authority import NativeRunnerAuthorityError
from ..oauth_token_claims import (
    oauth_access_token_expires_at,
    oauth_binding_from_credentials,
    oauth_effective_binding,
)
from ..package_firewall_defaults import extract_cloud_user_profile
from ..package_firewall_entitlement import (
    build_oauth_package_firewall_entitlement,
    reconcile_connect_state_with_oauth_entitlement,
)
from ..policy_bundle_activation import activate_with_reason
from ..policy_bundle_decisions import build_policy_bundle_decisions as _materialize_policy_bundle_decisions
from ..policy_bundle_delivery import (
    effective_policy_bundle_acknowledgement,
    is_failed_policy_bundle_acknowledgement,
)
from ..policy_bundle_parser import (
    CANONICAL_COMPILE_REJECTION_PREFIX,
    non_empty_string,
    policy_bundle_acceptance_checkpoint,
    policy_bundle_admission_rejection,
    policy_bundle_downgrade_verdict,
    policy_bundle_is_enforceable,
)
from ..policy_bundle_parser import (
    policy_bundle_rejection_payload as _policy_bundle_rejection_payload,
)
from ..policy_bundle_trusted_keys import (
    MANAGED_POLICY_BUNDLE_KEYRING_PROVENANCE_STATE_KEY,
    PolicyBundleVerificationKey,
    policy_bundle_keyring_payload,
    validate_synced_policy_bundle,
)
from ..policy_bundle_v2 import (
    POLICY_BUNDLE_V2_CONTRACT,
    validated_policy_bundle_v2_acknowledgement,
)
from ..policy_document_io import PolicyCompilationError, compile_policy_bundle_document
from ..redaction import redact_sensitive_text
from ..review_signature_verification import sync_review_verification_keys
from ..shims import package_shim_cloud_coverage
from ..store import GuardStore
from ..synced_policy import cached_policy_bundle_validation, validated_synced_policy_bundle
from . import runner_native_authority as _authority
from . import runner_native_sync as _sync
from . import runner_policy_shadow as _shadow
from .extension_catalog_handshake import (
    catalog_runtime_unavailable_summary,
    prepare_extension_catalog_handshake,
    runtime_session_success_summary,
    runtime_summary_device_id,
)
from .extension_catalog_handshake import (
    validate_extension_catalog_sync_response as _validate_extension_catalog_sync_response,
)
from .extension_catalog_sync import build_builtin_extension_catalog_wire
from .extension_control_authority import ExtensionControlAuthorityView
from .fleet_posture import (
    CAPABILITY as FLEET_POSTURE_CAPABILITY,
)
from .fleet_posture import (
    FOLLOWUP_STATE_KEY as _FLEET_POSTURE_FOLLOWUP_KEY,
)
from .fleet_posture import (
    FleetPostureBuild,
    FleetPostureSettings,
    build_fleet_posture_state,
)
from .fleet_posture_tools import device_display_name
from .guard_run_evaluation import _get_default_detector_registry as _get_default_detector_registry
from .local_runtime_fallbacks import local_receipt_redaction_level
from .managed_controls_sync import (
    apply_custom_extension_continuity_from_sync,
    effective_managed_controls_for_activation,
    validated_managed_controls_candidate,
)
from .managed_controls_sync import (
    managed_controls_lkg_capabilities as _managed_controls_lkg_capabilities,  # noqa: F401
)
from .managed_controls_sync import (
    managed_controls_negotiated_capabilities as _managed_controls_negotiated_capabilities,
)
from .managed_controls_sync import (
    managed_controls_runtime_sync_posture as _managed_controls_runtime_sync_posture,
)
from .policy_bundle_failure_ack import cached_bundle_failure_acknowledgement, failed_acknowledgement
from .sync_retry_delay import parse_retry_after_value
from .workspace_assessment_sync import (
    build_workspace_assessment_sync_safely,
)

_POLICY_DOCUMENT_VERSIONS = ("guard.hashgraphonline.com/v1alpha1",)
_POLICY_BUNDLE_VERSIONS = ("guard-policy-bundle.v1", "guard-policy-bundle.v2")
_POLICY_CONTRACTS = ("guard-policy-bundle/v1", "guard-policy-bundle/v2")
_POLICY_YAML_IMPORT_ENV = "HOL_GUARD_POLICY_YAML_IMPORT"
# The canonical compiler turns an exact `match.commands` rule into the same
# exact-shell-command rows the hook looks up, so Guard Cloud may deliver exact
# command rules in a v2 bundle to a device that advertises this.
POLICY_EXACT_COMMAND_RULES_CAPABILITY = "policy-document-exact-commands.v1"
# The canonical compiler turns a signed bundle's `review` rule into the same
# review row a v1 bundle materializes, so Guard Cloud may deliver review rules
# in a v2 bundle to a device that advertises this.
POLICY_DOCUMENT_REVIEW_RULES_CAPABILITY = "policy-document-review-rules.v1"
# The hook applies a v2 bundle's command-pattern Allow rule to a simple command.
POLICY_COMMAND_PATTERN_ALLOW_CAPABILITY = "policy-document-command-pattern-allow.v1"
# The hook asks or blocks every command in a risk group a v2 bundle rule names
# (``match.riskGroups``), such as every command that deletes files.
POLICY_RISK_GROUP_RULES_CAPABILITY = "policy-document-risk-group-rules.v1"
# Accepts Cloud exceptions signed into a v2 bundle (``cloudExceptions``).
POLICY_BUNDLE_V2_CLOUD_EXCEPTIONS_CAPABILITY = "policy-bundle-v2-cloud-exceptions.v1"
# Re-exported for the supply-chain services; the resident derives the endpoint.
_normalized_receipts_sync_url = _sync.normalized_receipts_sync_url


def _hol_guard_runtime_source_sha256(package_root: Path | None = None) -> str:
    resolved_package_root = package_root or Path(__file__).parents[2]
    digest = hashlib.sha256()
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
        source_sha256 = _hol_guard_runtime_source_sha256()
    except OSError:
        return None
    try:
        distribution_version = importlib.metadata.version("hol-guard")
    except importlib.metadata.PackageNotFoundError:
        distribution_version = None
    return distribution_version, source_sha256


_LOADED_HOL_GUARD_RUNTIME_PACKAGE_IDENTITY = _hol_guard_runtime_package_identity()


@contextmanager
def _guard_sync_auth_lock(store: GuardStore):
    with store.hold_oauth_refresh_lock():
        yield


_LOGGER = logging.getLogger(__name__)
_GUARD_SYNC_USER_AGENT = f"hol-guard/{__version__}"
_SYNC_HTTP_TIMEOUT_SECONDS = 20
_SYNC_HTTP_RETRY_TIMEOUT_SECONDS = 120
_RUNTIME_SYNC_TIMEOUT_SECONDS = 10
_RUNTIME_SYNC_RETRY_TIMEOUT_SECONDS = 90
_GUARD_EVENTS_ENDPOINT_UNAVAILABLE_RETRY_MINUTES = 5  # single 404 shouldn't disable sync for a full day


class GuardSyncNotConfiguredError(RuntimeError):
    """Raised when Guard Cloud sync is requested before the machine is paired."""


class GuardSyncEndpointUntrustedError(GuardSyncNotConfiguredError):
    """Raised when a configured Guard Cloud endpoint fails trust validation."""


class GuardSyncNotAvailableError(RuntimeError):
    """Raised when Guard Cloud sync is blocked by plan limits or temporary outages."""

    retryable: bool

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.retryable = retryable


class GuardSyncAuthorizationExpiredError(GuardSyncNotConfiguredError):
    """Raised when local OAuth material can no longer mint a runtime access token."""


def _policy_bundle_is_version_downgrade(
    existing_bundle: dict[str, object] | None,
    next_bundle: dict[str, object],
    *,
    expected_last_good_bundle: dict[str, object] | None = None,
) -> bool:
    return policy_bundle_downgrade_verdict(
        existing_bundle,
        next_bundle,
        expected_last_good=expected_last_good_bundle,
    )


def _policy_bundle_admission_rejection(
    store: GuardStore,
    existing_bundle: dict[str, object] | None,
    candidate: dict[str, object],
) -> str | None:
    """The first gate a validated synced candidate fails, or ``None``."""

    return policy_bundle_admission_rejection(candidate, _policy_bundle_downgrade_reference(store, existing_bundle))


def _policy_bundle_acceptance_checkpoint(policy_bundle: Mapping[str, object]) -> dict[str, object]:
    return policy_bundle_acceptance_checkpoint(dict(policy_bundle))


def _policy_bundle_downgrade_reference(
    store: GuardStore,
    existing_bundle: dict[str, object] | None,
) -> dict[str, object] | None:
    return _sync.policy_bundle_downgrade_reference(
        (
            store.get_sync_payload("policy_bundle_acceptance_checkpoint"),
            existing_bundle,
            store.get_sync_payload("policy_bundle_last_good"),
        ),
        store.get_cloud_workspace_id(),
    )


def _validate_cached_policy_bundle(
    store: GuardStore,
    policy_bundle: object,
) -> tuple[dict[str, object] | None, str | None]:
    """Revalidate cached policy authority before any rule is made effective."""

    return cached_policy_bundle_validation(store, policy_bundle)


def _build_canonical_policy_bundle_decisions(
    policy_bundle: dict[str, object],
    *,
    device_id: str,
    device_name: str,
) -> list[PolicyDecision]:
    """Persist the canonical bundle rules the resident scoped to this device."""

    return [
        PolicyDecision(
            harness=row.decision.harness,
            scope=row.decision.scope,
            action=row.decision.action,
            artifact_id=row.decision.artifact_id,
            artifact_hash=row.decision.artifact_hash,
            workspace=row.decision.workspace,
            publisher=row.decision.publisher,
            reason=row.decision.reason,
            owner=row.rule_id,
            source="policy-bundle-canonical",
            expires_at=row.decision.expires_at,
        )
        for row in compile_policy_bundle_document(
            policy_bundle,
            device_id=device_id,
            device_name=device_name,
        )
    ]


def _build_policy_bundle_decisions(
    policy_bundle: dict[str, object],
    *,
    device_id: str,
    device_name: str,
) -> list[PolicyDecision]:
    # Cloud sends a v2 bundle only when v1 cannot carry the policy, so every
    # device enforces its compiled rules. The rollout flag only decides whether
    # a v2 bundle that disagrees with the legacy shadow is refused.
    if policy_bundle.get("contractVersion") == POLICY_BUNDLE_V2_CONTRACT:
        return _build_canonical_policy_bundle_decisions(
            policy_bundle,
            device_id=device_id,
            device_name=device_name,
        )
    return _materialize_policy_bundle_decisions(
        policy_bundle,
        device_id=device_id,
        device_name=device_name,
    )


def policy_bundle_candidate_decisions(
    store: GuardStore,
    policy_bundle: dict[str, object],
    *,
    is_v2: bool,
    device_id: str,
    device_name: str,
    canonical_enforcement: bool,
    existing_policy_bundle: object,
    now: str,
) -> tuple[list[PolicyDecision], str | None, str | None]:
    """The decisions a verified bundle activates, or the reason it is refused.

    Both sync routes answer this the same way: the CLI's ``sync_receipts`` and
    the daemon's headless policy sync. A v2 bundle compiles to canonical
    decisions and is then held against the legacy shadow, so a device that
    cannot prove the two agree keeps the policy it already has. A bundle that
    fails to compile is reported here rather than raised at the caller, which
    on the daemon route would otherwise drop the request without a response.
    """

    try:
        if not is_v2:
            return (
                _build_policy_bundle_decisions(
                    policy_bundle,
                    device_id=device_id,
                    device_name=device_name,
                ),
                None,
                None,
            )
        canonical_decisions = _build_canonical_policy_bundle_decisions(
            policy_bundle,
            device_id=device_id,
            device_name=device_name,
        )
    except PolicyCompilationError as error:
        # The stored record drops the rule id for a code about the whole document.
        return [], f"{CANONICAL_COMPILE_REJECTION_PREFIX}{error.code}", error.rule_id
    except PolicyBundleNativeError as error:
        return [], native_rejection_code(error), None

    stored_legacy = store.get_sync_payload("policy_bundle_legacy_last_good")
    try:
        shadow_source, evaluating = _shadow.policy_shadow_source(
            policy_bundle,
            stored_legacy=stored_legacy,
            existing=existing_policy_bundle,
        )
    except NativeRunnerAuthorityError:
        # Rust picks the shadow. Without that choice the candidate cannot be
        # proven equivalent, so it is held like a missing comparison below.
        shadow_source, evaluating, native_shadow_unavailable = None, False, True
    else:
        native_shadow_unavailable = False
    legacy_payload = {"stored": stored_legacy, "existing": existing_policy_bundle}.get(shadow_source or "")
    try:
        legacy_decisions = (
            _build_policy_bundle_decisions(
                legacy_payload,
                device_id=device_id,
                device_name=device_name,
            )
            if isinstance(legacy_payload, dict)
            else []
        )
    except PolicyCompilationError:
        # The stored legacy bundle is the shadow, not the candidate. One that no
        # longer compiles cannot show agreement, so it stands in as unavailable
        # rather than refusing a candidate that is itself well formed.
        legacy_decisions = []
    except PolicyBundleNativeError as error:
        return [], native_rejection_code(error), None

    mismatch_reasons: tuple[str, ...] = ("native_shadow_unavailable",)
    rejection: str | None = "native_shadow_unavailable"
    if not native_shadow_unavailable and evaluating:
        # An Evaluate bundle keeps its canonical rows empty on purpose, so it
        # has nothing to drift from and needs no verdict from the resident.
        # This is the answer the Rust policy_shadow_verdict kind gives for an
        # evaluating candidate; test_policy_bundle_v2 pins that answer, so the
        # two stay in step. Asking anyway would refuse the bundle whenever the
        # resident is unreachable, which the Evaluate rollout must not do.
        mismatch_reasons, rejection = (), None
    elif not native_shadow_unavailable:
        try:
            mismatch_reasons, rejection = _shadow.policy_shadow_verdict(
                legacy_decisions,
                canonical_decisions,
                evaluating=evaluating,
                canonical_enforcement=canonical_enforcement,
            )
        except NativeRunnerAuthorityError:
            # Rust owns the shadow comparison. Without its verdict the candidate
            # cannot be proven equivalent, so treat it as a blocking mismatch:
            # keep the existing policy and never activate the new bundle.
            mismatch_reasons, rejection = ("native_shadow_unavailable",), "native_shadow_unavailable"
    if mismatch_reasons:
        store.add_event(
            "policy_bundle/shadow_mismatch",
            {
                "canonicalRows": len(canonical_decisions),
                "legacyRows": len(legacy_decisions),
                "reasonCodes": list(mismatch_reasons),
                "status": "mismatch",
            },
            now,
        )
    return canonical_decisions, rejection, None


def sync_receipts(
    store: GuardStore,
    *,
    persist_sync_summary: bool = True,
    persist_connect_state: bool = True,
    auth_context: dict[str, object] | None = None,
    home_dir: Path | None = None,
    workspace_dir: Path | None = None,
    include_aibom: bool = False,
    force_aibom: bool = False,
    managed_controls_publish: (Callable[[ExtensionControlAuthorityView, Callable[[], None]], object] | None) = None,
) -> dict[str, object]:
    """Push local receipts to the configured sync endpoint."""

    resolved_auth_context = auth_context if auth_context is not None else _resolve_guard_sync_auth_context(store)
    _sync.normalized_receipts_sync_url(_validate_guard_sync_url(_auth_context_sync_url(resolved_auth_context)))
    local_guard_online_at = _now()
    redaction_level = _resolve_cloud_receipt_redaction_level(store)
    _ensure_cloud_review_privacy_projection(store, level=redaction_level, synced_at=local_guard_online_at)
    _ensure_relaxed_receipt_redaction_resync(store, level=redaction_level, synced_at=local_guard_online_at)
    inventory = store.list_inventory()
    remote_decisions: set[PolicyDecision] = set()
    device_id, device_name = _guard_device_metadata(store)
    sync_context = _receipt_sync_context(
        store=store,
        local_guard_online_at=local_guard_online_at,
        device_id=device_id,
        device_name=device_name,
    )
    # The posture rides on the first request of the cycle only; later batches
    # carry receipts and the plain context.
    fleet_posture = _build_fleet_posture_for_sync(
        store,
        sync_context=sync_context,
        home_dir=home_dir,
        workspace_dir=workspace_dir,
    )
    workspace_assessments = build_workspace_assessment_sync_safely(store)
    bundle_hash_sent = _sync_context_bundle_hash(sync_context)
    from .cloud_bundle_sync import ReceiptUploadAnswer, cloud_receipt_upload

    uploaded = cloud_receipt_upload(
        Path(store.guard_home),
        {
            "redactionLevel": redaction_level,
            "deviceId": device_id,
            "deviceName": device_name,
            "now": local_guard_online_at,
            "syncContext": sync_context,
            "fleetPosture": None
            if fleet_posture is None
            else {
                "payload": fleet_posture.payload,
                "nextState": fleet_posture.next_state,
                "advancedInventory": fleet_posture.advanced_inventory,
            },
            "workspaceAssessments": None
            if workspace_assessments is None
            else {"payload": workspace_assessments.payload, "digest": workspace_assessments.digest},
            # A sign-in the caller supplied is never refreshed here.
            "allowAuthRefresh": auth_context is None,
        },
        auth_context=resolved_auth_context,
    )
    if not isinstance(uploaded, dict):
        raise RuntimeError("Guard Cloud sync returned an invalid response payload.")
    if uploaded.get("auth_refreshed") is True:
        resolved_auth_context = _resolve_guard_sync_auth_context(store)
    upload_answer = ReceiptUploadAnswer.from_native(uploaded)
    now = upload_answer.now
    policy_bundle_field_provided = upload_answer.policy_bundle_provided
    policy_bundle_field_malformed = upload_answer.policy_bundle_malformed
    policy_bundle_payload = upload_answer.policy_bundle
    policy_bundle_sync_payload = upload_answer.policy_bundle_sync_payload
    policy_bundle_delivery_field_provided = upload_answer.policy_bundle_delivery_provided
    policy_bundle_delivery_payload = upload_answer.policy_bundle_delivery
    review_verification_keys_payload = upload_answer.review_verification_keys
    aibom_context: dict[str, object] = {}
    if home_dir is not None:
        aibom_context["home_dir"] = str(home_dir)
    if workspace_dir is not None:
        aibom_context["workspace_dir"] = str(workspace_dir)
        workspace_id = store.get_cloud_workspace_id()
        if workspace_id is not None:
            aibom_context["workspace_id"] = workspace_id
    if aibom_context:
        store.set_sync_payload("aibom_inventory_context", aibom_context, now)
    # Top-level ``policy``, ``teamPolicyPack``, and ``exceptions`` fields are
    # legacy unsigned siblings. They may be present on an authenticated HTTPS
    # response, but they are not covered by the pinned policy-bundle signature
    # and therefore cannot be persisted or materialized as local authority.
    # Only decisions and exceptions inside a validated signed bundle are used.
    # The native upload already cached the advisories, stored the alert
    # preferences and recorded the advisory events.
    advisories_stored = upload_answer.advisories_stored
    cloud_workspace_id = store.get_cloud_workspace_id()
    canonical_enforcement = _sync.canonical_policy_enforcement_enabled(
        device_id=device_id,
        workspace_id=cloud_workspace_id,
    )
    candidate_policy_decisions: list[PolicyDecision] = []
    validated_policy_bundle: dict[str, object] | None = None
    candidate_managed_controls: ParsedManagedControlsPolicy | None = None
    candidate_managed_capabilities = frozenset[str]()
    validated_policy_bundle_delivery: dict[str, object] | None = None
    effective_managed_controls: ParsedManagedControlsPolicy | None = None
    effective_managed_capabilities = frozenset[str]()
    effective_policy_bundle: dict[str, object] | None = None
    retain_existing_policy_authority = False
    activation_last_error: dict[str, object] = {}
    # The bundle Cloud is told failed when authority is cleared below.
    failed_policy_bundle: object = None
    failed_policy_bundle_reason: str | None = None
    trusted_policy_bundle_keys: tuple[PolicyBundleVerificationKey, ...] = ()
    update_last_good = False
    existing_policy_bundle_payload = store.get_sync_payload("policy_bundle")
    existing_policy_bundle, existing_policy_bundle_error = _validate_cached_policy_bundle(
        store,
        existing_policy_bundle_payload,
    )
    runtime_session_summary = store.get_sync_payload("runtime_session_summary")
    delivery_device_id = runtime_summary_device_id(runtime_session_summary, device_id)
    if policy_bundle_field_provided:
        policy_bundle_rejection_reason: str | None
        policy_bundle_rejection_rule_id: str | None = None
        if policy_bundle_field_malformed or policy_bundle_payload is None:
            policy_bundle_rejection_reason = "invalid_policy_bundle"
        else:
            validated_policy_bundle, policy_bundle_rejection_reason, trusted_policy_bundle_keys = (
                validate_synced_policy_bundle(
                    policy_bundle_payload,
                    stored_keyring=store.get_sync_payload("policy_bundle_keyring"),
                    sync_payload=policy_bundle_sync_payload,
                    supply_chain_keyring=store.get_sync_payload("supply_chain_bundle_keyring"),
                    managed_keyring_provenance=store.get_sync_payload(
                        MANAGED_POLICY_BUNDLE_KEYRING_PROVENANCE_STATE_KEY
                    ),
                    expected_workspace_id=store.get_cloud_workspace_id(),
                )
            )
        if existing_policy_bundle_error == NATIVE_UNAVAILABLE_REJECTION:
            # The downgrade reference could not be validated, so a downgrade
            # cannot be ruled out. Reject instead of comparing to nothing.
            validated_policy_bundle = None
            policy_bundle_rejection_reason = NATIVE_UNAVAILABLE_REJECTION
        try:
            admission_rejection = (
                None
                if validated_policy_bundle is None
                else _policy_bundle_admission_rejection(store, existing_policy_bundle, validated_policy_bundle)
            )
            if admission_rejection is not None:
                validated_policy_bundle = None
                policy_bundle_rejection_reason = admission_rejection
        except PolicyBundleNativeError as error:
            validated_policy_bundle = None
            policy_bundle_rejection_reason = native_rejection_code(error)
        candidate_managed_capabilities = _managed_controls_negotiated_capabilities(store, policy_bundle_sync_payload)
        (
            validated_policy_bundle,
            candidate_managed_controls,
            validated_policy_bundle_delivery,
            managed_controls_error,
            validated_bundle_is_v2,
        ) = validated_managed_controls_candidate(
            validated_policy_bundle,
            negotiated_capabilities=candidate_managed_capabilities,
            delivery_field_provided=policy_bundle_delivery_field_provided,
            delivery_payload=policy_bundle_delivery_payload,
            workspace_id=cloud_workspace_id,
            device_id=delivery_device_id,
            runtime_summary=runtime_session_summary,
            guard_home=store.guard_home,
        )
        if managed_controls_error is not None:
            policy_bundle_rejection_reason = managed_controls_error
        if validated_policy_bundle is not None:
            (
                candidate_policy_decisions,
                candidate_rejection_reason,
                candidate_rejection_rule_id,
            ) = policy_bundle_candidate_decisions(
                store,
                validated_policy_bundle,
                is_v2=validated_bundle_is_v2,
                device_id=device_id,
                device_name=device_name,
                canonical_enforcement=canonical_enforcement,
                existing_policy_bundle=existing_policy_bundle,
                now=now,
            )
            if candidate_rejection_reason is not None:
                validated_policy_bundle = None
                policy_bundle_rejection_reason = candidate_rejection_reason
                policy_bundle_rejection_rule_id = candidate_rejection_rule_id
        if validated_policy_bundle is not None:
            effective_policy_bundle = validated_policy_bundle
            update_last_good = True
        else:
            # A response that claims signed-bundle authority cannot route the
            # same policy through unsigned sibling fields after verification
            # fails. Keep only a still-valid signed current/LKG bundle.
            remote_decisions.clear()
            last_good_bundle_payload = store.get_sync_payload("policy_bundle_last_good")
            last_good_bundle, _last_good_error = _validate_cached_policy_bundle(
                store,
                last_good_bundle_payload,
            )
            # A valid current bundle may be newer than last-good when a prior
            # sync stopped after persisting current but before advancing the
            # checkpoint. Prefer current so a rejected refresh cannot roll
            # policy authority back to an older signed bundle.
            effective_policy_bundle = existing_policy_bundle or last_good_bundle
            activation_last_error = _policy_bundle_rejection_payload(
                policy_bundle_rejection_reason,
                policy_bundle_rejection_rule_id,
            )
            failed_policy_bundle = policy_bundle_payload
            failed_policy_bundle_reason = str(activation_last_error["reason"])
            store.record_policy_bundle_rejection(activation_last_error, now=now)
    else:
        effective_policy_bundle = existing_policy_bundle
        if effective_policy_bundle is None:
            last_good_bundle_payload = store.get_sync_payload("policy_bundle_last_good")
            effective_policy_bundle, last_good_error = _validate_cached_policy_bundle(
                store,
                last_good_bundle_payload,
            )
            if (
                effective_policy_bundle is None
                and isinstance(existing_policy_bundle_payload, dict)
                and existing_policy_bundle_payload
            ):
                rejection_reason = existing_policy_bundle_error or last_good_error or "invalid_policy_bundle"
                activation_last_error = _policy_bundle_rejection_payload(rejection_reason)
                failed_policy_bundle = existing_policy_bundle_payload
                failed_policy_bundle_reason = rejection_reason
                store.record_policy_bundle_rejection(activation_last_error, now=now)
        if not activation_last_error:
            stored_last_error = store.get_sync_payload("policy_bundle_last_error")
            if isinstance(stored_last_error, dict):
                activation_last_error = stored_last_error
    cloud_exception_items: list[dict[str, object]] = []
    remote_policies_stored = 0
    remote_policy_sync_blocked = False
    if effective_policy_bundle is not None:
        activation_keyring = store.get_sync_payload("policy_bundle_keyring")
        if effective_policy_bundle is validated_policy_bundle and trusted_policy_bundle_keys:
            activation_keyring = policy_bundle_keyring_payload(
                trusted_policy_bundle_keys,
                workspace_id=store.get_cloud_workspace_id(),
            )
        activation_bundle, activation_reason, activation_keys = validate_synced_policy_bundle(
            effective_policy_bundle,
            stored_keyring=activation_keyring,
            supply_chain_keyring=store.get_sync_payload("supply_chain_bundle_keyring"),
            managed_keyring_provenance=store.get_sync_payload(MANAGED_POLICY_BUNDLE_KEYRING_PROVENANCE_STATE_KEY),
            expected_workspace_id=store.get_cloud_workspace_id(),
        )
        try:
            if activation_bundle is not None and not policy_bundle_is_enforceable(activation_bundle):
                activation_bundle = None
                activation_reason = "inactive_rollout_state"
            acceptance_checkpoint = store.get_sync_payload("policy_bundle_acceptance_checkpoint")
            if (
                activation_bundle is not None
                and isinstance(acceptance_checkpoint, dict)
                and _policy_bundle_is_version_downgrade(
                    acceptance_checkpoint,
                    activation_bundle,
                )
            ):
                activation_bundle = None
                activation_reason = "bundle_version_downgrade"
        except PolicyBundleNativeError as error:
            activation_bundle = None
            activation_reason = native_rejection_code(error)
        if activation_bundle is None:
            activation_last_error = _policy_bundle_rejection_payload(activation_reason)
            store.record_policy_bundle_rejection(activation_last_error, now=now)
            if failed_policy_bundle is None:
                failed_policy_bundle = effective_policy_bundle
                failed_policy_bundle_reason = str(activation_last_error["reason"])
            effective_policy_bundle = None
        else:
            # Use exactly the payload and anchor set from the final live trust
            # check for materialization and atomic activation. A key rotation
            # or revocation between initial selection and this check therefore
            # cannot leave the previously selected current/LKG bundle active.
            effective_policy_bundle = activation_bundle
            trusted_policy_bundle_keys = activation_keys
            if activation_bundle.get("contractVersion") == POLICY_BUNDLE_V2_CONTRACT:
                effective_managed_controls, effective_managed_capabilities, managed_error = (
                    effective_managed_controls_for_activation(
                        store,
                        activation_bundle,
                        validated_policy_bundle=validated_policy_bundle,
                        candidate=candidate_managed_controls,
                        candidate_capabilities=candidate_managed_capabilities,
                    )
                )
                if managed_error is not None:
                    activation_last_error = _policy_bundle_rejection_payload(managed_error)
                    store.record_policy_bundle_rejection(activation_last_error, now=now)
                    effective_policy_bundle = None
                    retain_existing_policy_authority = True
    if effective_policy_bundle is None and activation_last_error.get("reason") == NATIVE_UNAVAILABLE_REJECTION:
        # The resident could not decide. Do not activate anything new, but a
        # transient outage must not also erase the previously verified policy.
        retain_existing_policy_authority = True
    if effective_policy_bundle is None:
        if not retain_existing_policy_authority:
            _clear_policy_bundle_authority_reporting_failure(
                store,
                now,
                policy_bundle_last_error=activation_last_error,
                managed_controls_publish=managed_controls_publish,
                device_id=device_id,
                device_name=device_name,
                policy_bundle=failed_policy_bundle,
                reason=failed_policy_bundle_reason or _optional_string(activation_last_error.get("reason")),
            )
            _reset_cloud_receipt_redaction_authority(store, synced_at=now)
    else:
        try:
            selected_policy_decisions = (
                candidate_policy_decisions
                if validated_policy_bundle is not None
                and effective_policy_bundle.get("bundleHash") == validated_policy_bundle.get("bundleHash")
                else _build_policy_bundle_decisions(
                    effective_policy_bundle,
                    device_id=device_id,
                    device_name=device_name,
                )
            )
            policy_bundle_ack = effective_policy_bundle_acknowledgement(
                device_id=device_id,
                device_name=device_name,
                effective_policy_bundle=effective_policy_bundle,
                validated_policy_bundle=validated_policy_bundle,
                validated_delivery=validated_policy_bundle_delivery,
                stored_acknowledgement=_stored_policy_bundle_acknowledgement(store),
                synced_at=now,
            )
        except PolicyBundleNativeError as error:
            # Fail closed: nothing new is materialized or acknowledged. Only an
            # outage keeps the prior authority; a deterministic native rejection
            # is a verdict, so it must not leave a stale bundle in force.
            activation_last_error = _policy_bundle_rejection_payload(native_rejection_code(error))
            store.record_policy_bundle_rejection(activation_last_error, now=now)
            rejected_policy_bundle = effective_policy_bundle
            effective_policy_bundle = None
            if not isinstance(error, PolicyBundleNativeUnavailableError) and not retain_existing_policy_authority:
                _clear_policy_bundle_authority_reporting_failure(
                    store,
                    now,
                    policy_bundle_last_error=activation_last_error,
                    managed_controls_publish=managed_controls_publish,
                    device_id=device_id,
                    device_name=device_name,
                    policy_bundle=failed_policy_bundle or rejected_policy_bundle,
                    reason=failed_policy_bundle_reason or str(activation_last_error["reason"]),
                )
                _reset_cloud_receipt_redaction_authority(store, synced_at=now)
            selected_policy_decisions = []
            policy_bundle_ack = {}
        if effective_policy_bundle is not None:
            remote_decisions.update(selected_policy_decisions)
            try:
                cloud_exception_items = _policy_bundle_cloud_exception_items(
                    store,
                    device_id=device_id,
                    sync_exceptions=[],
                    policy_bundle=effective_policy_bundle,
                    policy_bundle_ack=policy_bundle_ack,
                )
                custom_extension_continuity = apply_custom_extension_continuity_from_sync(
                    store,
                    effective_policy_bundle,
                    device_id=delivery_device_id,
                    negotiated_capabilities=effective_managed_capabilities,
                    now=now,
                )
                activated, activation_rejection_reason = activate_with_reason(
                    store.apply_policy_bundle_authority,
                    list(remote_decisions),
                    now,
                    policy_bundle=effective_policy_bundle,
                    policy_bundle_keyring=policy_bundle_keyring_payload(
                        trusted_policy_bundle_keys,
                        workspace_id=store.get_cloud_workspace_id(),
                    ),
                    cloud_exceptions=cloud_exception_items,
                    policy_bundle_ack=policy_bundle_ack,
                    policy_bundle_checkpoint=_policy_bundle_acceptance_checkpoint(effective_policy_bundle),
                    update_last_good=update_last_good,
                    policy_bundle_last_error=activation_last_error,
                    managed_controls_policy=effective_managed_controls,
                    managed_controls_negotiated_capabilities=effective_managed_capabilities,
                    managed_controls_delivery=validated_policy_bundle_delivery,
                    managed_controls_publish=managed_controls_publish,
                    custom_extension_continuity=custom_extension_continuity,
                    remote_write_authorized=True,
                )
                if activated is None:
                    cloud_exception_items = []
                    activation_last_error = _policy_bundle_rejection_payload(activation_rejection_reason)
                    store.record_policy_bundle_rejection(activation_last_error, now=now, persist_last_error=True)
                else:
                    remote_policies_stored = len(remote_decisions)
                    store.record_policy_bundle_activation(
                        effective_policy_bundle,
                        now=now,
                        local_level=local_receipt_redaction_level(store.guard_home),
                        rollback_reason=(
                            str(activation_last_error.get("reason", "invalid_policy_bundle"))
                            if validated_policy_bundle is None and policy_bundle_field_provided
                            else None
                        ),
                    )
            except PolicyBundleNativeError as error:
                cloud_exception_items = []
                activation_last_error = _policy_bundle_rejection_payload(native_rejection_code(error))
                store.record_policy_bundle_rejection(activation_last_error, now=now, persist_last_error=True)
            except ApprovalGateError as error:
                cloud_exception_items = []
                remote_policy_sync_blocked = True
                activation_last_error = _policy_bundle_rejection_payload(error.code)
                store.record_policy_bundle_rejection(
                    activation_last_error,
                    now=now,
                    persist_last_error=True,
                    gate_blocked={
                        "error": error.code,
                        "remote_policies_count": len(remote_decisions),
                    },
                )
    _send_policy_ack_followup(
        store,
        sync_context=sync_context,
        bundle_hash_sent=bundle_hash_sent,
        auth_context=resolved_auth_context,
        device_id=device_id,
        device_name=device_name,
        local_guard_online_at=local_guard_online_at,
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        now=now,
    )
    review_verification_keys_rejection = (
        sync_review_verification_keys(
            review_verification_keys_payload,
            store=store,
            workspace_id=cloud_workspace_id,
            now=now,
        )
        if review_verification_keys_payload is not None
        else None
    )
    if upload_answer.answers_error is not None:
        # Raised once the policy bundle the same answer carried has been handled.
        raise RuntimeError(upload_answer.answers_error)
    try:
        pain_signals_uploaded = sync_pain_signals(store, auth_context=resolved_auth_context)
    except RuntimeError as pain_signal_error:
        if "429" in str(pain_signal_error):
            pain_signals_uploaded = 0
        else:
            raise
    value_metrics, weekly_digest = _sync.value_metrics(store.list_events(limit=_sync.VALUE_METRIC_EVENT_LIMIT), now)
    summary: dict[str, object] = {
        "synced_at": upload_answer.synced_at,
        "receipts_stored": upload_answer.receipts_stored,
        "advisories_stored": advisories_stored,
        "exceptions_stored": 0,
        "cloud_exceptions_stored": len(cloud_exception_items),
        "remote_policies_stored": remote_policies_stored,
        "pain_signals_uploaded": pain_signals_uploaded,
        "receipts": upload_answer.receipts,
        "receipt_cursor_rowid": upload_answer.receipt_cursor_rowid,
        "receipt_cursor_backfill": upload_answer.receipt_cursor_backfill,
        "inventory": 0,
        "inventory_tracked": len(inventory),
        "value_metrics": value_metrics,
        "weekly_digest": weekly_digest,
    }
    if upload_answer.receipts_skipped:
        # Too large for any request; the cursor has moved past them.
        summary["receipts_skipped"] = upload_answer.receipts_skipped
        _LOGGER.warning("Guard sync skipped %d receipt(s) too large to upload.", upload_answer.receipts_skipped)
    if remote_policy_sync_blocked:
        summary["remote_policy_sync_blocked"] = True
    if review_verification_keys_rejection is not None:
        summary["review_verification_keys_rejected"] = review_verification_keys_rejection
    summary["guard_events_v1"] = sync_guard_events(store, auth_context=resolved_auth_context)
    if include_aibom:
        from ..aibom_cli import sync_aibom_snapshots_if_due

        summary["aibom_inventory"] = sync_aibom_snapshots_if_due(
            store,
            generated_at=now,
            auth_context=resolved_auth_context,
            force=force_aibom,
            home_dir=home_dir,
            workspace_dir=workspace_dir,
        )
    else:
        summary["aibom_inventory"] = {
            "synced": False,
            "skipped": True,
            "reason": "background_deferred",
            "message": (
                "AIBOM inventory refresh is deferred to the Guard daemon background lane; "
                "run hol-guard sync --deep to refresh now."
            ),
        }
    if persist_sync_summary:
        store.set_sync_payload("sync_summary", summary, now)
    if persist_connect_state:
        store.record_latest_guard_connect_sync_success(sync_payload=summary, now=now)
    return summary


def _guard_cloud_http_error_details(error: urllib.error.HTTPError) -> tuple[str, bool]:
    answer = _cloud_http_error(error)
    return answer.message, answer.retryable


def sync_supply_chain_bundle(
    store: GuardStore,
    *,
    auth_context: dict[str, object] | None = None,
) -> dict[str, object]:
    """Fetch, verify, and persist the active supply-chain bundle for the cloud workspace."""

    from .cloud_bundle_sync import cloud_bundle_sync

    result = cloud_bundle_sync(Path(store.guard_home), "supply_chain", auth_context=auth_context)
    return result if isinstance(result, dict) else {}


def sync_network_protection_bundle(
    store: GuardStore,
    *,
    auth_context: dict[str, object] | None = None,
) -> dict[str, object]:
    """Fetch, verify, and save the workspace's signed network protection bundle."""

    from .cloud_bundle_sync import cloud_bundle_sync

    result = cloud_bundle_sync(Path(store.guard_home), "network", auth_context=auth_context)
    return result if isinstance(result, dict) else {}


def sync_network_protection_bundle_best_effort(
    store: GuardStore,
    *,
    auth_context: dict[str, object] | None = None,
) -> dict[str, object] | None:
    """Sync the network protection bundle, keeping the saved one on failure.

    Returns ``None`` when no workspace is connected, and a ``failed`` status
    with the error when the fetch or verification fails.
    """

    from .cloud_bundle_sync import cloud_bundle_sync

    try:
        result = cloud_bundle_sync(Path(store.guard_home), "network_best_effort", auth_context=auth_context)
    except RuntimeError as error:
        return {"status": "failed", "error": str(error)}
    return result if isinstance(result, dict) else None


def sync_guard_events(
    store: GuardStore,
    *,
    auth_context: dict[str, object] | None = None,
) -> dict[str, object]:
    """Push pending GuardEventV1 envelopes to Guard Cloud through the native runtime."""

    from .cloud_bundle_sync import cloud_event_sync

    result = cloud_event_sync(Path(store.guard_home), "guard_events", auth_context=auth_context)
    return result if isinstance(result, dict) else {}


def _guard_events_endpoint_unavailable_recently(store: GuardStore) -> bool:
    summary = store.get_sync_payload("guard_events_v1_summary")
    if not isinstance(summary, dict):
        return False
    if summary.get("sync_reason") not in ("guard_events_endpoint_unavailable", "guard_events_rate_limited"):
        return False
    synced_at = summary.get("synced_at")
    if not isinstance(synced_at, str):
        return True
    parsed = _parse_iso_timestamp(synced_at)
    if parsed is None:
        return True
    return datetime.now(timezone.utc) - parsed < timedelta(minutes=_GUARD_EVENTS_ENDPOINT_UNAVAILABLE_RETRY_MINUTES)


def sync_runtime_session(
    store: GuardStore,
    *,
    session: dict[str, object],
    auth_context: dict[str, object] | None = None,
    catalog_failures: list[Exception] | None = None,
) -> dict[str, object]:
    """Publish the active Guard runtime session so the dashboard can show the machine immediately.

    A caller that passes ``catalog_failures`` takes over a failed Extension
    catalog step: the error is appended there instead of raised, so the caller
    can finish the rest of its sync before reporting it.
    """

    from .cloud_bundle_sync import cloud_event_sync

    resolved_auth_context = auth_context or _resolve_guard_sync_auth_context(store)
    sync_url = _sync.normalized_runtime_sessions_sync_url(
        _validate_guard_sync_url(_auth_context_sync_url(resolved_auth_context))
    )
    session_payload = _cloud_runtime_session_payload(store, session)
    answer = cloud_event_sync(
        Path(store.guard_home),
        "runtime_session",
        auth_context=resolved_auth_context,
        session=session_payload,
    )
    if not isinstance(answer, dict):
        raise RuntimeError("Invalid sync response")
    if answer.get("status") == "skipped" and isinstance(answer.get("summary"), dict):
        return dict(answer["summary"])
    payload = answer.get("response")
    if not isinstance(payload, dict):
        raise RuntimeError("Invalid sync response")
    catalog_sync: dict[str, object]
    catalog_failed = False
    try:
        catalog_sync = _sync_extension_catalog_from_runtime_handshake(
            store=store,
            guard_home=store.guard_home,
            auth_context=resolved_auth_context,
            runtime_sync_url=sync_url,
            runtime_response=payload,
            session_payload=session_payload,
        )
    except Exception as error:
        if catalog_failures is None:
            raise
        catalog_failures.append(error)
        catalog_failed = True
        catalog_sync = {
            "extension_catalog_sync_status": "failed",
            "extension_catalog_sync_reason": "catalog_sync_failed",
        }
    synced_at = _sync_timestamp(payload)
    summary = runtime_session_success_summary(
        session_payload=session_payload,
        response_payload=payload,
        synced_at=synced_at,
        catalog_sync=catalog_sync,
    )
    if not catalog_failed:
        # A failed catalog step returns before this write when it raises; keep
        # the previous summary, whose policy metadata identity and credential
        # the managed-controls view still reads, when the caller takes it over.
        store.set_sync_payload("runtime_session_summary", summary, synced_at)
    workspace_id = store.get_cloud_workspace_id()
    device_id = store.get_or_create_installation_id()
    if not _guard_events_endpoint_unavailable_recently(store):
        store.add_guard_event_v1(
            build_runtime_session_event(
                session_id=str(session_payload["sessionId"]),
                occurred_at=synced_at,
                payload=session_payload,
                workspace_id=workspace_id,
                device_id=device_id,
            )
        )
    return summary


def _local_guard_runtime_session(
    *,
    device_id: str = "local-machine",
    workspace_id: str | None = None,
) -> dict[str, object]:
    capabilities = [
        "approval-center",
        "guard-cloud-sync",
        "local-daemon",
        FLEET_POSTURE_CAPABILITY,
        POLICY_BUNDLE_V2_CLOUD_EXCEPTIONS_CAPABILITY,
        # Exact command rules reach the hook through canonical decisions,
        # which every device activates from a verified v2 bundle.
        POLICY_EXACT_COMMAND_RULES_CAPABILITY,
        POLICY_DOCUMENT_REVIEW_RULES_CAPABILITY,
        POLICY_COMMAND_PATTERN_ALLOW_CAPABILITY,
        POLICY_RISK_GROUP_RULES_CAPABILITY,
    ]
    session: dict[str, object] = {
        "harness": "hol-guard",
        "surface": "cli",
        "status": "active",
        "client_name": "hol-guard",
        "client_title": "HOL Guard CLI",
        "client_version": __version__,
        "workspace": "local-machine",
        "capabilities": capabilities,
        "policy_document_versions": list(_POLICY_DOCUMENT_VERSIONS),
        "policy_bundle_versions": list(_POLICY_BUNDLE_VERSIONS),
        "policy_contracts": list(_POLICY_CONTRACTS),
        "yaml_import": os.environ.get(_POLICY_YAML_IMPORT_ENV) == "1",
    }
    if _sync.canonical_policy_enforcement_enabled(
        device_id=device_id,
        workspace_id=workspace_id,
    ):
        session["canonical_policy_enforcement"] = True
    return session


def sync_local_guard_cloud_proof(
    store: GuardStore,
    *,
    auth_context: dict[str, object] | None = None,
    now: str | None = None,
    home_dir: Path | None = None,
    workspace_dir: Path | None = None,
    include_aibom: bool = False,
    force_aibom: bool = False,
    managed_controls_publish: (Callable[[ExtensionControlAuthorityView, Callable[[], None]], object] | None) = None,
) -> dict[str, object]:
    """Publish the local Guard runtime session before syncing receipts."""
    resolved_now = now or _now()
    with store.hold_cloud_sync_lock():
        reconcile_connect_state_with_oauth_entitlement(store, now=resolved_now)
        resolved_auth_context = auth_context if auth_context is not None else _resolve_guard_sync_auth_context(store)
        device_id = store.get_or_create_installation_id()
        workspace_id = store.get_cloud_workspace_id()
        # The policy bundle arrives with the receipts sync. A failed Extension
        # catalog step must not keep it from this device, so it is reported
        # only after the receipts sync has delivered and acknowledged policy.
        catalog_failures: list[Exception] = []
        runtime_summary = sync_runtime_session(
            store,
            session=_local_guard_runtime_session(
                device_id=device_id,
                workspace_id=workspace_id,
            ),
            auth_context=resolved_auth_context,
            catalog_failures=catalog_failures,
        )
        receipts_summary = sync_receipts(
            store,
            persist_sync_summary=False,
            persist_connect_state=False,
            auth_context=resolved_auth_context,
            home_dir=home_dir,
            workspace_dir=workspace_dir,
            include_aibom=include_aibom,
            force_aibom=force_aibom,
            managed_controls_publish=managed_controls_publish,
        )
        if catalog_failures:
            raise catalog_failures[0]
        summary = dict(receipts_summary)
        summary.update(
            {
                "runtime_session_id": runtime_summary.get("runtime_session_id"),
                "runtime_session_synced_at": runtime_summary.get("runtime_session_synced_at"),
                "runtime_sessions_visible": runtime_summary.get("runtime_sessions_visible"),
                "local_guard_online_at": runtime_summary.get("local_guard_online_at")
                or receipts_summary.get("local_guard_online_at"),
                "runtime_harness": runtime_summary.get("runtime_harness"),
                "runtime_surface": runtime_summary.get("runtime_surface"),
                "runtime_workspace": runtime_summary.get("runtime_workspace"),
                "runtime_device_id": runtime_summary.get("runtime_device_id"),
                "runtime": runtime_summary,
                "receipts": dict(receipts_summary),
            }
        )
        recorded_at = str(summary.get("synced_at") or summary.get("runtime_session_synced_at") or _now())
        store.set_sync_payload("sync_summary", summary, recorded_at)
        store.record_latest_guard_connect_sync_success(sync_payload=summary, now=recorded_at)
        return summary


def sync_pain_signals(
    store: GuardStore,
    *,
    auth_context: dict[str, object] | None = None,
) -> int:
    """Upload the cloud pain signals through the native runtime; the count uploaded."""

    from .cloud_bundle_sync import cloud_event_sync

    result = cloud_event_sync(Path(store.guard_home), "pain_signals", auth_context=auth_context or None)
    return result if isinstance(result, int) and not isinstance(result, bool) else 0


def _policy_bundle_cloud_exception_items(
    store: GuardStore,
    *,
    device_id: str | None = None,
    sync_exceptions: list[dict[str, object]] | None = None,
    policy_bundle: dict[str, object] | None = None,
    policy_bundle_ack: dict[str, object] | None = None,
) -> list[dict[str, object]]:
    """Build bundle-derived exceptions without mutating activation state."""

    resolved_device_id = device_id
    if resolved_device_id is None:
        resolved_device_id, _device_name = _guard_device_metadata(store)
    bundle_ack = policy_bundle_ack
    if bundle_ack is None:
        bundle_ack_payload = store.get_sync_payload("policy_bundle_ack")
        bundle_ack = bundle_ack_payload if isinstance(bundle_ack_payload, dict) else None
    # ``sync_exceptions`` is retained as an explicit compatibility boundary so
    # callers can demonstrate that legacy unsigned siblings were considered
    # and rejected. It must never contribute enforcement authority.
    del sync_exceptions
    if not isinstance(policy_bundle, dict):
        return []
    try:
        return _sync.cloud_exceptions(policy_bundle, device_id=resolved_device_id, policy_bundle_ack=bundle_ack)
    except NativeRunnerAuthorityError as error:
        # Without the runtime's listing the bundle cannot be activated with
        # the exceptions it grants: an outage, not a verdict on the bundle.
        raise PolicyBundleNativeUnavailableError(NATIVE_UNAVAILABLE_REJECTION) from error


def _sign_guard_dpop_proof(
    *,
    request_url: str,
    method: str,
    dpop_key_material: GuardDpopKeyMaterial,
    access_token: str | None = None,
    nonce: str | None = None,
    now: datetime | None = None,
) -> str:
    try:
        return signed_dpop_proof(
            private_key_pem=dpop_key_material.private_key_pem,
            algorithm=dpop_key_material.algorithm,
            public_jwk=dpop_key_material.public_jwk,
            request_url=request_url,
            method=method,
            issued_at=int((now or datetime.now(timezone.utc)).timestamp()),
            access_token=access_token if isinstance(access_token, str) else None,
            nonce=nonce if isinstance(nonce, str) else None,
        )
    except PolicyBundleNativeUnavailableError as exc:
        raise GuardSyncNotAvailableError(
            "Guard could not sign the Guard Cloud request. Try again shortly.",
            retryable=True,
        ) from exc
    except PolicyBundleNativeError as exc:
        raise GuardSyncAuthorizationExpiredError(
            "Guard Cloud authorization key is invalid. Reconnect Guard Cloud."
        ) from exc


def _guard_http_header_value(response: object, header_name: str) -> str | None:
    headers = getattr(response, "headers", None)
    if headers is None:
        return None
    value = headers.get(header_name)
    if value is None:
        header_items = getattr(headers, "items", None)
        if callable(header_items):
            target_header = header_name.lower()
            raw_header_items = header_items()
            if not isinstance(raw_header_items, Iterable):
                raw_header_items = ()
            for header_item in raw_header_items:
                if not isinstance(header_item, tuple) or len(header_item) != 2:
                    continue
                current_name, current_value = header_item
                if isinstance(current_name, str) and current_name.lower() == target_header:
                    value = current_value
                    break
    if not isinstance(value, str):
        return None
    normalized_value = value.strip()
    return normalized_value or None


def _http_error_payload(error: urllib.error.HTTPError) -> object:
    try:
        raw_body = error.read()
    except OSError:
        raw_body = b""
    error.fp = io.BytesIO(raw_body)
    if not raw_body:
        return None
    try:
        return json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _dpop_nonce_from_http_error(error: urllib.error.HTTPError, payload: object) -> str | None:
    if error.code not in {400, 401}:
        return None
    nonce = _guard_http_header_value(error, "DPoP-Nonce")
    if nonce is None:
        return None
    if isinstance(payload, dict):
        oauth_error = str(payload.get("error") or "").strip()
        if oauth_error and oauth_error not in {"use_dpop_nonce", "invalid_dpop_proof"}:
            return None
    return nonce


def _guard_oauth_reauthorization_message() -> str:
    return "Guard authorization expired. Run `hol-guard connect` to sign in again."


def _guard_oauth_reconnect_after_revoked_message() -> str:
    return (
        "Guard Cloud sign-in on this device is no longer valid. Run `hol-guard connect` to repair it and sign in again."
    )


def _guard_runtime_was_upgraded() -> bool:
    loaded_identity = _LOADED_HOL_GUARD_RUNTIME_PACKAGE_IDENTITY
    if loaded_identity is None:
        return True
    return _hol_guard_runtime_package_identity() != loaded_identity


def _guard_runtime_upgrade_restart_message() -> str:
    return (
        "HOL Guard was upgraded while this process was running. Restart the agent application "
        "before Guard Cloud access resumes."
    )


def _guard_runtime_was_upgraded() -> bool:
    loaded_identity = _LOADED_HOL_GUARD_RUNTIME_PACKAGE_IDENTITY
    if loaded_identity is None:
        return True
    return _hol_guard_runtime_package_identity() != loaded_identity


def _guard_runtime_upgrade_restart_message() -> str:
    return (
        "HOL Guard was upgraded while this process was running. Restart the agent application "
        "before Guard Cloud access resumes."
    )


def _oauth_authorization_error_requires_fresh_sign_in(error: Exception) -> bool:
    message = str(error).strip().lower()
    return (
        "invalid_grant" in message
        or "missing, expired, or already consumed" in message
        or _guard_oauth_reconnect_after_revoked_message().lower() in message
    )


def clear_revoked_guard_oauth_sign_in(store: GuardStore) -> bool:
    """Return True when refresh proves the local OAuth grant was revoked and cleared."""
    try:
        with _guard_sync_auth_lock(store):
            credentials = store.get_oauth_local_credentials(allow_primary=True)
            if credentials is None:
                return False
            try:
                _resolve_guard_sync_auth_context_from_oauth_credentials(store, credentials)
            except GuardSyncAuthorizationExpiredError as error:
                if _oauth_authorization_error_requires_fresh_sign_in(error):
                    store._clear_oauth_local_credentials_locked()
                    return True
                return False
    except (RuntimeError, OSError, TimeoutError):
        return False
    return False


def repair_guard_cloud_connect_storage(store: GuardStore) -> dict[str, object]:
    """Repair local OAuth storage without clearing sign-in state."""
    repaired_storage = store.repair_oauth_local_credential_storage_from_primary()
    credentials = store.get_oauth_local_credentials(allow_primary=True)
    repaired_oauth_binding = False
    rebound_review_events = 0
    if credentials is not None:
        repaired_oauth_binding = _persist_recovered_oauth_binding(store, credentials)
        binding = store.get_review_event_oauth_binding()
        if binding is not None:
            rebound_review_events = store.refresh_review_event_outbox_binding_for_identity(
                workspace_id=binding["workspace_id"],
                oauth_subject_hash=binding["oauth_subject_hash"],
                machine_id=binding["machine_id"],
                machine_installation_id=binding["machine_installation_id"],
            )
    existing_sign_in_valid = credentials is not None
    return {
        "cleared_stale_sign_in": False,
        "existing_sign_in_valid": existing_sign_in_valid,
        "rebound_review_events": rebound_review_events,
        "repaired_oauth_binding": repaired_oauth_binding,
        "repaired_storage": repaired_storage,
    }


def prepare_guard_cloud_connect_authorization(store: GuardStore) -> dict[str, object]:
    """Repair local OAuth storage and clear revoked sign-in before reconnect."""
    repaired_storage = repair_guard_cloud_connect_storage(store)["repaired_storage"]
    cleared_stale_sign_in = clear_revoked_guard_oauth_sign_in(store)
    existing_sign_in_valid = store.get_oauth_local_credentials(allow_primary=True) is not None
    return {
        "repaired_storage": repaired_storage,
        "cleared_stale_sign_in": cleared_stale_sign_in,
        "existing_sign_in_valid": existing_sign_in_valid,
    }


def _guard_sync_reconnect_message() -> str:
    return "Guard Cloud sync endpoint is not trusted. Run `hol-guard connect` to restore Cloud sync."


def _validate_guard_sync_url(sync_url: str, *, issuer: str | None = None) -> str:
    try:
        return validate_guard_sync_endpoint(sync_url, issuer=issuer)
    except ValueError as error:
        raise GuardSyncEndpointUntrustedError(f"{_guard_sync_reconnect_message()} {error}") from error


def _refreshed_oauth_payload(answer: dict[str, object]) -> dict[str, object]:
    """The token response of a native refresh, or the error its outcome names."""

    outcome = answer.get("outcome")
    reason = _optional_string(answer.get("reason")) or "Guard Cloud did not say why."
    if outcome == "refreshed":
        payload = answer.get("payload")
        if not isinstance(payload, dict):
            raise GuardSyncAuthorizationExpiredError(_guard_oauth_reauthorization_message())
        return payload
    if outcome == "rate_limited":
        # The header as sent keeps an HTTP date and a long wait; the runner's
        # rate-limit circuit applies its own bound.
        header = answer.get("retryAfter")
        if isinstance(header, str) and header.strip():
            raise _GuardOAuthRefreshRateLimitedError(parse_retry_after_value(header.strip()))
        retry_after = answer.get("retryAfterSeconds")
        seconds = 60
        if isinstance(retry_after, int | float) and not isinstance(retry_after, bool):
            seconds = max(1, math.ceil(retry_after))
        raise _GuardOAuthRefreshRateLimitedError(seconds)
    if outcome == "dead_grant":
        raise GuardSyncAuthorizationExpiredError(_guard_oauth_reconnect_after_revoked_message())
    if outcome == "rejected":
        raise _GuardOAuthRefreshRejectedError(f"{_guard_oauth_reauthorization_message()} {reason}")
    if outcome == "unusable":
        raise GuardSyncAuthorizationExpiredError(f"{_guard_oauth_reauthorization_message()} {reason}")
    if outcome == "unreachable":
        raise GuardSyncNotAvailableError(_GUARD_CLOUD_UNREACHABLE_MESSAGE, retryable=True)
    raise RuntimeError(f"Guard OAuth token refresh failed: {reason}")


def _refresh_guard_oauth_access_token_once(
    *,
    token_endpoint: str,
    client_id: str,
    refresh_token: str,
    dpop_key_material: GuardDpopKeyMaterial,
) -> dict[str, object]:
    if _guard_runtime_was_upgraded():
        raise GuardSyncNotAvailableError(_guard_runtime_upgrade_restart_message(), retryable=True)
    from . import cloud_bundle_sync

    try:
        answer = cloud_bundle_sync.cloud_oauth_refresh(
            {
                "tokenEndpoint": token_endpoint,
                "clientId": client_id,
                "refreshToken": refresh_token,
                "dpopKey": {
                    "privateKeyPem": dpop_key_material.private_key_pem,
                    "publicJwk": dict(dpop_key_material.public_jwk),
                    "algorithm": dpop_key_material.algorithm,
                },
            }
        )
    except (GuardSyncNotConfiguredError, GuardSyncNotAvailableError):
        raise
    except RuntimeError as error:
        # The native runtime was missing or did not answer: an outage the
        # caller retries, not a refusal of this grant.
        raise GuardSyncNotAvailableError(str(error), retryable=True) from error
    payload = _refreshed_oauth_payload(answer)
    access_token = _optional_string(payload.get("access_token"))
    token_type = _optional_string(payload.get("token_type"))
    if access_token is None or token_type is None or token_type.lower() not in {"bearer", "dpop"}:
        raise GuardSyncAuthorizationExpiredError(_guard_oauth_reauthorization_message())
    try:
        access_token_expires_at = oauth_access_token_expires_at(
            access_token,
            expires_in=payload.get("expires_in"),
            now=datetime.now(timezone.utc),
        )
    except (NativeRunnerAuthorityError, OSError):
        # The refreshed token still works; without an expiry it is only
        # refreshed again before reuse instead of being served from cache.
        access_token_expires_at = None
    return {
        "access_token": access_token,
        "access_token_expires_at": access_token_expires_at,
        "package_firewall_entitlement": build_oauth_package_firewall_entitlement(
            payload,
            now=datetime.now(timezone.utc),
        ),
        "cloud_user_profile": extract_cloud_user_profile(payload),
        "had_guard_local_entitlement": isinstance(payload.get("guard_local_entitlement"), dict),
        "refresh_token": _optional_string(payload.get("refresh_token")) or refresh_token,
    }


def _oauth_sync_url_from_issuer(issuer: str) -> str:
    oauth_client = resolve_guard_oauth_client_config(issuer)
    return f"{oauth_client.issuer}/api/guard/receipts/sync"


def _oauth_dpop_key_material(credentials: dict[str, object]) -> GuardDpopKeyMaterial:
    dpop_private_key_pem = _optional_string(credentials.get("dpop_private_key_pem"))
    dpop_public_jwk = credentials.get("dpop_public_jwk")
    dpop_public_jwk_thumbprint = _optional_string(credentials.get("dpop_public_jwk_thumbprint"))
    if dpop_private_key_pem is None or not isinstance(dpop_public_jwk, dict) or dpop_public_jwk_thumbprint is None:
        raise GuardSyncAuthorizationExpiredError(_guard_oauth_reauthorization_message())
    return GuardDpopKeyMaterial(
        algorithm="ES256",
        private_key_pem=dpop_private_key_pem,
        public_jwk={str(key): str(value) for key, value in dpop_public_jwk.items()},
        public_jwk_thumbprint=dpop_public_jwk_thumbprint,
    )


_OAUTH_ACCESS_TOKEN_REFRESH_SKEW_SECONDS = 60
_OAUTH_INVALID_GRANT_MAX_ATTEMPTS = 2
_OAUTH_INVALID_GRANT_RETRY_DELAY_SECONDS = 0.75


class _GuardOAuthRefreshRateLimitedError(RuntimeError):
    """Token endpoint rate-limited the refresh; carries the Retry-After hint."""

    def __init__(self, retry_after_seconds: int) -> None:
        self.retry_after_seconds = retry_after_seconds
        super().__init__(f"Guard OAuth token refresh was rate limited. Retry after {retry_after_seconds} seconds.")


class _GuardOAuthRefreshRejectedError(GuardSyncAuthorizationExpiredError):
    """The token endpoint rejected the refresh request with an error other than invalid_grant."""


_OAUTH_REFRESH_CIRCUIT_FAILURE_REVOKED = "revoked"
_OAUTH_REFRESH_CIRCUIT_FAILURE_REJECTED = "rejected"


def _oauth_refresh_circuit(store: GuardStore, call: Mapping[str, object]) -> dict[str, object]:
    """Run one call against the native refresh circuit."""
    from .cloud_bundle_sync import cloud_oauth_refresh_circuit

    return cloud_oauth_refresh_circuit(Path(store.guard_home), call)


def _oauth_refresh_circuit_check(*, store: GuardStore, refresh_token: str) -> None:
    """Fast-fail refresh while a known-dead or rate-limited grant is in backoff.

    Stops every sync/poll caller from hammering the token endpoint once the
    grant proved invalid. The native circuit clears itself when the stored
    refresh token no longer matches the one that failed (a peer process
    re-paired), and lets one probe through each time the backoff elapses.
    A circuit that cannot be read fails closed with a retryable error.
    """
    try:
        answer = _oauth_refresh_circuit(store, {"op": "check", "refreshToken": refresh_token})
    except RuntimeError as error:
        # Keep the native reason: an older runtime says to run `hol-guard update`.
        raise GuardSyncNotAvailableError(
            str(error) or "Guard could not read its sign-in refresh state. Try again shortly.",
            retryable=True,
        ) from error
    state = answer.get("state")
    if state == "open":
        return
    if state == "parked":
        if answer.get("failureKind") == _OAUTH_REFRESH_CIRCUIT_FAILURE_REJECTED:
            raise GuardSyncAuthorizationExpiredError(_guard_oauth_reauthorization_message())
        raise GuardSyncAuthorizationExpiredError(_guard_oauth_reconnect_after_revoked_message())
    wait = answer.get("retryAfterSeconds")
    if state == "rate_limited" and isinstance(wait, int) and not isinstance(wait, bool):
        raise _GuardOAuthRefreshRateLimitedError(max(1, wait))
    raise GuardSyncNotAvailableError(
        "Guard could not read its sign-in refresh state. Try again shortly.",
        retryable=True,
    )


def _oauth_refresh_circuit_record_dead_grant(
    *,
    store: GuardStore,
    refresh_token: str,
    issuer: str,
    failure_kind: str = _OAUTH_REFRESH_CIRCUIT_FAILURE_REVOKED,
) -> None:
    """Mark the grant permanently invalid and schedule the next probe.

    A propagated failure already consumed the bounded invalid_grant retry, so
    one record flips the binding into needs-reauthorization and fires the
    single user-visible notice; later failures only extend the probe backoff.
    Other rejections (for example invalid_request) record the `rejected` kind
    so the fast-fail keeps their reauthorization error instead of the revoked
    one, which would let sign-in cleanup wipe credentials after one bad 400.
    A rejection sends the notice only once the next probe is rejected too.
    The caller's own error propagates even when the circuit cannot record.
    """
    try:
        answer = _oauth_refresh_circuit(
            store,
            {"op": "record_dead_grant", "refreshToken": refresh_token, "failureKind": failure_kind},
        )
    except RuntimeError:
        return
    fingerprint = _optional_string(answer.get("fingerprint"))
    if fingerprint is None or answer.get("noticeDue") is not True:
        return
    if not _notify_oauth_reauthorization_required(issuer=issuer, fingerprint=fingerprint):
        return
    with suppress(RuntimeError):
        _oauth_refresh_circuit(store, {"op": "notice_sent", "fingerprint": fingerprint})


def _oauth_refresh_circuit_record_rate_limit(
    *,
    store: GuardStore,
    refresh_token: str,
    retry_after_seconds: int,
) -> None:
    """Park refresh attempts until the server-provided Retry-After elapses."""
    with suppress(RuntimeError):
        _oauth_refresh_circuit(
            store,
            {
                "op": "record_rate_limit",
                "refreshToken": refresh_token,
                "retryAfterSeconds": int(retry_after_seconds),
            },
        )


def _oauth_refresh_circuit_clear(store: GuardStore) -> None:
    with suppress(RuntimeError):
        _oauth_refresh_circuit(store, {"op": "clear"})


def _notify_oauth_reauthorization_required(*, issuer: str, fingerprint: str) -> bool:
    """Send the single user-visible reconnect notice via the existing path."""
    from ..desktop_notifications import (
        DesktopApprovalNotification,
        notify_pending_approval_once,
    )

    return notify_pending_approval_once(
        DesktopApprovalNotification(
            request_id=f"oauth-reauth-{fingerprint}",
            title="HOL Guard lost its connection to hol.org",
            message="Run `hol-guard connect` to sign in again.",
            approval_url=f"{issuer.rstrip('/')}/guard",
        )
    )


def _refresh_guard_oauth_access_token(
    *,
    token_endpoint: str,
    client_id: str,
    refresh_token: str,
    dpop_key_material: GuardDpopKeyMaterial,
    credential_reloader: Callable[[], tuple[str, GuardDpopKeyMaterial] | None] | None = None,
) -> dict[str, object]:
    """Refresh with bounded invalid_grant tolerance.

    A single invalid_grant can be an edge 4xx or a rotation race resolved
    server-side without grant revocation; failing once must not declare the
    local sign-in invalid (which used to trigger credential wipes and stop
    sync). Retry exactly once after a short delay. Before the retry, ask the
    caller for the latest stored credentials — a peer process may have
    rotated the refresh token between attempts. A second invalid_grant is
    treated as genuine revocation and propagates.

    The returned payload includes `_effective_refresh_token` and
    `_effective_dpop_key_material` reflecting whichever credential snapshot
    actually succeeded — so callers can persist and return *those*, not the
    stale inputs.
    """
    last_error: GuardSyncAuthorizationExpiredError | None = None
    attempt_refresh_token = refresh_token
    attempt_dpop_key_material = dpop_key_material
    for attempt in range(_OAUTH_INVALID_GRANT_MAX_ATTEMPTS):
        try:
            result = _refresh_guard_oauth_access_token_once(
                token_endpoint=token_endpoint,
                client_id=client_id,
                refresh_token=attempt_refresh_token,
                dpop_key_material=attempt_dpop_key_material,
            )
        except GuardSyncAuthorizationExpiredError as error:
            if str(error) != _guard_oauth_reconnect_after_revoked_message():
                raise
            last_error = error
            if attempt + 1 >= _OAUTH_INVALID_GRANT_MAX_ATTEMPTS:
                break
            time.sleep(_OAUTH_INVALID_GRANT_RETRY_DELAY_SECONDS)
            if credential_reloader is None:
                continue
            reloaded = credential_reloader()
            if reloaded is None:
                continue
            attempt_refresh_token, attempt_dpop_key_material = reloaded
            continue
        result["_effective_refresh_token"] = attempt_refresh_token
        result["_effective_dpop_key_material"] = attempt_dpop_key_material
        return result
    if last_error is None:  # pragma: no cover - unreachable when MAX_ATTEMPTS >= 1
        raise GuardSyncAuthorizationExpiredError(_guard_oauth_reconnect_after_revoked_message())
    raise last_error


def _persist_recovered_oauth_binding(store: GuardStore, credentials: dict[str, object]) -> bool:
    recovered = oauth_binding_from_credentials(credentials)
    if not recovered or all(_optional_string(credentials.get(key)) is not None for key in recovered):
        return False
    refresh_token = _optional_string(credentials.get("refresh_token"))
    if refresh_token is None:
        return False
    _persist_rotated_oauth_refresh_token(
        store=store,
        credentials={
            **credentials,
            **{key: _optional_string(credentials.get(key)) or value for key, value in recovered.items()},
        },
        refresh_token=refresh_token,
        access_token=_optional_string(credentials.get("access_token")),
        access_token_expires_at=_optional_string(credentials.get("access_token_expires_at")),
    )
    return True


def _cached_oauth_access_token(credentials: dict[str, object], *, now: datetime) -> str | None:
    access_token = _optional_string(credentials.get("access_token"))
    access_token_expires_at = _optional_string(credentials.get("access_token_expires_at"))
    if access_token is None or access_token_expires_at is None:
        return None
    try:
        expires_at = datetime.fromisoformat(access_token_expires_at)
    except ValueError:
        return None
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    expires_at = expires_at.astimezone(timezone.utc)
    if expires_at <= now + timedelta(seconds=_OAUTH_ACCESS_TOKEN_REFRESH_SKEW_SECONDS):
        return None
    return access_token


def _persist_rotated_oauth_refresh_token(
    *,
    store: GuardStore,
    credentials: dict[str, object],
    package_firewall_entitlement: dict[str, object] | None = None,
    cloud_user_profile: dict[str, str] | None = None,
    refresh_token: str,
    access_token: str | None = None,
    access_token_expires_at: str | None = None,
    force_primary_secret_rewrite: bool = False,
) -> None:
    issuer = _optional_string(credentials.get("issuer"))
    client_id = _optional_string(credentials.get("client_id"))
    dpop_private_key_pem = _optional_string(credentials.get("dpop_private_key_pem"))
    dpop_public_jwk = credentials.get("dpop_public_jwk")
    dpop_public_jwk_thumbprint = _optional_string(credentials.get("dpop_public_jwk_thumbprint"))
    if (
        issuer is None
        or client_id is None
        or dpop_private_key_pem is None
        or not isinstance(dpop_public_jwk, dict)
        or dpop_public_jwk_thumbprint is None
    ):
        raise GuardSyncAuthorizationExpiredError(_guard_oauth_reauthorization_message())
    supply_chain_firewall: bool | None
    if isinstance(package_firewall_entitlement, dict) and isinstance(
        package_firewall_entitlement.get("supply_chain_firewall"), bool
    ):
        supply_chain_firewall = bool(package_firewall_entitlement.get("supply_chain_firewall"))
    else:
        credentials_supply_chain_firewall = credentials.get("supply_chain_firewall")
        supply_chain_firewall = (
            credentials_supply_chain_firewall if isinstance(credentials_supply_chain_firewall, bool) else None
        )
    effective_access_token = access_token or _optional_string(credentials.get("access_token"))
    effective_binding = oauth_effective_binding(credentials, access_token=access_token, issuer=issuer)
    store.set_oauth_local_credentials(
        issuer=issuer,
        client_id=client_id,
        refresh_token=refresh_token,
        dpop_private_key_pem=dpop_private_key_pem,
        dpop_public_jwk={str(key): str(value) for key, value in dpop_public_jwk.items()},
        dpop_public_jwk_thumbprint=dpop_public_jwk_thumbprint,
        grant_id=effective_binding["grant_id"],
        machine_id=effective_binding["machine_id"],
        device_id=effective_binding["device_id"],
        supply_chain_entitlement_expires_at=(
            _optional_string(package_firewall_entitlement.get("supply_chain_entitlement_expires_at"))
            if isinstance(package_firewall_entitlement, dict)
            else _optional_string(credentials.get("supply_chain_entitlement_expires_at"))
        ),
        supply_chain_firewall=supply_chain_firewall,
        supply_chain_plan_id=(
            _optional_string(package_firewall_entitlement.get("supply_chain_plan_id"))
            if isinstance(package_firewall_entitlement, dict)
            else _optional_string(credentials.get("supply_chain_plan_id"))
        ),
        workspace_id=effective_binding["workspace_id"],
        cloud_user_profile=cloud_user_profile,
        runtime_id=_optional_string(credentials.get("runtime_id")),
        runtime_label=_optional_string(credentials.get("runtime_label")),
        access_token=effective_access_token,
        access_token_expires_at=access_token_expires_at,
        now=_now(),
        force_primary_secret_rewrite=force_primary_secret_rewrite,
    )


def _resolve_guard_sync_auth_context_from_oauth_credentials(
    store: GuardStore,
    oauth_credentials: dict[str, object],
    *,
    persist_recovered_secret: bool = False,
    force_refresh: bool = False,
) -> dict[str, object]:
    issuer = _optional_string(oauth_credentials.get("issuer"))
    client_id = _optional_string(oauth_credentials.get("client_id"))
    refresh_token = _optional_string(oauth_credentials.get("refresh_token"))
    if issuer is None or client_id is None or refresh_token is None:
        raise GuardSyncAuthorizationExpiredError(_guard_oauth_reauthorization_message())
    dpop_key_material = _oauth_dpop_key_material(oauth_credentials)
    try:
        oauth_client = resolve_guard_oauth_client_config(issuer)
    except ValueError as error:
        raise GuardSyncEndpointUntrustedError(f"{_guard_sync_reconnect_message()} {error}") from error
    cached_access_token = (
        None if force_refresh else _cached_oauth_access_token(oauth_credentials, now=datetime.now(timezone.utc))
    )
    if cached_access_token is not None and not persist_recovered_secret:
        sync_url = _validate_guard_sync_url(
            _oauth_sync_url_from_issuer(oauth_client.issuer),
            issuer=oauth_client.issuer,
        )
        return {
            "sync_url": sync_url,
            "access_token": cached_access_token,
            "dpop_key_material": dpop_key_material,
        }

    effective_credentials_ref: dict[str, dict[str, object]] = {"value": oauth_credentials}

    def _reload_current_oauth_credentials() -> tuple[str, GuardDpopKeyMaterial] | None:
        reloaded_credentials = store.get_oauth_local_credentials(allow_primary=True)
        if not isinstance(reloaded_credentials, dict):
            return None
        reloaded_refresh_token = _optional_string(reloaded_credentials.get("refresh_token"))
        if reloaded_refresh_token is None:
            return None
        effective_credentials_ref["value"] = reloaded_credentials
        return reloaded_refresh_token, _oauth_dpop_key_material(reloaded_credentials)

    _oauth_refresh_circuit_check(store=store, refresh_token=refresh_token)
    try:
        refreshed = _refresh_guard_oauth_access_token(
            token_endpoint=oauth_client.token_endpoint,
            client_id=client_id,
            refresh_token=refresh_token,
            dpop_key_material=dpop_key_material,
            credential_reloader=_reload_current_oauth_credentials,
        )
    except _GuardOAuthRefreshRateLimitedError as error:
        failed_refresh_token = (
            _optional_string(effective_credentials_ref["value"].get("refresh_token")) or refresh_token
        )
        _oauth_refresh_circuit_record_rate_limit(
            store=store,
            refresh_token=failed_refresh_token,
            retry_after_seconds=error.retry_after_seconds,
        )
        raise
    except GuardSyncAuthorizationExpiredError as error:
        if str(error) == _guard_oauth_reconnect_after_revoked_message():
            failure_kind = _OAUTH_REFRESH_CIRCUIT_FAILURE_REVOKED
        elif isinstance(error, _GuardOAuthRefreshRejectedError):
            failure_kind = _OAUTH_REFRESH_CIRCUIT_FAILURE_REJECTED
        else:
            raise
        failed_refresh_token = (
            _optional_string(effective_credentials_ref["value"].get("refresh_token")) or refresh_token
        )
        _oauth_refresh_circuit_record_dead_grant(
            store=store,
            refresh_token=failed_refresh_token,
            issuer=issuer,
            failure_kind=failure_kind,
        )
        raise
    _oauth_refresh_circuit_clear(store)
    effective_credentials = effective_credentials_ref["value"]
    effective_dpop_key_material = _apply_refreshed_oauth_credentials(
        store=store,
        effective_credentials=effective_credentials,
        refreshed=refreshed,
        refresh_token=refresh_token,
        dpop_key_material=dpop_key_material,
        persist_recovered_secret=persist_recovered_secret,
        force_refresh=force_refresh,
    )
    sync_url = _validate_guard_sync_url(
        _oauth_sync_url_from_issuer(oauth_client.issuer),
        issuer=oauth_client.issuer,
    )
    return {
        "sync_url": sync_url,
        "access_token": str(refreshed["access_token"]),
        "dpop_key_material": effective_dpop_key_material,
    }


def _apply_refreshed_oauth_credentials(
    *,
    store: GuardStore,
    effective_credentials: dict[str, object],
    refreshed: dict[str, object],
    refresh_token: str,
    dpop_key_material: GuardDpopKeyMaterial,
    persist_recovered_secret: bool,
    force_refresh: bool,
) -> GuardDpopKeyMaterial:
    """Project the refresh result onto the credential store and return context.

    Removes the wrapper's internal `_effective_*` markers from `refreshed`,
    persists the rotated credentials when state actually changed (using the
    effective snapshot — the one the retry leg may have reloaded), and
    returns the effective DPoP key material for the caller to sign with.
    """
    refreshed.pop("_effective_refresh_token", None)
    effective_dpop_key_material_raw = refreshed.pop("_effective_dpop_key_material", None)
    effective_dpop_key_material = (
        effective_dpop_key_material_raw
        if isinstance(effective_dpop_key_material_raw, GuardDpopKeyMaterial)
        else dpop_key_material
    )
    rotated_refresh_token = str(refreshed["refresh_token"])
    refreshed_entitlement = refreshed.get("package_firewall_entitlement")
    package_firewall_entitlement: dict[str, object] | None = (
        refreshed_entitlement if isinstance(refreshed_entitlement, dict) else None
    )
    refreshed_cloud_user_profile = refreshed.get("cloud_user_profile")
    if not isinstance(refreshed_cloud_user_profile, dict):
        refreshed_cloud_user_profile = None
    had_entitlement = bool(refreshed.get("had_guard_local_entitlement"))
    # When the refresh response includes a guard_local_entitlement but no
    # user_profile, clear the stale profile rather than preserving it.
    # When there's no guard_local_entitlement at all (old server), keep existing.
    # Sources: prefer the refresh response, then the effective (possibly
    # reloaded-by-peer) credentials dict; compare against the same effective
    # snapshot so a peer's newer profile is not treated as a change.
    effective_cloud_user_profile: dict[str, str] | None
    if had_entitlement:
        effective_cloud_user_profile = refreshed_cloud_user_profile
    else:
        effective_cloud_user_profile = refreshed_cloud_user_profile or _extract_dict_field(
            effective_credentials, "cloud_user_profile"
        )
    stored_cloud_user_profile = _extract_dict_field(effective_credentials, "cloud_user_profile")
    profile_changed = effective_cloud_user_profile != stored_cloud_user_profile
    if (
        force_refresh
        or rotated_refresh_token != refresh_token
        or package_firewall_entitlement is not None
        or profile_changed
        or persist_recovered_secret
    ):
        _persist_rotated_oauth_refresh_token(
            store=store,
            credentials=effective_credentials,
            package_firewall_entitlement=package_firewall_entitlement,
            cloud_user_profile=effective_cloud_user_profile,
            refresh_token=rotated_refresh_token,
            access_token=_optional_string(refreshed.get("access_token")),
            access_token_expires_at=_optional_string(refreshed.get("access_token_expires_at")),
            force_primary_secret_rewrite=force_refresh,
        )
    return effective_dpop_key_material


# Test-only override: when set, _resolve_guard_sync_auth_context returns this dict
# directly instead of resolving OAuth credentials (which would refresh tokens over
# the network). Tests seed OAuth credentials for status/connect-state checks and set
# this override to keep sync-path exercises hermetic.
_test_sync_auth_context_override: dict[str, object] | None = None


def _test_sync_auth_context_from_env() -> dict[str, object] | None:
    if not os.environ.get("PYTEST_CURRENT_TEST"):
        return None
    raw = os.environ.get("HOL_GUARD_TEST_SYNC_AUTH_CONTEXT_JSON")
    if raw is None:
        return None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    # Error form: `{"error": "authorization_expired"}` makes the resolver raise
    # `GuardSyncAuthorizationExpiredError`, mirroring a resident seam where the
    # same JSON is forwarded as `sync_auth_context_override` and surfaces as
    # `EvalError::Validation` → `cloud_auth_error` fail-closed.
    if payload.get("error") == "authorization_expired":
        raise GuardSyncAuthorizationExpiredError(
            "Guard authorization expired (test override). Run `hol-guard connect` to sign in again."
        )
    sync_url = payload.get("sync_url")
    access_token = payload.get("access_token")
    if not isinstance(sync_url, str) or not isinstance(access_token, str):
        return None
    sync_url = _validate_guard_sync_url(sync_url)
    return {
        "sync_url": sync_url,
        "access_token": access_token,
        "dpop_key_material": None,
    }


def _resolve_guard_sync_auth_context(
    store: GuardStore,
    *,
    allow_primary_repair: bool = True,
    force_refresh: bool = False,
) -> dict[str, object]:
    if _test_sync_auth_context_override is not None:
        override = dict(_test_sync_auth_context_override)
        override["sync_url"] = _validate_guard_sync_url(_auth_context_sync_url(override))
        return override
    env_override = _test_sync_auth_context_from_env()
    if env_override is not None:
        return env_override
    with _guard_sync_auth_lock(store):
        oauth_health = store.get_oauth_local_credential_health()
        oauth_credentials = store.get_oauth_local_credentials(allow_primary=allow_primary_repair)
        if oauth_credentials is not None:
            try:
                return _resolve_guard_sync_auth_context_from_oauth_credentials(
                    store,
                    oauth_credentials,
                    force_refresh=force_refresh,
                )
            except GuardSyncAuthorizationExpiredError as error:
                if not _oauth_authorization_error_requires_fresh_sign_in(error):
                    raise
                store._clear_oauth_secret_payload_cache()
                refreshed_credentials = store.get_oauth_local_credentials(allow_primary=allow_primary_repair)
                if refreshed_credentials is None or _optional_string(
                    refreshed_credentials.get("refresh_token")
                ) == _optional_string(oauth_credentials.get("refresh_token")):
                    raise
                return _resolve_guard_sync_auth_context_from_oauth_credentials(
                    store,
                    refreshed_credentials,
                    force_refresh=force_refresh,
                )
        if bool(oauth_health.get("configured")):
            recoverable_credentials = store.get_recoverable_oauth_local_credentials()
            if recoverable_credentials is not None:
                return _resolve_guard_sync_auth_context_from_oauth_credentials(
                    store,
                    recoverable_credentials,
                    persist_recovered_secret=allow_primary_repair,
                    force_refresh=force_refresh,
                )
            raise GuardSyncAuthorizationExpiredError(_guard_oauth_reauthorization_message())
        raise GuardSyncNotConfiguredError("Guard is not logged in.")


def _guard_sync_headers(
    auth_context: dict[str, object],
    *,
    request_url: str,
    method: str,
    extra_headers: dict[str, str] | None = None,
    dpop_nonce: str | None = None,
) -> dict[str, str]:
    access_token = str(auth_context["access_token"])
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": _GUARD_SYNC_USER_AGENT,
    }
    dpop_key_material = auth_context.get("dpop_key_material")
    if isinstance(dpop_key_material, GuardDpopKeyMaterial):
        dpop_header = _sign_guard_dpop_proof(
            request_url=request_url,
            method=method,
            dpop_key_material=dpop_key_material,
            access_token=access_token,
            nonce=dpop_nonce,
        )
        headers["DPoP"] = dpop_header
    if isinstance(extra_headers, dict):
        headers.update(extra_headers)
    return headers


# Bounds the body shipped to the resident well inside its request cap; Guard
# Cloud and Cloudflare error bodies are far smaller.
_CLOUD_HTTP_ERROR_BODY_CHARS = 512 * 1024
_CLOUD_HTTP_ERROR_HEADERS = ("cf-mitigated", "cf-ray", "server", "content-type")
# The statuses the runtime itself treats as retryable (`RETRYABLE_STATUSES`).
_CLOUD_HTTP_ERROR_RETRYABLE_STATUSES = frozenset({429, 503, 524})


def _cloud_http_error(error: urllib.error.HTTPError) -> _sync.CloudHttpError:
    """Read the error once and return how the resident reads it.

    The answer carries the sync message, the retryable flag, the 403
    plan-restriction verdict and Cloudflare's edge-block message, so a caller
    never drains the stream twice.
    """
    try:
        raw_body = error.read().decode("utf-8", errors="replace")
    except OSError:
        raw_body = ""
    headers = error.headers
    projected = (
        None
        if headers is None
        else {name: str(value) for name in _CLOUD_HTTP_ERROR_HEADERS if (value := headers.get(name)) is not None}
    )
    try:
        return _sync.cloud_http_error(
            status=error.code,
            reason=str(error.reason),
            headers=projected,
            body=raw_body[:_CLOUD_HTTP_ERROR_BODY_CHARS],
        )
    except NativeRunnerAuthorityError:
        # The HTTP error still has to reach the user when the runtime cannot
        # answer, without a verdict the runtime never gave: the status alone
        # decides a retry, and the status line stands in as the edge block so
        # an unread 401 is reported as it came rather than as an expired sign-in.
        status_line = f"HTTP Error {error.code}: {error.reason}"
        retryable = error.code in _CLOUD_HTTP_ERROR_RETRYABLE_STATUSES
        return _sync.CloudHttpError(status_line, retryable, status_line, False, status_line, status_line)


def _cloud_edge_block_from_http_error(error: urllib.error.HTTPError) -> str | None:
    """The edge-block message, if Cloudflare answered instead of Guard Cloud."""
    return _cloud_http_error(error).edge_block


def _sync_http_error_message(error: urllib.error.HTTPError) -> str:
    return _cloud_http_error(error).sync_message


def _redact_sync_text(value: str) -> str:
    return redact_sensitive_text(value)


def _check_plan_restriction_403(
    error: urllib.error.HTTPError,
) -> tuple[bool, str]:
    """Read a 403 response body exactly once; return (is_plan_restriction, error_message)."""
    answer = _cloud_http_error(error)
    return answer.plan_restricted, answer.plan_message


def _sync_url_error_message(error: OSError) -> str:
    reason = getattr(error, "reason", error)
    if reason is not None:
        reason_text = str(reason).strip()
        if reason_text:
            return f"Guard sync failed: {reason_text}"
    return "Guard sync failed because the remote endpoint could not be reached."


_UNREACHABLE_NETWORK_ERRNOS = frozenset({errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ENETDOWN})
_MANAGED_PROXY_REQUEST_FAILED = "managed_proxy_request_failed"
_GUARD_CLOUD_UNREACHABLE_MESSAGE = "Guard Cloud could not be reached. Local Guard keeps protecting this machine."


def _is_guard_cloud_unreachable_error(error: OSError) -> bool:
    """Return whether a sync request failed because Guard Cloud was offline, not misconfigured.

    Refused or reset connections, unreachable hosts or networks, DNS failures and
    timeouts clear up on their own, so the caller can offer a retry, including
    when they happen behind a managed proxy. TLS verification failures are not
    included.
    """
    if _is_network_outage_error(error):
        return True
    if getattr(error, "reason", None) != _MANAGED_PROXY_REQUEST_FAILED:
        return False
    # A managed proxy keeps the transport failure only in the urllib3 error it
    # wraps, which nests it under reason, original_error or either chain link.
    pending: list[BaseException] = [error]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if current is not error and isinstance(current, OSError) and _is_network_outage_error(current):
            return True
        for attribute in ("reason", "original_error", "__cause__", "__context__"):
            nested = getattr(current, attribute, None)
            if isinstance(nested, BaseException):
                pending.append(nested)
    return False


def _is_network_outage_error(error: OSError) -> bool:
    if _is_timeout_error(error):
        return True
    reason = getattr(error, "reason", error)
    if isinstance(reason, ConnectionError | socket.gaierror):
        return True
    return isinstance(reason, OSError) and reason.errno in _UNREACHABLE_NETWORK_ERRNOS


def _is_timeout_error(error: OSError) -> bool:
    if isinstance(error, TimeoutError | socket.timeout):
        return True
    reason = getattr(error, "reason", error)
    if isinstance(reason, TimeoutError | socket.timeout):
        return True
    reason_text = str(reason).strip().lower()
    if not reason_text:
        return False
    return reason_text == "timed out" or reason_text.endswith(" timed out") or "timed out" in reason_text


def _optional_string(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return None


def _extract_dict_field(credentials: dict[str, object], key: str) -> dict[str, str] | None:
    value = credentials.get(key)
    if not isinstance(value, dict):
        return None
    return {str(k): str(v) for k, v in value.items()}


def _int_value(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def _string_items(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _auth_context_sync_url(auth_context: dict[str, object]) -> str:
    sync_url = _optional_string(auth_context.get("sync_url"))
    if sync_url is None:
        raise RuntimeError("Guard sync URL is unavailable.")
    return sync_url


def _normalized_timestamp_string(value: object) -> str | None:
    raw_value = _optional_string(value)
    if raw_value is None:
        return None
    parsed = _parse_iso_timestamp(raw_value)
    if parsed is None:
        return None
    return parsed.isoformat()


def _stored_policy_bundle_acknowledgement(store: GuardStore) -> object:
    """A failed acknowledgement describes a dropped bundle; never carry it onto a new one."""

    stored = store.get_sync_payload("policy_bundle_ack")
    return None if is_failed_policy_bundle_acknowledgement(stored) else stored


def _clear_policy_bundle_authority_reporting_failure(
    store: GuardStore,
    now: str,
    *,
    policy_bundle_last_error: dict[str, object],
    managed_controls_publish: Callable[[ExtensionControlAuthorityView, Callable[[], None]], object] | None,
    device_id: str,
    device_name: str,
    policy_bundle: object,
    reason: str | None,
) -> None:
    """Clear remote authority and leave a ``failed`` acknowledgement for Cloud."""

    store.clear_policy_bundle_authority(
        now,
        policy_bundle_last_error=policy_bundle_last_error,
        managed_controls_publish=managed_controls_publish,
        policy_bundle_ack=lambda stored: failed_acknowledgement(
            stored,
            policy_bundle=policy_bundle,
            reason=reason,
            device_id=device_id,
            device_name=device_name,
            synced_at=now,
        ),
    )


def _validated_policy_bundle_acknowledgement(
    store: GuardStore,
    *,
    device_id: str,
    device_name: str,
) -> dict[str, object] | None:
    acknowledgement = store.get_sync_payload("policy_bundle_ack")
    if not isinstance(acknowledgement, dict):
        return None
    # A cached bundle that no longer validates is reported as failed, never as
    # the applied state Guard stopped enforcing.
    failure = cached_bundle_failure_acknowledgement(
        store,
        acknowledgement=acknowledgement,
        device_id=device_id,
        device_name=device_name,
        validate=lambda guard_store, policy_bundle: cached_policy_bundle_validation(guard_store, policy_bundle),
    )
    if failure is not None:
        return failure or None
    if acknowledgement.get("contractVersion") == POLICY_BUNDLE_V2_CONTRACT:
        validated, _error = validated_policy_bundle_v2_acknowledgement(acknowledgement)
        return validated

    policy_bundle = validated_synced_policy_bundle(store)
    if policy_bundle is None:
        return None

    bundle_hash = non_empty_string(policy_bundle.get("bundleHash"))
    bundle_version = non_empty_string(policy_bundle.get("bundleVersion"))
    if bundle_hash is None or bundle_version is None:
        return None
    if acknowledgement.get("bundleHash") != bundle_hash:
        return None
    if acknowledgement.get("bundleVersion") != bundle_version:
        return None
    if acknowledgement.get("deviceId") != device_id:
        return None
    if acknowledgement.get("deviceName") != device_name:
        return None
    if acknowledgement.get("status") != "synced":
        return None
    if _normalized_timestamp_string(acknowledgement.get("appliedAt")) is None:
        return None
    return acknowledgement


def _sync_context_acknowledgement(sync_context: dict[str, object]) -> dict[str, object] | None:
    for key in ("policyBundleAcknowledgementV2", "policyBundleAcknowledgement"):
        value = sync_context.get(key)
        if isinstance(value, dict) and value:
            return value
    return None


def _sync_context_bundle_hash(sync_context: dict[str, object]) -> str | None:
    """Key the acknowledgement by bundle and outcome, so a failure is reported at once."""

    acknowledgement = _sync_context_acknowledgement(sync_context)
    bundle_hash = _optional_string(acknowledgement.get("bundleHash")) if acknowledgement is not None else None
    if bundle_hash is not None and acknowledgement is not None and acknowledgement.get("status") == "failed":
        return f"failed:{bundle_hash}"
    return bundle_hash


def _build_fleet_posture_for_sync(
    store: GuardStore,
    *,
    sync_context: dict[str, object],
    home_dir: Path | None,
    workspace_dir: Path | None,
) -> FleetPostureBuild | None:
    """Build the posture for one request. Never raises: posture is best-effort."""

    try:
        from ..config import load_guard_config
        from ..native_harness_ops import list_harnesses

        guard_home = store.guard_home
        try:
            guard_config = load_guard_config(guard_home, workspace_dir, create_home=False)
        except Exception:
            guard_config = None
        context = HarnessContext(
            home_dir=home_dir if home_dir is not None else Path.home(),
            workspace_dir=workspace_dir,
            guard_home=guard_home,
        )
        runtime = "python"
        return build_fleet_posture_state(
            store,
            list_harnesses(),
            FleetPostureSettings(context=context, guard_config=guard_config, runtime=runtime),
            acknowledgement=_sync_context_acknowledgement(sync_context),
        )
    except Exception:
        _LOGGER.debug("Fleet posture could not be built", exc_info=True)
        return None


def _send_policy_ack_followup(
    store: GuardStore,
    *,
    sync_context: dict[str, object],
    bundle_hash_sent: str | None,
    auth_context: dict[str, object],
    device_id: str,
    device_name: str,
    local_guard_online_at: str,
    home_dir: Path | None,
    workspace_dir: Path | None,
    now: str,
) -> None:
    """Report a bundle applied in this cycle without waiting for the next one.

    The context built at the start of a cycle carries the previous cycle's
    acknowledgement, so Guard Cloud would learn about a new bundle one full
    interval late. When the stored acknowledgement now names a bundle the request
    did not carry, refresh the in-memory context and send one empty-receipt
    follow-up. The attempt is recorded per bundle hash before sending, so a
    failure or a rejection never turns into a loop.
    """

    try:
        fresh = _receipt_sync_context(
            store,
            local_guard_online_at=local_guard_online_at,
            device_id=device_id,
            device_name=device_name,
        )
        fresh_ack = _sync_context_acknowledgement(fresh)
        fresh_hash = _sync_context_bundle_hash(fresh)
        if fresh_ack is None or fresh_hash is None:
            return
        for key in ("policyBundleAcknowledgementV2", "policyBundleAcknowledgement"):
            sync_context.pop(key, None)
        sync_context.update(
            {key: value for key, value in fresh.items() if key.startswith("policyBundleAcknowledgement")}
        )
        if fresh_hash == bundle_hash_sent:
            return
        attempted = store.get_sync_payload(_FLEET_POSTURE_FOLLOWUP_KEY)
        if isinstance(attempted, dict) and attempted.get("bundleHash") == fresh_hash:
            return
        store.set_sync_payload(_FLEET_POSTURE_FOLLOWUP_KEY, {"bundleHash": fresh_hash, "attemptedAt": now}, now)
        built = _build_fleet_posture_for_sync(
            store,
            sync_context=sync_context,
            home_dir=home_dir,
            workspace_dir=workspace_dir,
        )
        from .cloud_bundle_sync import cloud_receipt_upload

        # One request with no receipts; the native upload sends the posture on
        # it and records its delivery.
        cloud_receipt_upload(
            Path(store.guard_home),
            {
                "contextOnly": True,
                "redactionLevel": "full",
                "deviceId": device_id,
                "deviceName": device_name,
                "now": now,
                "syncContext": sync_context,
                "fleetPosture": None
                if built is None
                else {
                    "payload": built.payload,
                    "nextState": built.next_state,
                    "advancedInventory": built.advanced_inventory,
                },
                "workspaceAssessments": None,
                "allowAuthRefresh": False,
            },
            auth_context=auth_context,
        )
    except Exception:
        _LOGGER.debug("Policy acknowledgement follow-up sync failed", exc_info=True)


def _receipt_sync_context(
    store: GuardStore,
    *,
    local_guard_online_at: str,
    device_id: str | None = None,
    device_name: str | None = None,
) -> dict[str, object]:
    resolved_device_id = device_id
    resolved_device_name = device_name
    if resolved_device_id is None or resolved_device_name is None:
        resolved_device_id, resolved_device_name = _guard_device_metadata(store)
    runtime_summary = store.get_sync_payload("runtime_session_summary")
    runtime_synced_at = (
        _optional_string(runtime_summary.get("runtime_session_synced_at"))
        if isinstance(runtime_summary, dict)
        else None
    )
    runtime_harness = (
        _optional_string(runtime_summary.get("runtime_harness")) if isinstance(runtime_summary, dict) else None
    )
    sync_health = "healthy" if runtime_synced_at is not None else "degraded"
    policy_bundle_ack = _validated_policy_bundle_acknowledgement(
        store,
        device_id=resolved_device_id,
        device_name=resolved_device_name,
    )
    context: dict[str, object] = {
        "deviceId": resolved_device_id,
        "deviceName": resolved_device_name,
        "harness": runtime_harness or "hol-guard",
        "localGuardOnlineAt": local_guard_online_at,
        "syncHealth": sync_health,
    }
    if isinstance(policy_bundle_ack, dict) and policy_bundle_ack:
        acknowledgement_key = (
            "policyBundleAcknowledgementV2"
            if policy_bundle_ack.get("contractVersion") == POLICY_BUNDLE_V2_CONTRACT
            else "policyBundleAcknowledgement"
        )
        context[acknowledgement_key] = policy_bundle_ack
    if runtime_synced_at is not None:
        context["lastRuntimeSyncAt"] = runtime_synced_at
    return context


_RELAXED_RECEIPT_REDACTION_RESYNC_MARKER = "cloud_receipt_redaction_relaxed_resync_v1"
_CLOUD_REVIEW_PRIVACY_PROJECTION_MARKER = "cloud_review_privacy_projection_v2"
_RECEIPT_COMMAND_DETAIL_BACKFILL_MARKER = "cloud_receipt_command_detail_backfill_v2"


def _persist_cloud_receipt_redaction_level(store: GuardStore, *, level: str, synced_at: str) -> None:
    store.receipt_redaction_bookkeeping(
        "persist",
        now=synced_at,
        level=level,
        local_level=local_receipt_redaction_level(store.guard_home),
    )


def _reset_cloud_receipt_redaction_authority(store: GuardStore, *, synced_at: str) -> None:
    """Reset relaxation bookkeeping when no signed override is effective."""

    store.receipt_redaction_bookkeeping(
        "reset",
        now=synced_at,
        local_level=local_receipt_redaction_level(store.guard_home),
    )


def _ensure_cloud_review_privacy_projection(store: GuardStore, *, level: str, synced_at: str) -> None:
    store.receipt_redaction_bookkeeping("ensure_projection", now=synced_at, level=level)


def _requeue_cloud_review_privacy_projection(store: GuardStore, *, level: str, changed_at: str) -> int:
    return store.receipt_redaction_bookkeeping("requeue_projection", now=changed_at, level=level) or 0


def _ensure_relaxed_receipt_redaction_resync(store: GuardStore, *, level: str, synced_at: str) -> None:
    store.receipt_redaction_bookkeeping("ensure_resync", now=synced_at, level=level)


def _resolve_cloud_receipt_redaction_level(store: GuardStore) -> str:
    """Resolve the receipt redaction level for cloud sync.

    A cloud relaxation is authoritative only while its signed policy bundle
    remains valid. The separately persisted level is cursor bookkeeping, not
    an authority source, because it can outlive or be detached from a bundle.
    """
    policy_bundle = validated_synced_policy_bundle(store)
    if policy_bundle is not None:
        level = policy_bundle.get("receiptRedactionLevel")
        if isinstance(level, str) and level in VALID_RECEIPT_REDACTION_LEVELS:
            return level
    return local_receipt_redaction_level(store.guard_home)


def _cloud_runtime_session_payload(store: GuardStore, session: dict[str, object]) -> dict[str, object]:
    device_id, device_name = _guard_device_metadata(store)
    # The working directory only stands in for a missing workspace; a process
    # whose directory was removed still syncs a session that names its own.
    workspace = session.get("workspace")
    payload = _sync.runtime_session_payload(
        session,
        device_id=device_id,
        device_name=device_name,
        cwd=workspace if isinstance(workspace, str) and workspace.strip() else os.getcwd(),
        now=_now(),
        version=__version__,
    )
    updated_at = str(payload["updatedAt"])
    payload["localIdentity"], payload["localIdentitySource"] = _cloud_local_identity(observed_at=updated_at)
    payload["packageManagerCoverage"] = _cloud_package_manager_coverage(
        store,
        workspace=str(payload["workspace"]),
        generated_at=updated_at,
    )
    payload.update(_managed_controls_runtime_sync_posture(store, generated_at=updated_at))
    return payload


def _sync_extension_catalog_from_runtime_handshake(
    *,
    store: GuardStore | None = None,
    guard_home: Path | None = None,
    auth_context: dict[str, object],
    runtime_sync_url: str,
    runtime_response: dict[str, object],
    session_payload: dict[str, object],
) -> dict[str, object]:
    """Upload the canonical catalog only after a digest-bound Cloud request."""

    from .cloud_bundle_sync import cloud_json_request
    from .extension_catalog_pages import observed_view
    from .extension_catalog_sync import ExtensionCatalogUnavailableError, build_v1_catalog_from_view
    from .extension_catalog_transfer import catalog_sync_plan, sync_catalog_view

    signal = runtime_response.get("extensionCatalogSync")
    if isinstance(signal, dict) and "protocolVersion" in signal:
        sent = False

        def send_page(url: str, body: bytes) -> object:
            nonlocal sent
            sent = True
            try:
                return cloud_json_request(
                    auth_context,
                    url=url,
                    body=body,
                    timeout_seconds=_RUNTIME_SYNC_TIMEOUT_SECONDS,
                    retry_timeout_seconds=_RUNTIME_SYNC_RETRY_TIMEOUT_SECONDS,
                )
            except urllib.error.HTTPError as error:
                raise RuntimeError(_sync_http_error_message(error)) from error
            except OSError as error:
                raise RuntimeError(_sync_url_error_message(error)) from error

        try:
            # A concurrent publish can drop the view this session named at any
            # point up to the first page: the lookup, the pin the transfer
            # takes, and the plan it builds all read the shared cache. None of
            # those has told Cloud anything, so the session keeps going and the
            # next sync names a current view. What decides that is whether a
            # page actually went out, not which call raised: once a transfer
            # may have reached Cloud, a later failure must not be reported as
            # an absent catalog.
            view = observed_view(session_payload, guard_home)
            result = sync_catalog_view(
                runtime_sync_url=runtime_sync_url,
                runtime_response=runtime_response,
                session_payload=session_payload,
                view=view,
                send=send_page,
            )
            if store is None:
                raise RuntimeError("Authenticated catalog completion requires the current store")
            from .extension_catalog_completion import complete_authenticated_view

            result.update(
                complete_authenticated_view(
                    store=store,
                    view=view,
                    auth_context=auth_context,
                    url=catalog_sync_plan(
                        view=view,
                        runtime_sync_url=runtime_sync_url,
                        runtime_response=runtime_response,
                        session_payload=session_payload,
                    )["upload_url"],
                    send=send_page,
                )
            )
        except ExtensionCatalogUnavailableError:
            if sent:
                raise
            return catalog_runtime_unavailable_summary()
        return result

    summary, upload = prepare_extension_catalog_handshake(
        guard_home=guard_home,
        runtime_sync_url=runtime_sync_url,
        runtime_response=runtime_response,
        session_payload=session_payload,
        catalog_factory=lambda generated_at: (
            build_v1_catalog_from_view(observed_view(session_payload, guard_home))
            if "extensionCatalogViewDigest" in session_payload
            else build_builtin_extension_catalog_wire(
                guard_version=__version__, generated_at=generated_at, guard_home=guard_home
            )
        ),
        fallback_generated_at=_now(),
    )
    if upload is None:
        return summary
    try:
        response = cloud_json_request(
            auth_context,
            url=upload.url,
            body=upload.body,
            timeout_seconds=_RUNTIME_SYNC_TIMEOUT_SECONDS,
            retry_timeout_seconds=_RUNTIME_SYNC_RETRY_TIMEOUT_SECONDS,
        )
    except urllib.error.HTTPError as error:
        raise RuntimeError(_sync_http_error_message(error)) from error
    except OSError as error:
        raise RuntimeError(_sync_url_error_message(error)) from error
    digest = session_payload.get("extensionCatalogDigest")
    if not isinstance(digest, str):
        raise RuntimeError("Invalid Extension catalog handshake response")
    unverified = _validate_extension_catalog_sync_response(response, expected_digest=digest, guard_home=guard_home)
    return summary if unverified is None else unverified


def _cloud_local_identity(*, observed_at: str) -> tuple[dict[str, object], dict[str, str]]:
    """The host name and private address the session reports, and their source.

    The runtime reads both. Without an answer the session still syncs with
    only its sync time, which every field's absence already means.
    """
    try:
        return _authority.local_identity(observed_at)
    except NativeRunnerAuthorityError:
        return {"lastSyncedAt": observed_at}, {
            "daemonId": "local-guard",
            "daemonVersion": "local-guard",
            "daemonStatus": "local-guard",
            "relayState": "local-guard",
        }


def _cloud_package_manager_coverage(
    store: GuardStore,
    *,
    workspace: str,
    generated_at: str,
) -> dict[str, object]:
    coverage = package_shim_cloud_coverage(
        HarnessContext(
            home_dir=Path.home(),
            workspace_dir=Path(workspace),
            guard_home=store.guard_home,
        ),
        generated_at=generated_at,
    )
    coverage["staleIntel"] = _sync.stale_intel(
        (
            store.get_sync_payload("sync_summary"),
            store.get_sync_payload("runtime_session_summary"),
            store.get_sync_payload("supply_chain_bundle_summary"),
        ),
        generated_at=generated_at,
        now=_now(),
    )
    return coverage


def _guard_device_metadata(store: GuardStore) -> tuple[str, str]:
    metadata = store.get_device_metadata()
    return str(metadata["installation_id"]), device_display_name(store, str(metadata["device_label"]))


def _sync_timestamp(payload: dict[str, object]) -> str:
    synced_at = _optional_string(payload.get("syncedAt"))
    if synced_at is not None and _parse_iso_timestamp(synced_at) is not None:
        return synced_at
    return _now()


def _parse_iso_timestamp(value: str) -> datetime | None:
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
