"""Dependencies re-exported by the stable runner namespace."""

from __future__ import annotations

import base64
import hashlib
import importlib.metadata
import io
import json
import os
import re
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from base64 import urlsafe_b64encode
from collections.abc import Callable, Iterable, Mapping, Sequence
from contextlib import contextmanager, suppress
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from ...version import __version__
from ..action_lattice import is_guard_action, most_restrictive_guard_action
from ..adapters.base import HarnessAdapter, HarnessContext
from ..approval_gate import ApprovalGateError
from ..cli.oauth_client import (
    GuardDpopKeyMaterial,
    resolve_guard_oauth_client_config,
    validate_guard_sync_endpoint,
)
from ..cloud_exceptions import (
    build_cloud_exceptions_from_policy_bundle,
    cloud_exception_to_dict,
    dedupe_cloud_exceptions,
)
from ..config import VALID_RECEIPT_REDACTION_LEVELS, GuardConfig
from ..edge_events import build_runtime_session_event
from ..managed_controls_policy_fields import ParsedManagedControlsPolicy
from ..mdm.network import managed_urlopen
from ..models import GuardAction, GuardArtifact, HarnessDetection, PolicyDecision
from ..oauth_token_claims import decode_oauth_access_token_claims as _decode_oauth_access_token_claims
from ..oauth_token_claims import oauth_binding_from_credentials, oauth_binding_metadata, oauth_refresh_binding
from ..package_firewall_defaults import extract_cloud_user_profile
from ..package_firewall_entitlement import (
    build_oauth_package_firewall_entitlement,
    reconcile_connect_state_with_oauth_entitlement,
)
from ..policy_bundle_activation import activate_with_reason, persist_activation_rejection
from ..policy_bundle_decisions import build_policy_bundle_decisions as _materialize_policy_bundle_decisions
from ..policy_bundle_delivery import (
    effective_policy_bundle_acknowledgement,
)
from ..policy_bundle_parser import (
    POLICY_BUNDLE_RULE_MATCHER_FAMILIES,
    computed_policy_bundle_hash,
    non_empty_string,
    policy_bundle_acceptance_checkpoint,
    policy_bundle_is_enforceable,
    policy_bundle_is_version_downgrade,
    policy_bundle_rejection_message,
)
from ..policy_bundle_parser import (
    policy_bundle_daemon_version_supported as _daemon_version_supported,
)
from ..policy_bundle_trusted_keys import (
    MANAGED_POLICY_BUNDLE_KEYRING_PROVENANCE_STATE_KEY,
    PolicyBundleVerificationKey,
    policy_bundle_keyring_payload,
    validate_synced_policy_bundle,
)
from ..policy_bundle_v2 import (
    POLICY_BUNDLE_V2_CONTRACT,
    validate_policy_bundle_v2_transition,
    validated_policy_bundle_v2_acknowledgement,
)
from ..policy_document import GuardPolicyDocument
from ..policy_document_io import PolicyCompilationError, compile_policy_document
from ..redaction import redact_sensitive_text
from ..review_contracts import validated_review_verification_keys_from_sync
from ..shims import package_shim_cloud_coverage
from ..store import GuardStore
from ..synced_policy import cached_policy_bundle_validation, validated_synced_policy_bundle
from ..types import PromptRequest, RemediationAction
from .actions import GuardActionEnvelope, redacted_workspace_label
from .approval_context import (
    build_runtime_launch_identity,
    parse_approval_context_token,
    resolved_runtime_launch_argv,
    runtime_launch_identity_is_reusable,
)
from .approval_reuse import (
    APPROVAL_REUSE_CLAIM_FAILED,
    APPROVAL_REUSE_LAUNCH_IDENTITY_UNVERIFIED,
)
from .composition_rules import compose_action_from_signals
from .decisions import (
    AUTHORITATIVE_DECISION_INCONSISTENT,
    build_authoritative_decision,
    evaluation_authority_error,
    rebuild_artifact_authority,
)
from .detectors import DetectorContext, DetectorRegistry, DetectorRunResult, register_default_detectors
from .extension_catalog_handshake import (
    prepare_extension_catalog_handshake,
    runtime_session_success_summary,
    runtime_summary_device_id,
)
from .extension_catalog_handshake import (
    validate_extension_catalog_sync_response as _validate_extension_catalog_sync_response,
)
from .extension_catalog_sync import build_builtin_extension_catalog_wire
from .extension_control_authority import ExtensionControlAuthorityView
from .local_runtime_fallbacks import best_effort_access_token, local_receipt_redaction_level
from .managed_controls_sync import (
    apply_custom_extension_continuity_from_sync,
    effective_managed_controls_for_activation,
    validated_managed_controls_candidate,
)
from .managed_controls_sync import (
    managed_controls_lkg_capabilities as _managed_controls_lkg_capabilities,
)
from .managed_controls_sync import (
    managed_controls_negotiated_capabilities as _managed_controls_negotiated_capabilities,
)
from .managed_controls_sync import (
    managed_controls_runtime_sync_posture as _managed_controls_runtime_sync_posture,
)
from .prompt_injection import detect_prompt_injection_requests
from .signals import RiskSignalV2
from .supply_chain_bundle import (
    SupplyChainBundleError,
    load_supply_chain_bundle_response,
    load_supply_chain_verification_keys,
    verify_supply_chain_bundle_response,
)
from .supply_chain_bundle_models import SupplyChainVerificationKey
from .supply_chain_support import ecosystem_support_matrix

__all__ = [
    "APPROVAL_REUSE_CLAIM_FAILED",
    "APPROVAL_REUSE_LAUNCH_IDENTITY_UNVERIFIED",
    "AUTHORITATIVE_DECISION_INCONSISTENT",
    "MANAGED_POLICY_BUNDLE_KEYRING_PROVENANCE_STATE_KEY",
    "POLICY_BUNDLE_RULE_MATCHER_FAMILIES",
    "POLICY_BUNDLE_V2_CONTRACT",
    "VALID_RECEIPT_REDACTION_LEVELS",
    "Any",
    "ApprovalGateError",
    "Callable",
    "DetectorContext",
    "DetectorRegistry",
    "DetectorRunResult",
    "ExtensionControlAuthorityView",
    "GuardAction",
    "GuardActionEnvelope",
    "GuardArtifact",
    "GuardConfig",
    "GuardDpopKeyMaterial",
    "GuardPolicyDocument",
    "GuardStore",
    "HarnessAdapter",
    "HarnessContext",
    "HarnessDetection",
    "Iterable",
    "Mapping",
    "ParsedManagedControlsPolicy",
    "Path",
    "PolicyBundleVerificationKey",
    "PolicyCompilationError",
    "PolicyDecision",
    "PromptRequest",
    "RemediationAction",
    "RiskSignalV2",
    "Sequence",
    "SupplyChainBundleError",
    "SupplyChainVerificationKey",
    "__version__",
    "_daemon_version_supported",
    "_decode_oauth_access_token_claims",
    "_managed_controls_lkg_capabilities",
    "_managed_controls_negotiated_capabilities",
    "_managed_controls_runtime_sync_posture",
    "_materialize_policy_bundle_decisions",
    "_validate_extension_catalog_sync_response",
    "activate_with_reason",
    "apply_custom_extension_continuity_from_sync",
    "base64",
    "best_effort_access_token",
    "build_authoritative_decision",
    "build_builtin_extension_catalog_wire",
    "build_cloud_exceptions_from_policy_bundle",
    "build_oauth_package_firewall_entitlement",
    "build_runtime_launch_identity",
    "build_runtime_session_event",
    "cached_policy_bundle_validation",
    "cast",
    "cloud_exception_to_dict",
    "compile_policy_document",
    "compose_action_from_signals",
    "computed_policy_bundle_hash",
    "contextmanager",
    "dataclass",
    "datetime",
    "decode_dss_signature",
    "dedupe_cloud_exceptions",
    "detect_prompt_injection_requests",
    "ec",
    "ecosystem_support_matrix",
    "effective_managed_controls_for_activation",
    "effective_policy_bundle_acknowledgement",
    "evaluation_authority_error",
    "extract_cloud_user_profile",
    "hashes",
    "hashlib",
    "importlib",
    "io",
    "is_guard_action",
    "json",
    "load_supply_chain_bundle_response",
    "load_supply_chain_verification_keys",
    "local_receipt_redaction_level",
    "managed_urlopen",
    "most_restrictive_guard_action",
    "non_empty_string",
    "oauth_binding_from_credentials",
    "oauth_binding_metadata",
    "oauth_refresh_binding",
    "os",
    "package_shim_cloud_coverage",
    "parse_approval_context_token",
    "persist_activation_rejection",
    "policy_bundle_acceptance_checkpoint",
    "policy_bundle_is_enforceable",
    "policy_bundle_is_version_downgrade",
    "policy_bundle_keyring_payload",
    "policy_bundle_rejection_message",
    "prepare_extension_catalog_handshake",
    "re",
    "rebuild_artifact_authority",
    "reconcile_connect_state_with_oauth_entitlement",
    "redact_sensitive_text",
    "redacted_workspace_label",
    "register_default_detectors",
    "replace",
    "resolve_guard_oauth_client_config",
    "resolved_runtime_launch_argv",
    "runtime_launch_identity_is_reusable",
    "runtime_session_success_summary",
    "runtime_summary_device_id",
    "serialization",
    "socket",
    "subprocess",
    "suppress",
    "threading",
    "time",
    "timedelta",
    "timezone",
    "urllib",
    "urlsafe_b64encode",
    "uuid4",
    "validate_guard_sync_endpoint",
    "validate_policy_bundle_v2_transition",
    "validate_synced_policy_bundle",
    "validated_managed_controls_candidate",
    "validated_policy_bundle_v2_acknowledgement",
    "validated_review_verification_keys_from_sync",
    "validated_synced_policy_bundle",
    "verify_supply_chain_bundle_response",
]
