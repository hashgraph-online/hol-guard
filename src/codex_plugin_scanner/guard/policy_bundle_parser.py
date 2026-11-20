"""Policy bundle schema validation and integrity hashing.

Rust owns v1 bundle schema validation, canonical hashing, signature
verification, downgrade ordering and the remediation text a rejection carries.
This module keeps the sync-time names and the transport calls; a native failure
is a typed rejection, never a Python verdict.
"""

from __future__ import annotations

from ..version import __version__
from .native_policy_bundle import (
    NATIVE_UNAVAILABLE_REJECTION,
    PolicyBundleNativeError,
    PolicyBundleNativeUnavailableError,
    native_policy_bundle,
    policy_bundle_chunks,
)
from .policy_bundle_v2 import POLICY_BUNDLE_V2_CONTRACT

CANONICAL_COMPILE_REJECTION_PREFIX = "canonical_compile_"

# The resident cannot write the record of its own outage, so that one sentence
# stays here for the record stored when it does not answer.
_NATIVE_UNAVAILABLE_MESSAGE = (
    "The policy bundle was not applied because the Guard native runtime could not be reached. "
    "Check that Guard is healthy, then sync again."
)


def _non_empty_string(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _flag(kind: str, request: dict[str, object], *, otherwise: bool) -> bool:
    """Return one Rust boolean verdict.

    ``otherwise`` is the fail-closed answer when Rust rejects the request as
    malformed or answers with an error verdict. An outage of the resident is not
    a verdict: ``PolicyBundleNativeUnavailableError`` propagates so callers report it
    as unavailable rather than as an inactive, unsupported or downgraded bundle.
    """

    try:
        result = native_policy_bundle(kind, request)
    except PolicyBundleNativeUnavailableError:
        raise
    except ValueError:
        return otherwise
    if isinstance(result.get("error"), str):
        return otherwise
    return result.get("value") is True


# What the admission and downgrade gates read from a candidate and from the
# accepted reference. Only these fields cross the transport.
_CANDIDATE_KEYS = (
    "contractVersion",
    "rolloutState",
    "minDaemonVersion",
    "bundleVersion",
    "bundleHash",
    "payloadHash",
    "issuedAt",
    "workspaceId",
    "rollback",
    "cloudExceptions",
    "cloudExceptionsIssuedAt",
)
_REFERENCE_KEYS = (
    "bundleVersion",
    "bundleHash",
    "payloadHash",
    "issuedAt",
    "workspaceId",
    "cloudExceptionsIssuedAt",
    "cloudExceptionsHash",
)
_EXPECTED_KEYS = ("bundleVersion", "bundleHash")


def _view_chunks(bundle: object, keys: tuple[str, ...]) -> list[str] | None:
    if not isinstance(bundle, dict):
        return None
    return policy_bundle_chunks({key: bundle[key] for key in keys if key in bundle})


def _reference_chunks(reference: object, candidate: dict[str, object]) -> list[str] | None:
    """The reference fields the gates compare, with its exception set as a hash.

    Only the hash of the accepted Cloud exception set is compared, so the set
    itself never shares a request with the candidate. Two bundles near the size
    limit would otherwise exceed the transport cap together.
    """

    if not isinstance(reference, dict):
        return None
    view = {key: reference[key] for key in _REFERENCE_KEYS if key in reference}
    if (
        candidate.get("contractVersion") == POLICY_BUNDLE_V2_CONTRACT
        and not isinstance(view.get("cloudExceptionsHash"), str)
        and "cloudExceptions" in reference
    ):
        view["cloudExceptionsHash"] = _required_exceptions_hash(reference)
    return policy_bundle_chunks(view)


def _required_exceptions_hash(reference: dict[str, object]) -> str:
    """Hash the accepted exception set in its own request, or report an outage.

    Without this hash the same-time replay check cannot run, so an answer
    without a string hash fails closed instead of crossing as ``null``.
    """

    result = native_policy_bundle(
        "v2_cloud_exceptions_hash",
        {"bundle_chunks": policy_bundle_chunks({"cloudExceptions": reference["cloudExceptions"]})},
    )
    value = result.get("value")
    if isinstance(value, str) and value and "error" not in result:
        return value
    raise PolicyBundleNativeUnavailableError(NATIVE_UNAVAILABLE_REJECTION, result)


def policy_bundle_admission_rejection(
    candidate: dict[str, object],
    reference: dict[str, object] | None,
) -> str | None:
    """The first reason a validated candidate may not become live authority.

    Rust runs the daemon-version, rollout-state and downgrade gates in that
    order and answers ``None`` when the candidate passes all three. A native
    failure raises ``PolicyBundleNativeError`` (``PolicyBundleNativeUnavailableError``
    for an outage); it is never read as a pass.
    """

    result = native_policy_bundle(
        "candidate_admission",
        {
            "bundle_chunks": _view_chunks(candidate, _CANDIDATE_KEYS),
            "reference_chunks": _reference_chunks(reference, candidate),
            "daemon_version": __version__,
        },
    )
    error = result.get("error")
    if isinstance(error, str):
        raise PolicyBundleNativeError(error, result)
    # An answer without an explicit verdict is an outage, never a pass.
    if "rejection" not in result or "error" in result:
        raise PolicyBundleNativeUnavailableError(NATIVE_UNAVAILABLE_REJECTION, result)
    rejection = result["rejection"]
    if rejection is None or (isinstance(rejection, str) and rejection):
        return rejection
    raise PolicyBundleNativeUnavailableError(NATIVE_UNAVAILABLE_REJECTION, result)


def policy_bundle_downgrade_verdict(
    reference: dict[str, object] | None,
    candidate: dict[str, object],
    *,
    expected_last_good: dict[str, object] | None = None,
) -> bool:
    """Whether ``candidate`` replays or rolls back the accepted ``reference``.

    Rust applies the v2 transition rules to a v2 candidate and the v1 ordering
    rules otherwise. A malformed request fails closed as a downgrade; an outage
    raises ``PolicyBundleNativeUnavailableError``.
    """

    try:
        request: dict[str, object] = {
            "bundle_chunks": _view_chunks(candidate, _CANDIDATE_KEYS),
            "reference_chunks": _reference_chunks(reference, candidate),
            "expected_chunks": _view_chunks(expected_last_good, _EXPECTED_KEYS),
        }
        result = native_policy_bundle("downgrade_verdict", request)
    except PolicyBundleNativeUnavailableError:
        raise
    except ValueError:
        return True
    error = result.get("error")
    if isinstance(error, str):
        return True
    value = result.get("value")
    if "error" not in result and isinstance(value, bool):
        return value
    # A reply without a boolean verdict is an outage, never "no downgrade".
    raise PolicyBundleNativeUnavailableError(NATIVE_UNAVAILABLE_REJECTION, result)


def policy_bundle_is_enforceable(policy_bundle: dict[str, object]) -> bool:
    """Return whether an authenticated rollout is intended as live authority."""

    slim = {key: policy_bundle[key] for key in ("contractVersion", "rolloutState") if key in policy_bundle}
    return _flag("is_enforceable", {"bundle": slim}, otherwise=False)


def policy_bundle_acceptance_checkpoint(policy_bundle: dict[str, object]) -> dict[str, object]:
    """Return the signed identity fields needed for monotonic replay defense."""

    checkpoint = {
        "bundleHash": policy_bundle.get("bundleHash"),
        "bundleVersion": policy_bundle.get("bundleVersion"),
        "issuedAt": policy_bundle.get("issuedAt"),
        "payloadHash": policy_bundle.get("payloadHash"),
        "workspaceId": policy_bundle.get("workspaceId"),
        "cloudExceptionsIssuedAt": policy_bundle.get("cloudExceptionsIssuedAt"),
        "cloudExceptionsHash": policy_bundle_cloud_exceptions_hash(policy_bundle),
    }
    return {key: value for key, value in checkpoint.items() if value is not None}


def policy_bundle_cloud_exceptions_hash(policy_bundle: dict[str, object]) -> str | None:
    """Return the identity of the bundle's signed Cloud exception set, if any.

    A checkpoint keeps it beside the issue time, so a different set signed at
    the same instant is a replay rather than the set the device accepted.
    """

    stored = policy_bundle.get("cloudExceptionsHash")
    if isinstance(stored, str):
        return stored
    if "cloudExceptions" not in policy_bundle:
        return None
    result = native_policy_bundle(
        "v2_cloud_exceptions_hash",
        {"bundle_chunks": policy_bundle_chunks({"cloudExceptions": policy_bundle["cloudExceptions"]})},
    )
    value = result.get("value")
    return value if isinstance(value, str) else None


_ORDERING_KEYS = ("bundleVersion", "bundleHash", "payloadHash", "issuedAt", "workspaceId")


def _ordering_view(bundle: object) -> object:
    if not isinstance(bundle, dict):
        return bundle
    return {key: bundle[key] for key in _ORDERING_KEYS if key in bundle}


def policy_bundle_is_version_downgrade(
    accepted_bundle: dict[str, object] | None,
    candidate_bundle: dict[str, object],
) -> bool:
    """Reject older or unordered signed payloads relative to accepted authority."""

    try:
        accepted_chunks = None if accepted_bundle is None else policy_bundle_chunks(_ordering_view(accepted_bundle))
        request: dict[str, object] = {
            "accepted_chunks": accepted_chunks,
            "bundle_chunks": policy_bundle_chunks(_ordering_view(candidate_bundle)),
        }
    except ValueError:
        return True
    return _flag("is_downgrade", request, otherwise=True)


def policy_bundle_rejection_payload(reason: str | None, rule_id: str | None = None) -> dict[str, object]:
    """Return the stored record of why a bundle was not applied.

    Rust writes the record: the reason, the sentence telling an administrator
    what to do, and the rule that refused to compile. Without the resident the
    record keeps the reason alone. The outage record is written here without
    asking, since that reason means the resident just failed to answer.
    """

    resolved = reason or "invalid_policy_bundle"
    if resolved == NATIVE_UNAVAILABLE_REJECTION:
        # The resident just failed to answer; asking it again would wait out a second timeout.
        return {"reason": resolved, "message": _NATIVE_UNAVAILABLE_MESSAGE}
    try:
        record = native_policy_bundle("rejection_payload", {"reason": reason, "rule_id": rule_id})
    except PolicyBundleNativeError:
        record = {}
    if (
        isinstance(record.get("reason"), str)
        and isinstance(record.get("message", ""), str)
        and isinstance(record.get("ruleId", ""), str)
    ):
        return dict(record)
    return {"reason": resolved}


def policy_bundle_rejection_message(reason: str | None) -> str | None:
    """Return the remediation sentence stored with ``reason``, if any."""

    if reason is None:
        return None
    message = policy_bundle_rejection_payload(reason).get("message")
    return message if isinstance(message, str) else None


non_empty_string = _non_empty_string
