"""Read a contained run's request and word its refusals.

The sink re-exports these, so callers keep importing them from
``contained_test_hook``.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from ..desktop_core_currency import OUT_OF_SYNC_REASON, superseded_desktop_core
from .contained_authority import authority_unavailable
from .restricted_pytest import RestrictedPytestError

_FAILURE = "contained_run_authorization_failed"


def _reject(response: object = None) -> RestrictedPytestError:
    # Only an unavailable *rejected receipt* may change the error wording.
    # Shape validation and unrelated later rejections must not inherit state
    # from a previous native authority call in this process.
    if authority_unavailable(response) and isinstance(response, Mapping):
        superseded = superseded_desktop_core()
        if superseded is not None:
            return RestrictedPytestError(OUT_OF_SYNC_REASON, superseded.message())
        reason = response.get("reason_code")
        return RestrictedPytestError(
            _FAILURE,
            f"Guard's native policy runtime did not answer ({reason}), so this command was not run. "
            "Try it again; if it keeps failing, run `hol-guard repair`.",
        )
    return RestrictedPytestError(_FAILURE, "Guard could not authorize this contained run.")


def _names_pytest(command: list[str] | None) -> bool:
    """Whether native authority reads `command` as a pytest run.

    Only the wording of a refusal turns on this, and the planners' own reading
    is what chose that wording, so the question goes back to them rather than to
    a second copy of their grammar here. The copy that stood here read `python
    -Im pytest -q` as something other than pytest, because it looked for `-m` as
    a whole word while the planners read the `m` inside the cluster.

    A command the planners never reached, or an answer native authority cannot
    give, reports the authorization that failed, exactly as an unrecognized
    command does.
    """
    if not command:
        return False
    from ..native_restricted_pytest import restricted_native

    try:
        return restricted_native("pytest_command", {"command": command}, bool) is True
    except RestrictedPytestError:
        return False


def read_contained_test_request(path: Path, expected_sha256: str, *, workspace: Path) -> dict[str, object]:
    """Read one bounded private adapter snapshot, without following its leaf.

    Native authority reads it where and as the hook wrote it, at the digest
    the rewritten command pins; any other answer refuses the run.
    """
    from ..native_restricted_pytest import restricted_native

    try:
        return restricted_native(
            "contained_test_request",
            {"path": path, "sha256": expected_sha256, "workspace": workspace},
            dict,
        )
    except RestrictedPytestError as error:
        if error.reason_code != _FAILURE and (superseded := superseded_desktop_core()) is not None:
            raise RestrictedPytestError(OUT_OF_SYNC_REASON, superseded.message()) from error
        raise _reject() from error


def _contained_receipt(receipt: object) -> bool:
    return (
        isinstance(receipt, Mapping)
        and receipt.get("decision") == "deny"
        and receipt.get("policy_action") == "sandbox-required"
        and isinstance(receipt.get("required_execution_profile"), str)
        and receipt.get("observe_mode") is not True
    )
