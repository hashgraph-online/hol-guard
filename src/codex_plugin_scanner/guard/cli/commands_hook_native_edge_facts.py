"""Hand the typed native edge verdict to the native artifact composition."""

from collections.abc import Mapping


def _native_edge_facts(
    native_edge_result: Mapping[str, object] | None,
    event_name: str | None,
    *,
    artifact_type: str | None = None,
) -> dict[str, object] | None:
    """Project the native edge result onto the policy stack's edge facts.

    The resident derives the floor from these facts; Python only forwards them.
    """

    if not isinstance(native_edge_result, Mapping):
        return None
    return {
        "event_name": event_name,
        "policy_action": native_edge_result.get("policy_action"),
        "minimum_action": native_edge_result.get("minimum_action"),
        "decision": native_edge_result.get("decision"),
        "reason_code": native_edge_result.get("reason_code"),
        "package_request": artifact_type == "package_request",
    }
