"""Project typed native enforcement onto the artifact composition boundary."""

from collections.abc import Mapping

from ..action_lattice import coerce_guard_action
from ..models import GuardAction


def _native_edge_floor_action(
    native_edge_result: Mapping[str, object] | None,
    event_name: str,
    *,
    artifact_default_action: object | None = None,
    artifact_type: str | None = None,
) -> GuardAction | None:
    """Project the typed native edge result onto the composition floor."""

    if not isinstance(native_edge_result, Mapping):
        return None
    action = coerce_guard_action(native_edge_result.get("policy_action") or native_edge_result.get("minimum_action"))
    if (
        event_name == "PreToolUse"
        and artifact_type == "package_request"
        and native_edge_result.get("reason_code") == "native_command_extension_evaluation_failed"
    ):
        # Package requests have their own fail-closed evaluator. A generic
        # command-control failure is not a second package verdict.
        return None
    if event_name == "PreToolUse" and action in {"block", "sandbox-required"}:
        # A typed terminal native edge cannot become browser-overridable review
        # when the compatibility command floor lacks the same source context.
        return action
    if event_name != "PostToolUse":
        # Other floors come from native command review and artifact classes;
        # the edge result remains provenance rather than a second floor.
        return None
    if action is None and native_edge_result.get("decision") == "deny":
        action = "block"
    if action not in {"block", "sandbox-required"}:
        return action
    if artifact_default_action == "warn":
        # The edge still masks output already priced as warn-tier evidence.
        return None
    # The action has finished: retain output masking and reviewability.
    return "require-reapproval"
