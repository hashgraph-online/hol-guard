"""Public carriers delegated to the existing native shell kernels."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import cast, get_args

from ...models import GuardAction
from ...native_runner_authority import NativeRunnerAuthorityError
from ...native_shell_request_authority import shell_request_authority

_GUARD_ACTIONS = frozenset(get_args(GuardAction))
# The names ``GitHubCapability::as_str`` emits. A name outside this set means
# the resident and this carrier disagree, so the answer is rejected.
_CAPABILITY_NAMES = frozenset(
    {
        "read_local",
        "read_remote",
        "propose_remote",
        "create_private_remote",
        "routine_merge_remote",
        "routine_review_thread_remote",
        "routine_workflow_remote",
        "write_local",
        "maintain_remote",
        "content_remote",
        "merge_remote",
        "admin_merge_remote",
        "publish_remote",
        "workflow_remote",
        "force_remote",
        "delete_remote",
        "secret_remote",
        "access_remote",
        "mutate_remote",
        "unknown",
    }
)


@dataclass(frozen=True, slots=True)
class GitHubShellAssessment:
    """The resident's GitHub capability classification for one shell command.

    The floor and workflow eligibility come from the Rust capability contract
    (``guard-command/src/github_capability_contract.rs``); nothing here derives
    them again.
    """

    capability: str
    capabilities: tuple[str, ...]
    reason_code: str
    detail: str
    action_floor: GuardAction
    workflow_authorizable: bool


def classify_github_shell_capabilities(command_text: str, *, home_dir: Path | None) -> GitHubShellAssessment | None:
    value: object = shell_request_authority("classify_github_shell_capabilities", locals())
    if value is None:
        return None
    if not isinstance(value, dict):
        raise NativeRunnerAuthorityError("native_github_shell_capabilities_invalid")
    answer = cast(dict[str, object], value)
    capability = answer.get("capability")
    capabilities = answer.get("capabilities")
    reason_code = answer.get("reason_code")
    detail = answer.get("detail")
    action_floor = answer.get("action_floor")
    workflow_authorizable = answer.get("workflow_authorizable")
    if not isinstance(capabilities, list):
        raise NativeRunnerAuthorityError("native_github_shell_capabilities_invalid")
    classified = tuple(cast(list[object], capabilities))
    if (
        not isinstance(capability, str)
        or not all(isinstance(item, str) and item in _CAPABILITY_NAMES for item in classified)
        or capability not in classified
        or not isinstance(reason_code, str)
        or not isinstance(detail, str)
        or not isinstance(action_floor, str)
        or action_floor not in _GUARD_ACTIONS
        or not isinstance(workflow_authorizable, bool)
    ):
        raise NativeRunnerAuthorityError("native_github_shell_capabilities_invalid")
    return GitHubShellAssessment(
        capability,
        cast(tuple[str, ...], classified),
        reason_code,
        detail,
        cast(GuardAction, action_floor),
        workflow_authorizable,
    )


__all__ = ["GitHubShellAssessment", "classify_github_shell_capabilities"]
