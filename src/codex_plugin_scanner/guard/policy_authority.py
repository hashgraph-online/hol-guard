"""Authority checks for remembered local rules and Cloud policy rows."""

from __future__ import annotations

from .models import PolicyDecision
from .policy_integrity import is_remote_policy_source


class PolicyAuthorityError(ValueError):
    """Raised when a policy row would cross its allowed authority boundary."""


def validate_policy_write_authority(
    decision: PolicyDecision,
    *,
    remote_write_authorized: bool = False,
) -> None:
    """Reject local writes that would impersonate stronger authority."""

    if is_remote_policy_source(decision.source):
        if remote_write_authorized:
            return
        raise PolicyAuthorityError("remote_policy_source_requires_validated_sync_path")
