"""Check an explicit install workspace with the hook's native path owner."""

from __future__ import annotations

from ..adapters.base import HarnessContext
from ..native_directory_trust import NativeDirectoryTrustError, native_directory_trust


def require_supported_codex_workspace(context: HarnessContext) -> None:
    """Do not publish hooks whose workspace the daemon will discard."""
    if not context.workspace_override_explicit or context.workspace_dir is None:
        return
    try:
        verdicts = native_directory_trust(
            [("workspace", str(context.workspace_dir))],
            guard_home=context.guard_home,
            home_dir=context.home_dir,
        )
    except NativeDirectoryTrustError as error:
        raise ValueError(
            "Codex installation stopped before changing its configuration: "
            f"the native runtime could not validate --workspace ({error.code}). "
            "Repair the native runtime, then retry the install."
        ) from error
    if len(verdicts) != 1 or not verdicts[0].trusted:
        reason = verdicts[0].reason if len(verdicts) == 1 else "invalid_result"
        raise ValueError(
            "Codex installation stopped before changing its configuration: "
            f"--workspace is outside the supported hook directories ({reason}). "
            "Use a workspace within this installation's supported hook directories. "
            "The selected workspace is not supported by this installation's path policy."
        )
