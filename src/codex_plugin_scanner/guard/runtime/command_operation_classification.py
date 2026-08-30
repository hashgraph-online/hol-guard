"""Local side-effect authority classes for Guard Cloud commands."""

READ_ONLY_COMMAND_OPERATIONS: tuple[str, ...] = (
    "guard.packageShims.status",
    "guard.packageShims.test",
    "guard.packageShims.audit",
    "guard.app.status",
    "guard.app.updateCheck",
)
LOCAL_CONFIRMATION_COMMAND_OPERATIONS: frozenset[str] = frozenset(
    {
        "guard.packageShims.remove",
        "guard.app.remove",
    }
)
STATE_CHANGING_COMMAND_OPERATIONS: frozenset[str] = frozenset(
    {
        "guard.packageShims.repair",
        "guard.packageShims.sync",
        "guard.packageShims.install",
        "guard.app.repair",
        "guard.app.connect",
        "guard.app.update",
        "guard.review.syncPolicyMemory",
    }
)
POLICY_MEMORY_COMMAND_OPERATIONS: frozenset[str] = frozenset({"guard.review.syncPolicyMemory"})
REMOTE_STEP_UP_COMMAND_OPERATIONS: frozenset[str] = frozenset()
