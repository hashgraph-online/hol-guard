"""Dependency-free runtime-hook scheduler value types."""

from typing import Literal

RuntimeHookLane = Literal["decision", "content-security", "evidence"]
RuntimeHookAdmissionReason = Literal[
    "daemon_hook_deadline_exhausted",
    "daemon_hook_queue_capacity",
    "daemon_hook_queue_bytes",
]

__all__ = ["RuntimeHookAdmissionReason", "RuntimeHookLane"]
