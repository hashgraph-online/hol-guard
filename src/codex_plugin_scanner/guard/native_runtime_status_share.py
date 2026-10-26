"""Hand an already verified runtime status to the rest of one hook request.

The daemon decides a hook against the runtime status bound to its acknowledged
policy snapshot, and the native edge runs that status's binary without hashing
it again. A review that needs approval then asks ``native_runtime_status`` once
more, which re-hashes the whole binary and can push the review past its hook
deadline on Windows, where hashes are never cached across requests. Sharing the
verified status with the request scope skips that second hash. Every reuse still
rechecks the binary's size, mtime and bundled manifest, and nothing outlives the
request.
"""

from __future__ import annotations

from . import native_runtime as _runtime
from .native_runtime_request_scope import _resolved_candidate_path, remember_scoped_status, scoped_status
from .native_runtime_values import NativeRuntimeStatus


def share_verified_runtime_status(status: NativeRuntimeStatus) -> None:
    """Seed the active request scope with ``status`` when it is still the runtime to use."""

    identity = status.identity
    if identity is None or not status.available or not status.compatible or status.mode != _runtime.native_mode():
        return
    candidates = _runtime._runtime_candidates()
    # Validation takes the first usable candidate, so only the first candidate's
    # status may stand in for it. When the publisher fell back to a later one, the
    # request validates again in case the preferred runtime is usable by now.
    if not candidates or identity.path != _resolved_candidate_path(candidates[0]):
        return
    key = _runtime._status_request_key(candidates)
    if scoped_status(key) is None:
        remember_scoped_status(key, status)
