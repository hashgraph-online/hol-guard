"""Frozen previous Pi managed extension source."""

from __future__ import annotations

import os
from pathlib import Path

from ..codex_hook_windows_job import windows_system_executable_path
from ..daemon.manager import GUARD_DAEMON_COMPATIBILITY_VERSION
from .pi_extension_previous_source_body import build_previous_source_body
from .pi_extension_previous_source_header import build_previous_source_header
from .pi_extension_previous_source_tail import build_previous_source_tail
from .pi_extension_runtime_ownership import resolve_pi_extension_runtime_ownership
from .pi_extension_source_runtime import (
    ExtensionSourceVariantV1,
    build_lifecycle_abort_event_source_v1,
    build_tool_approval_continuation_source_v1,
    render_extension_source_variant_v1,
)

# Pi terminates extension hooks at roughly 4.5 seconds. Keep Guard's daemon and
# recovery/fallback paths below that host deadline so a fail-safe result returns.
GUARD_HOOK_TIMEOUT_MS = 4_250
GUARD_HOOK_DEADLINE_RESERVE_MS = 250
GUARD_DAEMON_HOOK_TIMEOUT_MS = 3_100
GUARD_DAEMON_RECOVERY_TIMEOUT_MS = 250
GUARD_DAEMON_RETRY_TIMEOUT_MS = 150
GUARD_CLI_HOOK_TIMEOUT_MS = 300
GUARD_HOOK_TEXT_LIMIT_CHARS = 12_000
GUARD_HOOK_CONTENT_ITEM_LIMIT = 24
GUARD_HOOK_OBJECT_KEY_LIMIT = 24
GUARD_HOOK_MAX_DEPTH = 24
GUARD_HOOK_MAX_SERIALIZED_PAYLOAD_CHARS = 24_000

_PREVIOUS_SOURCE_VARIANT_V1 = ExtensionSourceVariantV1(
    hook_timeout_ms=GUARD_HOOK_TIMEOUT_MS,
    deadline_reserve_ms=GUARD_HOOK_DEADLINE_RESERVE_MS,
    daemon_hook_timeout_ms=GUARD_DAEMON_HOOK_TIMEOUT_MS,
    daemon_recovery_timeout_ms=GUARD_DAEMON_RECOVERY_TIMEOUT_MS,
    daemon_retry_timeout_ms=GUARD_DAEMON_RETRY_TIMEOUT_MS,
    cli_hook_timeout_ms=GUARD_CLI_HOOK_TIMEOUT_MS,
    text_limit_chars=GUARD_HOOK_TEXT_LIMIT_CHARS,
    content_item_limit=GUARD_HOOK_CONTENT_ITEM_LIMIT,
    object_key_limit=GUARD_HOOK_OBJECT_KEY_LIMIT,
    max_depth=GUARD_HOOK_MAX_DEPTH,
    max_serialized_payload_chars=GUARD_HOOK_MAX_SERIALIZED_PAYLOAD_CHARS,
    build_header=build_previous_source_header,
    build_body=build_previous_source_body,
    build_tail=build_previous_source_tail,
    build_lifecycle=build_lifecycle_abort_event_source_v1,
    build_approval=build_tool_approval_continuation_source_v1,
)


def previous_managed_extension_source(
    *,
    guard_home: Path,
    home_dir: Path,
    settings_path: Path,
    harness: str = "pi",
    display_name: str = "Pi",
) -> str:
    return render_extension_source_variant_v1(
        guard_home=guard_home,
        home_dir=home_dir,
        settings_path=settings_path,
        harness=harness,
        display_name=display_name,
        package_source=Path(__file__),
        compatibility_version=GUARD_DAEMON_COMPATIBILITY_VERSION,
        runtime_resolver=resolve_pi_extension_runtime_ownership,
        windows_executable_path=windows_system_executable_path,
        platform_name=os.name,
        variant=_PREVIOUS_SOURCE_VARIANT_V1,
    )
