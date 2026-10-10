"""Point a tampered command-policy block at the local repair page.

The hook never launches the CLI and never calls authority recovery. A recent
authenticator proof can satisfy that call, so the blocked tool call must not
rebuild protection. The deny reason includes one signed loopback link. The
person opens that page and presses Repair protection. The current tool call
stays denied.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from pathlib import Path

from ..local_dashboard_session import PROTECTION_REPAIR_DASHBOARD_SURFACE
from ..runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from ..runtime.extension_control_authority import AuthorityHealth

_LOGGER = logging.getLogger(__name__)

_AUTHORITY_BLOCK_REASON = "native_command_control_authority_block"
_REPAIRABLE_HEALTH = frozenset({AuthorityHealth.TAMPERED, AuthorityHealth.RECOVERY_REQUIRED})

_APPROVAL_REASON = (
    "HOL Guard blocked this action because trusted protection settings need repair. "
    "Open this local page and press Repair protection: {url}"
)
_APPROVAL_REASON_WITHOUT_URL = (
    "HOL Guard blocked this action because trusted protection settings need repair. "
    "Open HOL Guard Extensions and press Repair protection."
)

RepairUrl = Callable[[Path], str | None]


def apply_command_policy_repair(
    store: object,
    native_result: Mapping[str, object],
    *,
    guard_home: Path,
    repair_page_url: RepairUrl | None = None,
) -> dict[str, object]:
    """Return the native denial, with a repair link when this block can be repaired."""

    try:
        result = dict(native_result)
    except Exception as exc:
        _LOGGER.warning("command policy repair could not read the native denial (%s)", type(exc).__name__)
        return {}
    try:
        return _apply_command_policy_repair(
            store,
            result,
            guard_home=guard_home,
            repair_page_url=repair_page_url,
        )
    except Exception as exc:
        _LOGGER.warning("command policy repair could not prepare the local repair link (%s)", type(exc).__name__)
        return result


def _apply_command_policy_repair(
    store: object,
    result: dict[str, object],
    *,
    guard_home: Path,
    repair_page_url: RepairUrl | None,
) -> dict[str, object]:
    if str(result.get("reason_code") or "") != _AUTHORITY_BLOCK_REASON:
        return result
    if str(result.get("minimum_action") or "") == "allow" or result.get("decision") == "allow":
        return result
    reader = getattr(store, "read_extension_control_authority_for_registry", None)
    if not callable(reader):
        return result
    view = reader(BUILT_IN_COMMAND_EXTENSION_REGISTRY)
    if getattr(view, "health", None) not in _REPAIRABLE_HEALTH:
        return result
    return _approval_required(result, guard_home, repair_page_url)


def _approval_required(
    result: dict[str, object],
    guard_home: Path,
    repair_page_url: RepairUrl | None,
) -> dict[str, object]:
    url = _safe_repair_url(guard_home, repair_page_url)
    if url:
        result["reason"] = _APPROVAL_REASON.replace("{url}", url)
        result["repair_url"] = url
    else:
        result["reason"] = _APPROVAL_REASON_WITHOUT_URL
        result.pop("repair_url", None)
    result["repair_status"] = "approval_required"
    return result


def _safe_repair_url(guard_home: Path, repair_page_url: RepairUrl | None) -> str | None:
    try:
        url = repair_page_url(guard_home) if repair_page_url is not None else command_policy_repair_page_url(guard_home)
    except Exception as exc:
        _LOGGER.warning("command policy repair link was not available (%s)", type(exc).__name__)
        return None
    if not isinstance(url, str) or not url:
        return None
    from ..approval_hook_copy import is_loopback_approval_url

    if not is_loopback_approval_url(url):
        return None
    return url


def command_policy_repair_page_url(guard_home: Path) -> str | None:
    """Signed loopback URL for the one-button repair page, or None when it is not safe."""

    from ..approval_hook_copy import authenticated_approval_review_url, is_loopback_approval_url
    from .manager import read_approval_center_locator

    locator = read_approval_center_locator(guard_home)
    daemon_url = getattr(locator, "daemon_url", None)
    if not isinstance(daemon_url, str) or not daemon_url:
        return None
    page = f"{daemon_url.rstrip('/')}/protection/repair"
    if not is_loopback_approval_url(page):
        return None
    signed = authenticated_approval_review_url(
        page,
        guard_home=guard_home,
        surface=PROTECTION_REPAIR_DASHBOARD_SURFACE,
    )
    if not isinstance(signed, str) or not is_loopback_approval_url(signed):
        return None
    return signed
