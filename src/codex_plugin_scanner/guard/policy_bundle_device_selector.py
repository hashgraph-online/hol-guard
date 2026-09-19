"""Stable installation identity for signed-bundle device targeting."""

from __future__ import annotations

from collections.abc import Sequence


def device_selector_matches_installation(
    devices: object,
    *,
    device_id: str,
) -> bool:
    """Match device selectors by immutable installation identity only.

    Human device names are display labels. Matching on them would widen a
    policy whenever two installations share a name.
    """

    if not isinstance(devices, Sequence) or isinstance(devices, (str, bytes)) or not devices:
        return True
    return any(isinstance(item, str) and item == device_id for item in devices)


def selected_installation_acknowledgement(*, device_id: str, device_name: str) -> dict[str, str]:
    return {
        "deviceId": device_id,
        "deviceName": device_name,
        "targetingIdentity": "installation_id",
    }


__all__ = ["device_selector_matches_installation", "selected_installation_acknowledgement"]
