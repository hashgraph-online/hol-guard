"""Small OAuth token fixtures shared by Guard runtime tests."""

from __future__ import annotations

import base64
import json


def oauth_binding_access_token(
    device_id: str,
    grant_id: str,
    machine_id: str,
    workspace_id: str,
) -> str:
    claims = {
        "device": {"deviceId": device_id},
        "grant": {"grantId": grant_id},
        "machine": {"machineId": machine_id},
        "workspace": {"workspaceId": workspace_id},
    }
    encoded = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"header.{encoded}.signature"


__all__ = ["oauth_binding_access_token"]
