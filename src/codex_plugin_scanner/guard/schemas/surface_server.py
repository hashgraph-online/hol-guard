"""Guard Surface Server schema helpers."""

from __future__ import annotations

CURRENT_PROTOCOL_VERSION = "1.1"
MINIMUM_PROTOCOL_VERSION = "1.0"
SUPPORTED_PROTOCOL_VERSIONS = (CURRENT_PROTOCOL_VERSION, MINIMUM_PROTOCOL_VERSION)
SCHEMA_VERSION = "guard-surface-server.v1"


def build_surface_server_contract() -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "protocol_versions": list(SUPPORTED_PROTOCOL_VERSIONS),
        "protocol": {
            "current_version": CURRENT_PROTOCOL_VERSION,
            "minimum_version": MINIMUM_PROTOCOL_VERSION,
            "supported_versions": list(SUPPORTED_PROTOCOL_VERSIONS),
            "compatibility": "same-major",
        },
        "entities": {
            "session": {
                "states": ["created", "attached", "active", "idle", "archived"],
                "required_fields": [
                    "session_id",
                    "harness",
                    "surface",
                    "status",
                    "client_name",
                    "created_at",
                    "updated_at",
                ],
                "json_schema": {
                    "type": "object",
                    "required": [
                        "session_id",
                        "harness",
                        "surface",
                        "status",
                        "client_name",
                        "created_at",
                        "updated_at",
                    ],
                },
            },
            "operation": {
                "states": ["started", "waiting_on_approval", "resumed", "completed", "blocked", "failed"],
                "required_fields": [
                    "operation_id",
                    "session_id",
                    "harness",
                    "operation_type",
                    "status",
                    "created_at",
                    "updated_at",
                ],
                "json_schema": {
                    "type": "object",
                    "required": [
                        "operation_id",
                        "session_id",
                        "harness",
                        "operation_type",
                        "status",
                        "created_at",
                        "updated_at",
                    ],
                },
            },
            "item": {
                "states": ["created", "completed"],
                "required_fields": [
                    "item_id",
                    "operation_id",
                    "item_type",
                    "lifecycle",
                    "payload",
                    "created_at",
                ],
                "json_schema": {
                    "type": "object",
                    "required": [
                        "item_id",
                        "operation_id",
                        "item_type",
                        "lifecycle",
                        "payload",
                        "created_at",
                    ],
                },
            },
        },
        "methods": [
            "initialize",
            "session/start",
            "session/list",
            "session/attach",
            "operation/start",
            "operation/status",
            "operation/item/add",
            "client/attach",
            "client/heartbeat",
        ],
        "notifications": [
            "session/started",
            "session/attached",
            "operation/started",
            "operation/waitingApproval",
            "operation/resumed",
            "operation/completed",
            "item/completed",
            "approval/requested",
            "approval/resolved",
            "receipt/created",
            "policy/changed",
        ],
    }
