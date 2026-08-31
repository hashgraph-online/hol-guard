"""Truthful, bounded network-status command projection."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.daemon.client import (
    GuardDaemonRequestError,
    GuardDaemonResponseSchemaError,
    GuardDaemonTimeoutError,
    GuardDaemonTransportError,
    load_running_guard_surface_daemon_client,
)
from codex_plugin_scanner.guard.runtime.network_status import (
    NetworkStatusSchemaError,
    build_network_status,
    validate_network_status,
)


def load_network_status_payload(
    *,
    guard_home: Path | None,
    config: GuardConfig | None,
) -> dict[str, object]:
    """Return authenticated daemon truth or a privacy-safe zero-claim fallback."""

    legacy_domain_action = config.new_network_domain_action if config is not None else None
    reason_code: str | None = None
    payload: dict[str, object] | None = None
    try:
        if guard_home is None:
            raise GuardDaemonTransportError("Guard daemon authority is unavailable")
        payload = validate_network_status(load_running_guard_surface_daemon_client(guard_home).network_status())
        payload["status_source"] = "daemon"
    except GuardDaemonTimeoutError:
        reason_code = "daemon-timeout"
    except GuardDaemonTransportError:
        reason_code = "daemon-transport-unavailable"
    except GuardDaemonResponseSchemaError:
        reason_code = "daemon-schema-invalid"
    except GuardDaemonRequestError as error:
        reason_code = "daemon-authentication-failed" if error.status in {401, 403} else "daemon-request-failed"
    except NetworkStatusSchemaError:
        reason_code = "daemon-schema-invalid"

    if reason_code is not None:
        payload = build_network_status(profiles=(), legacy_domain_action=legacy_domain_action)
        payload.update({"status_source": "fallback", "reason_code": reason_code})
    else:
        assert payload is not None

    if reason_code is None and legacy_domain_action is not None:
        authoritative_policy = build_network_status(profiles=(), legacy_domain_action=legacy_domain_action).get(
            "legacy_domain_policy"
        )
        if authoritative_policy is not None:
            payload["legacy_domain_policy"] = authoritative_policy
    return payload
