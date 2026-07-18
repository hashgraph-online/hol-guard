"""Early MDM lifecycle command dispatch."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..mdm.continuity import provision_machine_continuity
from ..mdm.contracts import LocalIntegritySnapshot
from ..mdm.device_key import (
    machine_device_key_status,
    provision_machine_device_key,
    revoke_machine_device_key,
    rotate_machine_device_key,
)
from ..mdm.integrity import machine_integrity_snapshot
from ..mdm.lifecycle import (
    activate_user,
    authorize_deactivation,
    deactivate_user,
    machine_status,
    register_user_coverage,
    repair_user,
    unregister_user_coverage,
    user_status,
    validate_user_home,
)
from ..mdm.network import diagnose_endpoint
from ..mdm.policy import load_managed_policy
from ..mdm.supervisor import install_machine_supervisor, remove_machine_supervisor


def _emit_mdm(payload: dict[str, object] | LocalIntegritySnapshot, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(f"{payload.get('operation')}: {payload.get('state', 'complete')}")


def _run_guard_mdm_command(
    args: argparse.Namespace, *, input_text: str | None = None, output_stream: object | None = None
) -> int:
    del input_text, output_stream
    command = str(args.mdm_command)
    payload: dict[str, object] | LocalIntegritySnapshot
    try:
        if command == "authorize-deactivation":
            payload = authorize_deactivation(
                Path(str(args.home)).resolve(),
                str(args.user),
                actor=str(args.actor),
                reason=str(args.reason),
                token_name=getattr(args, "token_name", None),
            )
        elif command == "network-diagnose":
            policy_state = load_managed_policy()
            network_policy = policy_state.policy.network if policy_state.policy is not None else None
            results = [diagnose_endpoint(endpoint, network_policy).to_dict() for endpoint in args.endpoint]
            payload = {
                "schemaVersion": "hol-guard-mdm-status.v1",
                "operation": command,
                "healthy": all(
                    isinstance(result, dict) and result.get("reasonCode") == "endpoint_reachable" for result in results
                ),
                "managedPolicy": policy_state.to_public_dict(),
                "results": results,
            }
        elif command == "integrity-snapshot":
            payload = dict(machine_integrity_snapshot())
        elif command == "supervisor-install":
            payload = install_machine_supervisor()
        elif command == "supervisor-remove":
            payload = remove_machine_supervisor()
        elif command == "device-key-provision":
            payload = provision_machine_device_key()
        elif command == "device-key-status":
            status = machine_device_key_status()
            payload = {
                "schemaVersion": "hol-guard-mdm-status.v1",
                "operation": command,
                "healthy": status.healthy,
                "state": status.state,
                "protectionLevel": status.level,
                "reasonCodes": [status.reason_code],
            }
        elif command == "device-key-rotate":
            payload = rotate_machine_device_key()
        elif command == "device-key-revoke":
            payload = revoke_machine_device_key()
        elif command == "continuity-provision":
            payload = provision_machine_continuity()
        elif command == "status" and args.scope == "machine":
            root = Path(args.machine_root).resolve() if getattr(args, "machine_root", None) else None
            payload = machine_status(machine_root=root)
        else:
            if command == "status" and not getattr(args, "home", None):
                raise ValueError("mdm_home_required_for_user_scope")
            machine_coverage_command = command in {
                "harness-coverage-register",
                "harness-coverage-unregister",
            }
            home = validate_user_home(
                str(args.home),
                getattr(args, "user", None),
                require_user_context=not machine_coverage_command,
            )
            if command == "status":
                payload = user_status(home)
            elif command == "activate":
                payload = activate_user(home, str(args.user))
            elif command == "repair":
                payload = repair_user(home, str(args.user))
            elif command == "harness-coverage-register":
                payload = register_user_coverage(home, str(args.user))
            elif command == "harness-coverage-unregister":
                payload = unregister_user_coverage(home, str(args.user))
            elif command == "deactivate":
                if not args.authorization_file:
                    raise PermissionError("mdm_removal_authorization_required")
                payload = deactivate_user(
                    home,
                    user=str(args.user),
                    authorization_file=Path(str(args.authorization_file)),
                )
            else:
                raise ValueError("mdm_command_invalid")
    except (OSError, RuntimeError, ValueError, PermissionError) as exc:
        payload = {
            "schemaVersion": "hol-guard-mdm-status.v1",
            "operation": command,
            "healthy": False,
            "reasonCodes": [str(exc)],
        }
        _emit_mdm(payload, bool(args.json))
        return 2
    _emit_mdm(payload, bool(args.json))
    return 0 if payload.get("healthy", True) else 1


__all__ = ["_run_guard_mdm_command"]
