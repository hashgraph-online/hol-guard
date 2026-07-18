"""Stable, prompt-free MDM lifecycle parser contract."""

from __future__ import annotations

import argparse


def _add_json(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="Emit the versioned JSON automation contract")


def _add_user(parser: argparse.ArgumentParser, *, require_user: bool = False) -> None:
    parser.add_argument("--home", required=True, help="Absolute home directory for the target user")
    parser.add_argument("--user", required=require_user, help="Target operating-system user identity")
    _add_json(parser)


def _configure_guard_mdm_parsers(
    guard_subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
) -> None:
    mdm = guard_subparsers.add_parser("mdm", help="Prompt-free enterprise deployment lifecycle")
    commands = mdm.add_subparsers(dest="mdm_command", required=True)

    status = commands.add_parser("status", help="Read machine or per-user deployment health")
    status.add_argument("--scope", required=True, choices=("machine", "user"))
    status.add_argument("--home", help="Absolute target home; required for user scope")
    status.add_argument("--machine-root", help="Machine runtime root override for test and remediation scripts")
    _add_json(status)

    integrity_snapshot = commands.add_parser(
        "integrity-snapshot", help="Read a fail-honest local machine integrity snapshot"
    )
    integrity_snapshot.add_argument("--scope", required=True, choices=("machine",))
    integrity_snapshot.add_argument(
        "--json", required=True, action="store_true", help="Emit the versioned JSON automation contract"
    )

    for name in ("supervisor-install", "supervisor-remove"):
        supervisor = commands.add_parser(name, help=argparse.SUPPRESS)
        _add_json(supervisor)

    for name in ("device-key-provision", "device-key-status", "device-key-rotate", "device-key-revoke"):
        device_key = commands.add_parser(name, help=argparse.SUPPRESS)
        _add_json(device_key)

    for name in ("activate", "repair"):
        command = commands.add_parser(name, help=f"Idempotently {name} Guard for one user")
        _add_user(command, require_user=True)

    deactivate = commands.add_parser("deactivate", help="Restore Guard-owned user integrations")
    _add_user(deactivate, require_user=True)
    deactivate.add_argument("--authorization-file", help="Short-lived MDM removal authorization file")

    authorize = commands.add_parser(
        "authorize-deactivation", help="Create a short-lived machine-owned user removal authorization"
    )
    _add_user(authorize, require_user=True)
    authorize.add_argument("--token-name", help="Machine-state token filename selected by the MDM wrapper")

    network = commands.add_parser("network-diagnose", help="Test managed DNS, proxy, and TLS without prompts")
    network.add_argument("--endpoint", action="append", required=True, help="Approved HTTPS endpoint to test")
    _add_json(network)


__all__ = ["_configure_guard_mdm_parsers"]
