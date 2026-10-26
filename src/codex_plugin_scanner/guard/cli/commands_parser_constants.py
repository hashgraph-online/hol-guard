"""Guard CLI parser constants that stay importable without the command surface."""

from __future__ import annotations

import argparse

from ..config_constants import VALID_RISK_ACTION_KEYS

DEFAULT_ALIAS_NAME = "guardp"
DEFAULT_GUARD_SYNC_URL = "https://hol.org/api/guard/receipts/sync"
DEFAULT_GUARD_CONNECT_URL = "https://hol.org/guard/connect"
_SERVICE_RUNTIME_CHOICES = ("hermes", "openclaw", "custom")
_GUARD_HELP_GROUPS = (
    "HOL Guard AI Antivirus command center:\n"
    "  start        First-run protection setup for one local AI harness\n"
    "  status       Home: current protection state, proof, and next action\n"
    "  dashboard    Open local Home, Protect, Inbox, Evidence, and Settings\n"
    "  apps         Protect: connect, test, repair, or disconnect AI tools\n"
    "  run          Enforce Guard before a harness launch\n"
    "  approvals    Inbox: approve, block, or scope requests needing judgment\n"
    "  receipts     Evidence: review local decisions and proof receipts\n"
    "\n"
    "Team and cloud coordination:\n"
    "  connect      Pair this machine to Guard Cloud\n"
    "  disconnect   Revoke local Guard Cloud auth and optionally revoke cloud grant state\n"
    "  login        Compatibility alias for browser pairing\n"
    "  sync         Send local decisions, receipts, and policy memory to Guard Cloud\n"
    "  service      Manage hosted-runtime Guard Cloud login and sync\n"
    "  device       Inspect or rotate this machine identity\n"
    "  bridge       Forward Guard signals to external channels\n"
    "\n"
    "Advanced and diagnostics:\n"
    "  detect       Discover harnesses and managed artifacts\n"
    "  protect      Wrap installs before they land\n"
    "  preflight    Scan a target before you add it\n"
    "  scan         Run a consumer-mode artifact scan\n"
    "  diff         Compare current artifacts to stored snapshots\n"
    "  inventory    Inspect tracked artifacts\n"
    "  abom         Export the local artifact bill of materials\n"
    "  aibom        Export the local AIBOM with trust and source metadata\n"
    "  explain      Show evidence for one artifact\n"
    "  policies     Inspect local Guard policy state\n"
    "  settings     Settings: show or update local Guard rules\n"
    "  exceptions   Inspect active exception windows\n"
    "  advisories   Inspect cached Guard Cloud advisories\n"
    "  events       Review Guard lifecycle events\n"
    "  doctor       Run local diagnostics\n"
    "  repair       Repair the daemon, hooks, and stale Guard state\n"
    "  hooks        Remove every Guard hook from every app (hooks remove --all)\n"
    "  bootstrap    Detect, install, and launch the approval center\n"
    "  install      Enable Guard management for a harness\n"
    "  uninstall    Disable Guard management or remove hol-guard entirely\n"
    "  update       Update hol-guard in the current environment\n"
    "\n"
    "Command selection:\n"
    "  Use status for Home posture and the next safe step\n"
    "  Use apps for Protect install, repair, status, and first protected action proof\n"
    "  Use approvals for Inbox decisions and receipts for Evidence\n"
    "  Use doctor for setup and runtime probes\n"
    "  Use diff for changed artifacts after a blocked launch\n"
    "  Use explain for detailed artifact evidence\n"
    "  Use events for the local timeline"
)


def _guard_risk_action_key(value: str) -> str:
    normalized = value.strip().lower().replace("-", "_")
    if normalized not in VALID_RISK_ACTION_KEYS:
        raise argparse.ArgumentTypeError(f"invalid risk class: {value}")
    return normalized
