#!/usr/bin/env python3
"""Side-effect-free installed runtime probe for Extension Control Center CI."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from codex_plugin_scanner import __version__
from codex_plugin_scanner.guard.runtime.command_evaluation import evaluate_command
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_base import EncryptedFileSecretStore

_PROBE_COMMAND = "git clean -fdx"
_EXPECTED_PERMISSION = "command.git.permission.force-clean"
_EXPECTED_RULE = "command.git.force-clean"


def main() -> None:
    expected_version = os.environ["HOL_GUARD_INSTALLED_EXPECTED_VERSION"]
    if __version__ != expected_version:
        raise RuntimeError("installed runtime probe version mismatch")
    package_file = Path(sys.modules["codex_plugin_scanner"].__file__ or "").resolve(strict=True)
    if "site-packages" not in package_file.parts:
        raise RuntimeError("runtime probe must import from installed site-packages")

    guard_home = Path(os.environ["HOL_GUARD_INSTALLED_HOME"]).resolve()
    workspace = Path(os.environ["HOL_GUARD_INSTALLED_WORKSPACE"]).resolve()
    output = Path(os.environ["HOL_GUARD_INSTALLED_PROBE_FILE"]).resolve()
    store = GuardStore(guard_home, prime_policy_integrity=False)
    store._extension_control_authority_secret_store = EncryptedFileSecretStore(guard_home)  # pyright: ignore[reportPrivateUsage]
    authority = store.read_extension_control_authority(
        catalog_digest=BUILT_IN_COMMAND_EXTENSION_REGISTRY.catalog_digest,
    )
    if authority.health is not AuthorityHealth.PROTECTED:
        raise RuntimeError(f"runtime probe authority is not protected: {authority.health.value}")

    permission = BUILT_IN_COMMAND_EXTENSION_REGISTRY.permission(_EXPECTED_PERMISSION)
    if permission is None or _EXPECTED_RULE not in permission.rule_ids:
        raise RuntimeError("runtime probe catalog ownership changed")

    evaluation = evaluate_command(
        _PROBE_COMMAND,
        cwd=workspace,
        home_dir=guard_home,
        extension_control_layers=authority.layers,
    )
    if not evaluation.control_resolution.blocked:
        raise RuntimeError("installed runtime probe was not blocked by extension policy")
    if evaluation.minimum_action != "block":
        raise RuntimeError("installed runtime probe minimum action is not block")
    matched_rule_ids = sorted({owned.match.rule.rule_id for owned in evaluation.matches})
    if _EXPECTED_RULE not in matched_rule_ids:
        raise RuntimeError("installed runtime probe did not match the governed rule")

    reason_codes = sorted({factor.reason_code for factor in evaluation.control_resolution.factors})
    payload = {
        "schema_version": "guard.ci.extension-control-runtime-probe.v1",
        "guard_version": __version__,
        "authority_revision": authority.revision,
        "catalog_digest": authority.catalog_digest,
        "permission_id": _EXPECTED_PERMISSION,
        "matched_rule_ids": matched_rule_ids,
        "minimum_action": evaluation.minimum_action,
        "control_blocked": evaluation.control_resolution.blocked,
        "control_reason_codes": reason_codes,
        "command_executed": False,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    output.chmod(0o600)


if __name__ == "__main__":
    main()
