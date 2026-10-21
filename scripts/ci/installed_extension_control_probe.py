#!/usr/bin/env python3
"""Side-effect-free installed runtime probe for Extension Control Center CI."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from installed_extension_authority_fixture import describe_authority, read_authority

from codex_plugin_scanner import __version__
from codex_plugin_scanner.guard.native_pretool import review_pre_tool_native
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from codex_plugin_scanner.guard.runtime.extension_control_authority import AuthorityHealth
from codex_plugin_scanner.guard.runtime.extension_control_runtime import ExtensionControlRuntimeSnapshot
from codex_plugin_scanner.guard.runtime.native_command_evaluation import review_command_native
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_base import EncryptedFileSecretStore

_PROBE_COMMAND = "aws apigateway delete-rest-api --rest-api-id ci-proof"
_EXPECTED_PERMISSION = "command.api-gateway.permission.delete"
_EXPECTED_RULE = "command.api-gateway.delete"


_NATIVE_TIMEOUT_SECONDS = 15.0


def _native_failure_detail(snapshot: ExtensionControlRuntimeSnapshot, guard_home: Path, workspace: Path) -> str:
    """Report which stage of the native review produced no result."""

    facts = [f"authority_failure={snapshot.authority_failure or 'none'}"]
    try:
        native = review_pre_tool_native(
            _PROBE_COMMAND,
            guard_home=guard_home,
            cwd=workspace,
            home_dir=guard_home,
            timeout_seconds=_NATIVE_TIMEOUT_SECONDS,
            record_health=False,
        )
    except Exception as error:  # pragma: no cover - diagnostic only
        facts.append(f"native_error={type(error).__name__}: {error}")
        return ", ".join(facts)
    if native is None:
        facts.append("native_pre_tool=unavailable")
        return ", ".join(facts)
    facts.append(f"native_keys={sorted(native)}")
    facts.append(f"command_model={'present' if isinstance(native.get('command_model'), dict) else 'missing'}")
    return ", ".join(facts)


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
    authority = read_authority(store)
    if authority.health is not AuthorityHealth.PROTECTED:
        raise RuntimeError(
            f"runtime probe authority is not protected: {authority.health.value} ({describe_authority(store)})"
        )

    permission = BUILT_IN_COMMAND_EXTENSION_REGISTRY.permission(_EXPECTED_PERMISSION)
    if permission is None or _EXPECTED_RULE not in permission.rule_ids:
        raise RuntimeError("runtime probe catalog ownership changed")

    snapshot = ExtensionControlRuntimeSnapshot.from_authority_view(authority)
    # A cold runner pays for the first native invocation: process start, binary
    # page-in and catalog load. The runtime's half-second default is sized for a
    # warm resident daemon, not for this one-shot probe, and timing out here
    # reports a dead runtime rather than the policy outcome under test.
    reviewed = review_command_native(
        _PROBE_COMMAND,
        guard_home=guard_home,
        cwd=workspace,
        home_dir=guard_home,
        extension_control_snapshot=snapshot,
        timeout_seconds=_NATIVE_TIMEOUT_SECONDS,
    )
    if reviewed is None:
        raise RuntimeError(
            "installed runtime probe could not obtain a native command evaluation "
            f"({_native_failure_detail(snapshot, guard_home, workspace)})"
        )
    evaluation = reviewed.evaluation
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
