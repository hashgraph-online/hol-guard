"""Exercise the installed Bash sink in the explicit private browser fixture.

This helper queues and retries commands. Only the browser supplies consent.
It never prints private fixture readiness, credentials or SDK handles.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import subprocess
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--guard-home", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--case", choices=("allow-once", "always-allow"), required=True)
    parser.add_argument(
        "--action", choices=("configure", "prepare", "execute", "replay", "new", "after-stop"), required=True
    )
    arguments = parser.parse_args()
    root = Path(os.environ["DASHBOARD_E2E_ROOT"]).resolve(strict=True)
    guard = arguments.guard_home.resolve(strict=True)
    workspace = arguments.workspace.resolve(strict=True)
    if root == guard or not guard.is_relative_to(root) or not workspace.is_relative_to(root):
        raise ValueError("execution fixture requires the explicit private browser root")
    os.environ["HOME"] = str((root / "home").resolve(strict=True))
    if arguments.action == "configure":
        # Trusted fixture policy makes even the fixed, captured Bash builtins
        # require consent. It grants no approval and never modifies a live home.
        from codex_plugin_scanner.guard.native_bash_protocol import runtime_status

        identity = runtime_status().identity
        if identity is None:
            raise RuntimeError("installed native execution runtime is unavailable")
        request = {
            "schema": "guard-config-update.v1",
            "guard_home": str(guard),
            "kind": "settings",
            "value_text": json.dumps({"subprocess_action": "review"}),
        }
        configured = subprocess.run(
            [str(identity.path), "guard-config-update", "--stdin"],
            input=json.dumps(request),
            text=True,
            capture_output=True,
            timeout=30,
        )
        if configured.returncode or json.loads(configured.stdout).get("ok") is not True:
            raise RuntimeError("fixture execution review policy was not configured")
        print(json.dumps({"code": 0, "execution_review_required": True}))
        return
    profile = root / f"execution-profile-{arguments.case}"
    entry = workspace / f"execution-{arguments.case}.sh"
    report = profile / "execution-report.txt"
    expected = f"browser-cigar-{arguments.case}\n"
    if arguments.action == "prepare":
        profile.mkdir(mode=0o700)
        with entry.open("x") as out:
            out.write(': > "$HOME/execution-report.txt"\n')
            out.write(f'printf "browser-cigar-{arguments.case}\\n" >> "$HOME/execution-report.txt"\n')
    profile.resolve(strict=True)
    entry.resolve(strict=True)
    os.chdir(workspace)
    os.environ["HOME"] = str(profile)
    os.environ["PATH"] = "/usr/bin:/bin"

    from codex_plugin_scanner.guard.runtime.bound_bash_sink import run_bound_bash
    from codex_plugin_scanner.guard.store import GuardStore
    from codex_plugin_scanner.guard.store_base import EncryptedFileSecretStore

    store = GuardStore(guard, prime_policy_integrity=False)
    store._extension_control_authority_secret_store = EncryptedFileSecretStore(guard)
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "bash",
        "tool_input": {"command": f"/bin/bash '{entry}'"},
        "cwd": str(workspace),
    }
    operation = f"browser-cigar-{arguments.case}-operation-1"
    if arguments.action == "new":
        operation = f"browser-cigar-{arguments.case}-operation-2"
    elif arguments.action == "after-stop":
        operation = f"browser-cigar-{arguments.case}-operation-3"
    if arguments.action == "replay":
        if report.read_text() != expected:
            raise RuntimeError("fixture execution was not established before replay")
        report.write_text("preserved after completed native execution")
    output, errors = io.StringIO(), io.StringIO()
    code = run_bound_bash(
        payload,
        store=store,
        workspace=workspace,
        harness="omp",
        operation_id=operation,
        output=output,
        errors=errors,
    )
    result: dict[str, object] = {"code": code}
    if arguments.action == "prepare":
        if code != 125 or "native_bash_consent_required" not in errors.getvalue() or report.exists():
            raise RuntimeError("native execution did not wait for browser consent")
        pending = [
            row
            for row in store.list_approval_requests()
            if row["action_envelope_json"].get("native_bash", {}).get("review_lineage", {}).get("operation_id")
            == operation
        ]
        if len(pending) != 1:
            raise RuntimeError("native execution review was not uniquely queued")
        result["request_id"] = pending[0]["request_id"]
    elif arguments.action == "replay":
        result["effect_unchanged"] = report.read_text() == "preserved after completed native execution"
        result["output_not_retained"] = "output_not_retained" in errors.getvalue()
    else:
        result["expected_effect"] = report.exists() and report.read_text() == expected
        result["requires_consent"] = "native_bash_consent_required" in errors.getvalue()
    print(json.dumps(result))


if __name__ == "__main__":
    main()
