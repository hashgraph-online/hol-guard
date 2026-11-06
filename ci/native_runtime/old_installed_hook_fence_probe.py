"""Run with the previous wheel's isolated Python, never the checkout's imports."""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import io
import json
import sys
from pathlib import Path

import codex_plugin_scanner
from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard import store as store_module
from codex_plugin_scanner.guard.native_command_control_authority import decode_authority
from codex_plugin_scanner.guard.native_command_control_authority_io import hold_command_control_authority_lock
from codex_plugin_scanner.guard.native_command_control_authority_store import begin_native_command_control_mutation
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.native_resident_client import close_native_residents
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.version import __version__


class ScopedMemorySecrets:
    """Synthetic credential transport; actual old signing/publishing stays intact."""

    def __init__(self):
        self.values = {}

    def get_secret(self, reference):
        return self.values.get(reference)

    def set_secret(self, reference, value):
        self.values[reference] = value

    def delete_secret(self, reference):
        self.values.pop(reference, None)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def run(home):
    package = Path(codex_plugin_scanner.__file__).resolve().parent
    assert package == Path(sys.prefix) / "lib/python3.12/site-packages/codex_plugin_scanner", package
    backend = ScopedMemorySecrets()
    store_module._build_policy_integrity_secret_store = lambda *args, **kwargs: backend
    home.mkdir(mode=0o700)
    (home / "config.toml").write_text(
        'protection_posture = "protected"\ndefault_action = "allow"\n'
        'subprocess_action = "allow"\nsandbox_analysis = "off"\n'
    )
    store = GuardStore(home)
    publisher = NativePolicySnapshotPublisher(store=store)
    payload = dict(hook_event_name="PreToolUse", tool_name="Bash", tool_input=dict(command="pwd"), cwd=str(home))
    event = home / "event.json"
    event.write_bytes(encoded(payload))

    def hook(command="pwd"):
        payload["tool_input"]["command"] = command
        event.write_bytes(encoded(payload))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(
                [
                    "guard",
                    "hook",
                    "--guard-home",
                    str(home),
                    "--home",
                    str(home),
                    "--harness",
                    "claude-code",
                    "--event-file",
                    str(event),
                    "--json",
                ]
            )
        return dict(exit=result, output=json.loads(output.getvalue()))

    def retained_rows():
        with store._connect() as connection:
            return [
                list(row)
                for row in connection.execute(
                    "select * from policy_decisions where reason = 'old-hook-fence-fixture' order by decision_id"
                )
            ]

    def verdict(result, expected):
        output = result["output"]
        assert output["hookSpecificOutput"]["permissionDecision"] == expected, result
        if expected == "deny":
            assert output.get("policy_action", "block") == "block", result
        else:
            assert result["exit"] == 0 and output["policy_action"] == "allow", result

    try:
        publisher._publish_once()
        assert publisher.is_ready(), publisher.last_error
        marker_path = home / "native-runtime/command-control-authority.v1.json"
        key = (home / "native-runtime/policy-verifier.key").read_bytes()
        legacy = decode_authority(marker_path.read_bytes(), key)
        assert legacy["phase"] == "committed"
        with hold_command_control_authority_lock(home):
            begin_native_command_control_mutation(store)
        assert decode_authority(marker_path.read_bytes(), key)["phase"] == "closed"
        publisher._publish_once()
        assert publisher.is_ready(), publisher.last_error
        program = publisher.current_snapshot()["command_extensions"]["program_digest"]
        before = hook()
        verdict(before, "allow")
        print(json.dumps(dict(stage="before", permission_decision="allow")), flush=True)
        core = hook("rm -rf /")
        verdict(core, "deny")
        with store._connect() as connection:
            # Fixture rows use the real durable schema and exact core action
            # identity. Retention is asserted; approval issuance is not exercised.
            for action, source in (("block", "managed"), ("allow", "local")):
                connection.execute(
                    "insert into policy_decisions"
                    "(harness,scope,artifact_id,artifact_hash,action,source,reason,updated_at) "
                    "values('claude-code','artifact',?,?,?,?,'old-hook-fence-fixture','2026-10-18T00:00:00Z')",
                    (core["output"]["artifact_id"], core["output"]["artifact_hash"], action, source),
                )
        retained = retained_rows()
        verdict(hook("rm -rf /"), "deny")
        marker = json.loads(marker_path.read_bytes())
        marker.pop("mac")
        marker.update(
            schema="guard.native-command-control-authority.v3",
            pack_program_digest=program,
            active_security_digest="a" * 64,
        )
        marker["mac"] = hmac.new(
            key, b"hol-guard.native-command-control-authority.v3\0" + encoded(marker), hashlib.sha256
        ).hexdigest()
        marker_path.write_bytes(encoded(marker))
        marker_bytes = marker_path.read_bytes()
        for command in ("pwd", "rm -rf /", "pwd"):
            after = hook(command)
            verdict(after, "deny")
            print(json.dumps(dict(stage="after", command=command, permission_decision="deny")), flush=True)
            assert marker_path.read_bytes() == marker_bytes
        # A fresh old publisher must not reconstruct a legacy snapshot.
        cold = NativePolicySnapshotPublisher(store=store)
        try:
            cold._publish_once()
            assert not cold.is_ready() and cold.current_snapshot() is None
            assert cold.last_error == "native_command_control_authority_invalid", cold.last_error
            print(json.dumps(dict(stage="publisher", ready=cold.is_ready(), error=cold.last_error)), flush=True)
        finally:
            assert cold.close()
        with hold_command_control_authority_lock(home):
            try:
                begin_native_command_control_mutation(store)
            except Exception as error:
                assert str(error) == "native_command_control_authority_invalid", repr(error)
                print(json.dumps(dict(stage="writer", error=str(error))), flush=True)
            else:
                raise AssertionError("old writer accepted v3")
        assert marker_path.read_bytes() == marker_bytes
        assert retained_rows() == retained
        # An otherwise valid legacy body signed in the v3 MAC domain cannot
        # be downgraded into an old authority either. No disk rewrite here.
        domain_body = {name: value for name, value in legacy.items() if name != "mac"}
        domain_body["mac"] = hmac.new(
            key, b"hol-guard.native-command-control-authority.v3\0" + encoded(domain_body), hashlib.sha256
        ).hexdigest()
        try:
            decode_authority(encoded(domain_body), key)
        except Exception as error:
            assert str(error) == "native_command_control_authority_integrity_invalid", repr(error)
        else:
            raise AssertionError("old codec accepted v3 MAC domain for legacy body")
        print(
            json.dumps(dict(stage="retained", actions=["managed:block", "local:allow"], core_before="deny")), flush=True
        )
    finally:
        assert publisher.close()
        assert close_native_residents(home)
    print(json.dumps(dict(version=__version__, package=str(package))), flush=True)


if __name__ == "__main__":
    run(Path(sys.argv[1]))
