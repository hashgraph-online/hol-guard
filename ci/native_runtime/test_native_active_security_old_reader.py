"""An actual previous native executable must fence an already warm reader.

Supply HOL_GUARD_OLD_NATIVE_BINARY from a separately verified release artifact.
Only the temporary fixture home is provisioned; no credential or approval IO.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.native_policy_snapshot_policy import _scope_digest_v3
from codex_plugin_scanner.guard.native_resident_client import (
    close_native_residents,
    native_resident_client_request,
)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def private(path, data):
    path.write_bytes(data)
    path.chmod(0o600)


def test_actual_old_installed_python_hook_and_publisher_reject_security_v3(tmp_path):
    python = os.environ.get("HOL_GUARD_OLD_PYTHON")
    if not python:
        pytest.skip("separately verified previous installed Python wheel is required")
    environment = {k: os.environ[k] for k in ("PATH", "TMPDIR", "SYSTEMROOT", "WINDIR") if k in os.environ}
    environment.update(HOME=str(tmp_path), USERPROFILE=str(tmp_path))
    probe = Path(__file__).with_name("old_installed_hook_fence_probe.py")
    result = subprocess.run(
        [python, "-I", str(probe), str(tmp_path / "installed-hook-home")],
        cwd=tmp_path, env=environment, capture_output=True, timeout=240,
    )
    log = os.environ.get("HOL_GUARD_OLD_HOOK_LOG")
    if log:
        Path(log).write_bytes(result.stdout + result.stderr)
    assert result.returncode == 0, (result.stdout + result.stderr).decode()[-3000:]
    records = [json.loads(line) for line in result.stdout.splitlines()]
    assert [row["stage"] for row in records[:-1]] == [
        "before", "after", "after", "after", "publisher", "writer", "retained"
    ]
    # Verify the cross-version fixture is genuinely admitted by the new codec.
    from codex_plugin_scanner.guard.native_command_control_authority import decode_authority

    state = tmp_path / "installed-hook-home/native-runtime"
    marker = decode_authority(
        (state / "command-control-authority.v1.json").read_bytes(), (state / "policy-verifier.key").read_bytes()
    )
    assert marker["schema"] == "guard.native-command-control-authority.v3"
    assert marker["active_security_digest"] == "a" * 64


def test_actual_old_warm_native_reader_rejects_security_v3_marker(tmp_path):
    binary = os.environ.get("HOL_GUARD_OLD_NATIVE_BINARY")
    if not binary:
        pytest.skip("separately verified previous native release is required")
    runtime = Path(binary).resolve(strict=True)
    package = runtime.parent.parent
    program = json.loads((package / "guard/contracts/data/extensions/native-command-program.v1.json").read_bytes())
    home = tmp_path / "old-reader-home"
    home.mkdir(mode=0o700)
    state = home / "native-runtime"
    state.mkdir(mode=0o700)
    key = b"s" * 32
    private(state / "policy-verifier.key", key)
    private(home / "extension-control-authority.lock", b"0")
    authority = dict(epoch=1, mutation_revision=1, authority_key_id="0" * 64, recovery=None)
    body = dict(
        schema_version="guard.extension-control-runtime-snapshot.v1",
        catalog_digest=program["catalog_digest"],
        health="unenrolled",
        revision=0,
        managed_revision=0,
        layers=[],
    )
    raw = encoded(body)
    effective = hashlib.sha256(
        b"guard.extension-control-runtime-snapshot.v1\0" + str(len(raw)).encode() + b"\0" + raw
    ).hexdigest()
    binding = dict(
        schema="guard.native-command-control-binding.v1",
        program_digest=program["program_digest"],
        catalog_digest=program["catalog_digest"],
        trust_digest=program["trust_digest"],
        health="unenrolled",
        revision=0,
        managed_revision=0,
        layers=[],
        effective_digest=effective,
        authority=authority,
    )
    marker = dict(
        schema="guard.native-command-control-authority.v1", **authority, phase="committed", effective_digest=effective
    )

    def publish(value, domain):
        private(
            state / "command-control-authority.v1.json",
            encoded({**value, "mac": hmac.new(key, domain + encoded(value), hashlib.sha256).hexdigest()}),
        )

    publish(marker, b"hol-guard.native-command-control-authority.v1\0")
    fixture = json.loads(
        (Path(__file__).parents[2] / "contracts/native-policy-snapshot/v3/policy-snapshot-vector.json").read_bytes()
    )
    policy = fixture["snapshot"]["effective_policy"]
    policy.update(
        default_action="allow", protection_posture="protected", subprocess_action="allow", sandbox_analysis="off"
    )
    rule = json.loads(subprocess.check_output([str(runtime), "rule-contract", "--json"], timeout=10))["rule_digest"]
    now = int(time.time() * 1000)
    request = dict(
        schema="guard-native-policy-build.v1",
        version=1,
        verifier_key=list(key),
        generation=1,
        runtime_identity=hashlib.sha256(runtime.read_bytes()).hexdigest(),
        rule_digest=rule,
        mode="enforce",
        scope_contract=dict(
            schema="guard-native-scope.v1",
            kind="guard-home",
            scope_digest=_scope_digest_v3(home),
            workspace_binding="request-source",
        ),
        effective_policy=policy,
        command_extensions=binding,
        issued_at_ms=now - 1,
        expires_at_ms=now + 3600000,
    )
    built = subprocess.run(
        [str(runtime), "policy-snapshot-build", "--stdin"], input=encoded(request), capture_output=True, timeout=15
    )
    assert built.returncode == 0, built.stderr.decode()
    snapshot = json.loads(built.stdout)
    envelope = dict(
        schema="guard-hook-envelope.v2",
        request_id="old-warm-security",
        harness="claude",
        event="PreToolUse",
        raw_payload=dict(hook_event_name="PreToolUse", tool_name="Bash", tool_input=dict(command="pwd")),
        deadline_budget_ms=5000,
        policy_generation=1,
        policy_snapshot=snapshot,
        source=dict(cwd=str(home), home_dir=str(home), guard_home=str(home), source_ref_external_allowed=False),
    )
    environment = {
        k: os.environ[k] for k in ("PATH", "SYSTEMROOT", "SystemRoot", "WINDIR", "TEMP", "TMP") if k in os.environ
    }
    environment.update(HOME=str(tmp_path), USERPROFILE=str(tmp_path))

    def exchange(payload, hook=False):
        return native_resident_client_request(
            executable=runtime,
            guard_home=home,
            environment=environment,
            payload=encoded(payload),
            timeout_seconds=10,
            raw_hook_envelope=hook,
        )

    try:
        push = subprocess.run(
            [str(runtime), "resident-client", "--stdin", str(state)],
            input=encoded(
                dict(
                    operation="policy_snapshot_push",
                    deadline_budget_ms=9000,
                    request=dict(schema="guard-policy-snapshot-push.v1", snapshot=snapshot),
                )
            ),
            capture_output=True,
            timeout=15,
            env=environment,
        )
        assert push.returncode == 0, push.stderr
        pushed = push.stdout
        assert pushed is not None and json.loads(pushed).get("status") == "accepted", pushed
        before = exchange(envelope, True)
        assert before is not None and json.loads(before)["result"]["minimum_action"] == "allow"
        residents = sorted(state.glob("resident-v3-*/generation-*.json"))
        assert len(residents) == 1
        warm_generation = residents[0].read_bytes()
        # The actual v3 marker retains the existing filename, lock and domain
        # separation. Old readers must not interpret it as their committed v1.
        publish(
            {
                **marker,
                "schema": "guard.native-command-control-authority.v3",
                "pack_program_digest": program["program_digest"],
                "active_security_digest": "a" * 64,
            },
            b"hol-guard.native-command-control-authority.v3\0",
        )
        for _ in range(3):
            after = exchange(envelope, True)
            assert after is None or json.loads(after).get("result", {}).get("minimum_action") != "allow"
        assert sorted(state.glob("resident-v3-*/generation-*.json")) == residents
        assert residents[0].read_bytes() == warm_generation
    finally:
        assert close_native_residents(home)
