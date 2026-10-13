"""Native preparation stays profile-bound and terminal on transport failure."""

import hashlib
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_restricted_pytest as transport
from codex_plugin_scanner.guard.runtime import restricted_inline_eval, restricted_node_test, restricted_vitest
from codex_plugin_scanner.guard.runtime.restricted_pytest_model import RestrictedPytestError


def reply(tmp_path, profile):
    return {
        "value": {
            "profile_version": profile,
            "backend": "macos-seatbelt",
            "backend_executable": "/usr/bin/true",
            "workspace": str(tmp_path),
            "cwd": str(tmp_path),
            "executable": "/usr/bin/node",
            "command": ["/usr/bin/node"],
            "allowed_executables": ["/usr/bin/node"],
            "denied_capabilities": ["network", "workspace-write"],
        }
    }


def test_tsx_positive_nested_reply_reaches_the_caller(monkeypatch):
    monkeypatch.setattr(transport, "_call", lambda *args, **kwargs: {"value": ["math.test.ts", ["--flag"]]})
    assert restricted_vitest.tsx_test_invocation(["tsx", "math.test.ts", "--flag"]) == ("math.test.ts", ("--flag",))


@pytest.mark.parametrize(
    "module,method,profile",
    [
        (restricted_node_test, "prepare_restricted_node_test", "node-test-readonly-v1"),
        (restricted_vitest, "prepare_restricted_vitest", "vitest-readonly-v1"),
        (restricted_inline_eval, "prepare_restricted_inline_eval", "node-eval-readonly-v1"),
    ],
)
def test_preparation_is_one_bound_call(monkeypatch, tmp_path, module, method, profile):
    calls = []

    def call(action, **kwargs):
        calls.append(action)
        return reply(tmp_path, profile)

    monkeypatch.setattr(transport, "_call", call)
    plan = getattr(module, method)(["node", "--test"], workspace=tmp_path)
    assert plan.profile_version == profile
    assert len(calls) == 1
    assert calls[0]["kind"] == "restricted_pytest"
    assert not {"allow", "verdict", "decision"}.intersection(calls[0]["body"]["input"])


@pytest.mark.parametrize("profile", ["pytest-restricted-v1", "node-build-output-v1", "allow"])
def test_reply_cannot_lower_requested_readonly_profile(monkeypatch, tmp_path, profile):
    monkeypatch.setattr(transport, "_call", lambda *a, **k: reply(tmp_path, profile))
    with pytest.raises(RestrictedPytestError):
        restricted_node_test.prepare_restricted_node_test(["node", "--test"], workspace=tmp_path)


@pytest.mark.parametrize(
    "module,method",
    [
        (restricted_node_test, "prepare_restricted_node_test"),
        (restricted_vitest, "prepare_restricted_vitest"),
        (restricted_inline_eval, "prepare_restricted_inline_eval"),
    ],
)
def test_unavailable_native_cannot_launch(monkeypatch, tmp_path, module, method):
    monkeypatch.setattr(transport, "_call", lambda *a, **k: None)
    with pytest.raises(RestrictedPytestError, match="execution was not started"):
        getattr(module, method)(["node"], workspace=tmp_path)


def test_mapping_codec_preserves_full_index_without_python_inspection(monkeypatch, tmp_path):
    observed = []

    def call(action, **kwargs):
        observed.append(action)
        snapshot = action["body"]["input"]
        path = Path(snapshot["mapping_snapshot"])
        raw = path.read_bytes()
        assert path.stat().st_mode & 0o077 == 0
        assert path.parent.stat().st_mode & 0o077 == 0
        assert len(raw) == snapshot["decoded_bytes"]
        assert hashlib.sha256(raw).hexdigest() == snapshot["sha256"]
        assert json.loads(raw)["read_files"] == list(map(str, paths))
        result = b"[]"
        path.with_name("mapping-result.json").write_bytes(result)
        path.with_name("mapping-result.json").chmod(0o600)
        return {"value": {"decoded_bytes": len(result), "sha256": hashlib.sha256(result).hexdigest()}}

    monkeypatch.setattr(transport, "_call", call)
    paths = [tmp_path / f"module-{i}.so" for i in range(100000)]
    assert transport.restricted_native("mapping_evidence", {"read_files": paths}, list) == []
    assert not Path(observed[0]["body"]["input"]["mapping_snapshot"]).exists()


def test_large_mapping_response_reaches_namespace_preparation_caller(monkeypatch, tmp_path):
    from codex_plugin_scanner.guard.runtime.restricted_linux_mapping_plan import collect_mapping_evidence

    records = [
        {"path": "/workspace/" + "module-" * 430 + str(i), "identity": [1, i, 1, 1, 0o100500], "sha256": "0" * 64}
        for i in range(1024)
    ]
    raw = json.dumps(records, separators=(",", ":")).encode()
    assert len(raw) > 2 * 1024 * 1024
    outputs = []

    def call(action, **kwargs):
        assert len(json.dumps(action).encode()) < 2 * 1024 * 1024
        output = Path(action["body"]["input"]["mapping_snapshot"]).with_name("mapping-result.json")
        output.write_bytes(raw)
        output.chmod(0o600)
        outputs.append(output)
        return {"value": {"decoded_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}}

    monkeypatch.setattr(transport, "_call", call)
    assert collect_mapping_evidence(images=set(), read_files=set(), runtime_roots=(), workspace=tmp_path) == records
    assert not outputs[0].exists()


@pytest.mark.parametrize("corruption", ["digest", "length", "budget", "permissions"])
def test_mapping_result_transport_corruption_fails_closed(monkeypatch, corruption):
    def call(action, **kwargs):
        output = Path(action["body"]["input"]["mapping_snapshot"]).with_name("mapping-result.json")
        output.write_bytes(b"[]")
        output.chmod(0o644 if corruption == "permissions" else 0o600)
        length = 3 if corruption == "length" else (32 * 1024 * 1024 + 1 if corruption == "budget" else 2)
        digest = "0" * 64 if corruption == "digest" else hashlib.sha256(b"[]").hexdigest()
        return {"value": {"decoded_bytes": length, "sha256": digest}}

    monkeypatch.setattr(transport, "_call", call)
    with pytest.raises(RestrictedPytestError, match="Mapping snapshot transport"):
        transport.restricted_native("mapping_evidence", {}, list)


def test_node_omitted_cwd_stays_at_supplied_workspace(monkeypatch, tmp_path):
    calls = []

    def call(action, **kwargs):
        calls.append(action)
        return reply(tmp_path, "node-test-readonly-v1")

    monkeypatch.setattr(transport, "_call", call)
    restricted_node_test.prepare_restricted_node_test(["node", "--test"], workspace=tmp_path)
    assert calls[0]["body"]["input"]["cwd"] == str(tmp_path)


def test_native_domain_refusal_is_preserved(monkeypatch):
    monkeypatch.setattr(
        transport,
        "_call",
        lambda *a, **k: {
            "reason_code": "vitest_restricted_dependency_unavailable",
            "message": "Local dependency unavailable.",
        },
    )
    with pytest.raises(RestrictedPytestError) as caught:
        restricted_vitest.vitest_arguments(["vitest", "run"])
    assert caught.value.reason_code == "vitest_restricted_dependency_unavailable"
