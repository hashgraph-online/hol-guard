"""Finite native projection, explicit fallback and bounded pipe contracts."""

from __future__ import annotations

import json
import os
import random
import sys
import time
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import lockfile_parse_result as contract
from codex_plugin_scanner.guard.runtime.package_manifest_diff import _dependency_map_for_path
from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import _package_lock_entries
from scripts import package_native_pilot as pilot


@pytest.fixture
def binary():
    value = os.environ.get("GUARD_PACKAGE_PILOT_BINARY")
    if sys.platform != "linux" or not value:
        pytest.skip("explicit built Linux example required; no production installation")
    path = Path(value)
    assert path.is_file()
    return path


def _parse(parser, source, *, path="package-lock.json", seconds=1.5):
    return parser(
        path,
        source,
        deadline=time.monotonic() + seconds,
        budget_ms=seconds * 1000,
        dependency_parser=_dependency_map_for_path,
        package_lock_parser=_package_lock_entries,
    )


def _same_contract(actual, expected):
    # Durations describe their different implementation work. All source,
    # parser, completeness, projection, warning and error fields are exact.
    assert replace(actual, elapsed_ms=0) == replace(expected, elapsed_ms=0)


@pytest.mark.parametrize("seed", range(30))
def test_native_complete_projection_matches_independent_python_parser(binary, seed):
    randomizer = random.Random(seed)
    packages = {"": {"name": "workspace", "version": "9"}}
    for index in range(30):
        prefix = "node_modules/" if index % 5 else "workspace/"
        path = prefix + ("@scope/root/node_modules/" if index % 3 else "") + f"alias-{index}"
        package = {"metadata": [{"seed": seed, "nested": [True, None, 1.25]}]}
        if randomizer.choice((True, True, False)):
            package["version"] = randomizer.choice(("", "1.2.3", "7-beta+build", " 2 "))
        if randomizer.choice((True, False)):
            package["name"] = randomizer.choice(("\x1c@scope/name\x1f", " \t ", "名", "name"))
        packages[path] = package
    source = json.dumps({"lockfileVersion": 3, "packages": packages}, ensure_ascii=False)
    adapter = pilot.NativePackagePilot(binary, min_bytes=0)
    actual = _parse(adapter.parse, source)
    expected = _parse(contract.parse_lockfile_text, source)
    _same_contract(actual, expected)
    assert actual.complete
    assert adapter.counts == {"native_invocations": 1, "native_complete": 1}


@pytest.mark.parametrize(
    "source,reason",
    [
        ('{"lockfileVersion":3.0,"packages":{}}', "version_outside_pilot_scope"),
        ('{"lockfileVersion":2,"packages":{}}', "version_outside_pilot_scope"),
        ('{"lockfileVersion":true,"packages":{}}', "version_outside_pilot_scope"),
        (
            '{"lockfileVersion":3,"packages":{},"dependencies":{"a":{"version":"1"}}}',
            "legacy_fallback_outside_pilot_scope",
        ),
        ('{"lockfileVersion":3,"packages":[],"dependencies":{}}', "shape_outside_pilot_scope"),
        ('{"lockfileVersion":3,"packages":{},"dependencies":[]}', "shape_outside_pilot_scope"),
        ('{"lockfileVersion":3,"packages":{},"a":[{"x":0,"\\u0078":1}]}', "duplicate_key"),
        ('{"lockfileVersion":3,"packages":{},"x":NaN}', "invalid_json"),
        ('{"lockfileVersion":3,"packages":{},"x":"\\ud800"}', "invalid_json"),
        ('{"lockfileVersion":3,"packages":{}} trailing', "invalid_json"),
    ],
)
def test_outside_scope_and_malformed_inputs_take_complete_python_fallback(binary, source, reason):
    adapter = pilot.NativePackagePilot(binary, min_bytes=0)
    _same_contract(_parse(adapter.parse, source), _parse(contract.parse_lockfile_text, source))
    assert adapter.counts == {"native_invocations": 1, "fallback:native_" + reason: 1}


def test_deeper_valid_python_json_falls_back_without_lowering_product_depth(binary):
    nested = "[" * 65 + "0" + "]" * 65
    source = '{"lockfileVersion":3,"packages":{},"metadata":' + nested + "}"
    adapter = pilot.NativePackagePilot(binary, min_bytes=0)
    actual = _parse(adapter.parse, source)
    _same_contract(actual, _parse(contract.parse_lockfile_text, source))
    assert actual.complete
    assert adapter.counts["fallback:native_depth_outside_pilot_scope"] == 1


@pytest.mark.parametrize(
    "bound,value,reason",
    [("LOCKFILE_MAX_NODES", 3, "node_limit_exceeded"), ("LOCKFILE_MAX_ENTRIES", 1, "entry_limit_exceeded")],
)
def test_native_respects_reduced_resource_limits_and_never_returns_partial(binary, monkeypatch, bound, value, reason):
    monkeypatch.setattr(contract, bound, value)
    source = '{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1"},"node_modules/b":{"version":"2"}}}'
    adapter = pilot.NativePackagePilot(binary, min_bytes=0)
    actual = _parse(adapter.parse, source)
    _same_contract(actual, _parse(contract.parse_lockfile_text, source))
    assert not actual.complete and not actual.entries
    assert actual.error_reason == reason
    assert adapter.counts["fallback:native_" + reason] == 1


@pytest.mark.parametrize(
    "path,source",
    [
        ("yarn.lock", 'a@^1:\n  version "1.2.3"\n'),
        ("pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  a@1.2.3:\n    resolution: {integrity: abc}\n"),
        ("bun.lock", '{"lockfileVersion":1,"packages":{"a":["a@1.2.3",""]}}'),
        ("Cargo.lock", 'version = 3\n[[package]]\nname = "a"\nversion = "1.2.3"\n'),
        ("composer.lock", '{"packages":[{"name":"a/b","version":"1.2.3"}]}'),
        ("Gemfile.lock", "GEM\n  specs:\n    a (1.2.3)\n\nDEPENDENCIES\n  a\n"),
        ("poetry.lock", '[[package]]\nname = "a"\nversion = "1.2.3"\n'),
        ("uv.lock", 'version = 1\n[[package]]\nname = "a"\nversion = "1.2.3"\n'),
        ("Pipfile.lock", '{"default":{"a":{"version":"==1.2.3"}}}'),
    ],
)
def test_every_other_format_routes_unchanged_without_native_invocation(binary, path, source):
    adapter = pilot.NativePackagePilot(binary, min_bytes=0)
    _same_contract(_parse(adapter.parse, source, path=path), _parse(contract.parse_lockfile_text, source, path=path))
    assert adapter.counts == {"fallback:format": 1}


def test_small_invalid_utf8_and_custom_parser_inputs_remain_python_owned(binary):
    adapter = pilot.NativePackagePilot(binary)
    source = '{"lockfileVersion":3,"packages":{}}'
    _same_contract(_parse(adapter.parse, source), _parse(contract.parse_lockfile_text, source))
    adapter.min_bytes = 0
    _same_contract(_parse(adapter.parse, b"\xff"), _parse(contract.parse_lockfile_text, b"\xff"))
    arguments = {
        "deadline": time.monotonic() + 1,
        "budget_ms": 1000,
        "dependency_parser": lambda *_args, **_kwargs: {"custom": "1"},
        "package_lock_parser": _package_lock_entries,
    }
    _same_contract(
        adapter.parse("package-lock.json", source, **arguments),
        contract.parse_lockfile_text("package-lock.json", source, **arguments),
    )
    assert adapter.counts == {"fallback:source_bytes": 1, "fallback:boundary_error": 1, "fallback:custom_parser": 1}


@pytest.mark.parametrize(
    "changes,reason",
    [
        ({"request_id": "b" * 64}, "response_identity"),
        ({"schema_version": True}, "response_identity"),
        ({"extra": 1}, "response_schema"),
        ({"status": "fallback", "reason": "no", "entries": [["a", "a", "1", True]]}, "response_partial_fallback"),
        ({"entries": [["a", "a", "1", 1]]}, "response_entry_identity"),
        ({"entries": [["a", "a", "1", True], ["a", "a", "2", True]]}, "response_entry_identity"),
    ],
)
def test_response_contract_rejects_bad_identity_types_partial_or_duplicate_entries(changes, reason):
    response = {"schema_version": 1, "request_id": "a" * 64, "status": "complete", "reason": None, "entries": []}
    response.update(changes)
    with pytest.raises(pilot.PilotFallbackError, match=reason):
        pilot._entries(json.dumps(response).encode(), "a" * 64, max_entries=100)


def test_duplicate_response_keys_are_rejected():
    with pytest.raises(pilot.PilotFallbackError, match="duplicate_response_key"):
        pilot._entries(b'{"status":"complete","status":"fallback"}', "a" * 64, max_entries=100)


def test_byte_limit_and_expired_deadline_stay_complete_or_fail(binary, monkeypatch):
    adapter = pilot.NativePackagePilot(binary, min_bytes=0)
    monkeypatch.setattr(contract, "LOCKFILE_MAX_BYTES", 8)
    result = _parse(adapter.parse, b"123456789")
    assert not result.complete and not result.entries and result.error_reason == "byte_limit_exceeded"
    assert adapter.counts == {"fallback:source_bytes": 1}
    monkeypatch.setattr(contract, "LOCKFILE_MAX_BYTES", 1000)
    result = _parse(adapter.parse, '{"lockfileVersion":3,"packages":{}}', seconds=-1)
    assert not result.complete and not result.entries and result.error_reason == "deadline_exceeded"
    assert adapter.counts["fallback:deadline_exceeded"] == 1


def _child(tmp_path, code):
    path = tmp_path / "fake-native"
    path.write_text("#!" + sys.executable + "\n" + code + "\n")
    path.chmod(0o700)
    return path


def test_pipe_deadline_covers_blocked_stdin_and_reaps_child(tmp_path):
    binary = _child(tmp_path, "import time; time.sleep(20)")
    started = time.monotonic()
    with pytest.raises(pilot.PilotFallbackError, match="deadline_exceeded"):
        pilot._exchange(binary, b"x" * (1024 * 1024), deadline=started + 0.1)
    assert time.monotonic() - started < 2


def test_pipe_output_is_bounded_and_child_reaped(tmp_path, monkeypatch):
    monkeypatch.setattr(pilot, "MAX_RESPONSE_BYTES", 1024)
    binary = _child(tmp_path, "import os,sys; sys.stdin.buffer.read(); os.write(1,b'x'*1025)")
    with pytest.raises(pilot.PilotFallbackError, match="response_byte_limit"):
        pilot._exchange(binary, b"request", deadline=time.monotonic() + 2)


def test_timeout_fallback_keeps_original_absolute_deadline(binary, monkeypatch):
    adapter = pilot.NativePackagePilot(binary, min_bytes=0)
    observations = []
    original = adapter.original

    def fail(*_args, **_kwargs):
        raise pilot.PilotFallbackError("deadline_exceeded")

    def observe(*args, **kwargs):
        observations.append(kwargs["deadline"])
        return original(*args, **kwargs)

    monkeypatch.setattr(pilot, "_exchange", fail)
    adapter.original = observe
    deadline = time.monotonic() + 1
    result = adapter.parse(
        "package-lock.json",
        '{"lockfileVersion":3,"packages":{}}',
        deadline=deadline,
        budget_ms=1000,
        dependency_parser=_dependency_map_for_path,
        package_lock_parser=_package_lock_entries,
    )
    assert result.complete and observations == [deadline]
    assert adapter.counts["fallback:deadline_exceeded"] == 1
