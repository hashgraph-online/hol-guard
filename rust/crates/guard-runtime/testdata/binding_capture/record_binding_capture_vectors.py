"""Record Codex binding-capture parity vectors from the Python implementation.

The Python modules this exercises (``codex_binding_capture*.py``) were retired
by the native cutover; run this recorder against a checkout that still carries
them (the parent of the cutover commit) to regenerate ``vectors.json``:

    GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 \
        .venv/bin/python rust/crates/guard-runtime/testdata/binding_capture/record_binding_capture_vectors.py

Time is pinned to ``NOW`` so every vector is independent of the wall clock.
Random AES-GCM nonces make sealed receipts non-deterministic, so recorded
output files normalise each sealed receipt to its decrypted body; seed files
carry the real Python-sealed bytes so the native side proves interoperability.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

NOW = 1_800_000_000
KEY = bytes(range(32))
KEY_ID = "0123456789abcdef0123456789abcdef"
RUN_ID = "run-1"

_real_time = time.time
time.time = lambda: float(NOW)  # type: ignore[assignment]

from codex_plugin_scanner.guard import codex_binding_capture as cap  # noqa: E402
from codex_plugin_scanner.guard import codex_binding_capture_crypto as crypto  # noqa: E402
from codex_plugin_scanner.guard.codex_binding_capture_bounds import canonical_json_bytes  # noqa: E402
from codex_plugin_scanner.guard.codex_binding_capture_join import (  # noqa: E402
    join_binding_records,
    valid_existing_records,
)
from codex_plugin_scanner.guard.native_decision_receipt import canonical_receipt_bytes  # noqa: E402

import base64  # noqa: E402


def marker_text(**overrides: object) -> str:
    payload: dict[str, object] = {
        "schema": crypto.CAPTURE_SCHEMA,
        "enabled": True,
        "run_id": RUN_ID,
        "expires_at": NOW + 600,
        "max_records": 16,
        "max_bytes": 64 * 1024,
        "key_id": KEY_ID,
        "capture_key_b64": base64.urlsafe_b64encode(KEY).decode("ascii"),
    }
    payload.update(overrides)
    return json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"


def session_for(**overrides: object) -> crypto.CaptureSession:
    session = crypto.parse_marker(json.loads(marker_text(**overrides)))
    assert session is not None
    return session


def session_json(session: crypto.CaptureSession | None) -> object:
    if session is None:
        return None
    return {
        "run_id": session.run_id,
        "expires_at": session.expires_at,
        "max_records": session.max_records,
        "max_bytes": session.max_bytes,
        "key_id": session.key_id,
        "key_hex": session.key.hex(),
    }


def receipt(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema": "guard-native-hook-decision-receipt.v1",
        "version": 1,
        "authority": "rust",
        "decision_id": "0" * 64,
        "request_id": "sha256:request-1",
        "request_digest": "a" * 64,
        "harness": "codex",
        "event_name": "PreToolUse",
        "payload_kind": "inline",
        "policy_generation": 1,
        "policy_digest": None,
        "rule_digest": None,
        "runtime_identity": None,
        "decision": "allow",
        "model_output_action": "not_applicable",
        "policy_action": "allow",
        "observed_policy_action": None,
        "reason_code": "native_allow",
        "workspace_bound": False,
        "source_ref_external_allowed": False,
        "reviewed_output_sha256": None,
        "observe_mode": False,
        "deadline_budget_ms": 100,
    }
    value.update(overrides)
    if "decision_id" not in overrides:
        value["decision_id"] = hashlib.sha256(canonical_receipt_bytes(value)).hexdigest()
    return value


BINDING = {
    "schema": "guard.native-command-receipt-binding.v1",
    "program_digest": "1" * 64,
    "catalog_digest": "2" * 64,
    "trust_digest": "3" * 64,
    "control_revision": 4,
    "managed_control_revision": 5,
    "control_effective_digest": "6" * 64,
    "observations_digest": "7" * 64,
    "observation_count": 2,
    "uncertainty_count": 1,
}


def json_text(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


# ---------------------------------------------------------------- json section
def json_cases() -> list[dict[str, object]]:
    deep = lambda n: "[" * n + "]" * n  # noqa: E731
    deep_obj = lambda n: '{"a":' * n + "1" + "}" * n  # noqa: E731
    texts = [
        '{"a":1}',
        ' \n{"b":[1,2.5,true,null,"x"]}\t',
        '{"b":1,"a":2}',
        '{"a":1,"a":2}',
        '{"a":NaN}',
        '{"a":Infinity}',
        '{"a":-Infinity}',
        '{"a":1e999}',
        '{"a":1.0}',
        '{"a":1E2}',
        '{"a":1e16}',
        '{"a":1e-7}',
        '{"a":0.1}',
        '{"a":-0}',
        '{"a":-0.0}',
        '{"a":123456789012345678901234567890}',
        '{"a":"é\\u00e9\\ud83d\\ude00"}',
        '{"a":"\\ud800"}',
        '{"é":1,"z":2,"a":3}',
        '{"a":"\\u2028"}',
        '{"a":01}',
        '{"a":1.}',
        '{"a":.5}',
        '{"a":+1}',
        "[1,2]",
        '"x"',
        "1",
        "",
        "{",
        '{"a":1}x',
        '{"a":1} {"b":2}',
        "﻿" + '{"a":1}',
        '{"a":"line\nbreak"}',
        '{"a":"tab\\t"}',
        "{'a':1}",
        '{"a":[' + ",".join(["1"] * 4090) + "]}",
        '{"a":[' + ",".join(["1"] * 4100) + "]}",
        '{"a":' + deep(63) + "}",
        '{"a":' + deep(64) + "}",
        '{"a":' + deep(65) + "}",
        deep_obj(30),
        deep_obj(63),
        deep_obj(64),
        '{"a":"' + "x" * 65530 + '"}',
        '{"a":"' + "x" * 65536 + '"}',
        '{"a":"' + "é" * 30000 + '"}',
        '{"a":"' + "é" * 33000 + '"}',
        '{"a":1,"b":2,"c":3,"d":{"e":[1,2,{"f":null}]}}',
        '{"a":1.5e300}',
        '{"a":12345678901234567890}',
        '{"a":-9223372036854775808}',
        '{"a":0.30000000000000004}',
        '{"a":5e-324}',
        '{"a":1.7976931348623157e308}',
        '{"a":100000000000000000000.0}',
    ]
    cases: list[dict[str, object]] = []
    for text in texts:
        encoded = text.encode("utf-8", errors="surrogatepass")
        parsed = cap._json_object(encoded)
        canonical = None if parsed is None else canonical_json_bytes(parsed)
        if parsed is None or canonical is None:
            object_text = None
        else:
            object_text = canonical.decode("utf-8")
        cases.append(
            {
                "text": text,
                "object": object_text,
                "validated": parsed is not None,
            }
        )
    return cases


# ------------------------------------------------------------- marker section
def marker_cases() -> list[dict[str, object]]:
    base = json.loads(marker_text())
    variants: list[dict[str, object]] = [base]

    def mut(**kw: object) -> dict[str, object]:
        value = dict(base)
        value.update(kw)
        return value

    variants += [
        mut(expires_at=NOW),
        mut(expires_at=NOW + 1),
        mut(expires_at=NOW + 3600),
        mut(expires_at=NOW + 3601),
        mut(expires_at=NOW - 1),
        mut(expires_at=float(NOW + 10)),
        mut(expires_at=True),
        mut(max_records=0),
        mut(max_records=128),
        mut(max_records=129),
        mut(max_records="16"),
        mut(max_bytes=0),
        mut(max_bytes=65536),
        mut(max_bytes=65537),
        mut(run_id=""),
        mut(run_id="-bad"),
        mut(run_id="a" * 64),
        mut(run_id="a" * 65),
        mut(run_id="ok.run:1_2-3"),
        mut(run_id="bad space"),
        mut(key_id="0" * 31),
        mut(key_id="A" * 32),
        mut(key_id=1),
        mut(capture_key_b64=base64.urlsafe_b64encode(b"k" * 31).decode()),
        mut(capture_key_b64=base64.urlsafe_b64encode(b"k" * 33).decode()),
        mut(capture_key_b64=base64.urlsafe_b64encode(KEY).decode().rstrip("=")),
        mut(capture_key_b64=base64.b64encode(bytes([251] * 32)).decode()),
        mut(capture_key_b64=base64.urlsafe_b64encode(bytes([251] * 32)).decode()),
        mut(capture_key_b64=""),
        mut(capture_key_b64=None),
        mut(schema="guard-codex-binding-capture.v1"),
        mut(enabled=False),
        mut(enabled=1),
    ]
    extra = dict(base)
    extra["extra"] = 1
    variants.append(extra)
    missing = dict(base)
    del missing["key_id"]
    variants.append(missing)
    cases = []
    for variant in variants:
        cases.append({"marker": variant, "session": session_json(crypto.parse_marker(variant))})
    return cases


# ----------------------------------------------------------------- hmac section
def hmac_cases() -> list[dict[str, object]]:
    session = session_for()
    cases: list[dict[str, object]] = []
    payloads: list[object] = [
        {"a": 1},
        {"hook_event_name": "PreToolUse", "tool_use_id": "call-1", "tool_input": {"command": "echo é"}},
        {},
        {"z": [1, 2.5, None, True], "a": "x"},
        {"a": float("nan")},
        {"a": "x" * 70000},
        {"a": 1e16},
        {"a": 100000000000000000000.0},
    ]
    for role in ("raw", "forwarded", "row", "other"):
        for payload in payloads:
            expected = crypto.payload_hmac(session, role, payload)
            cases.append({"kind": "payload", "role": role, "payload": payload if "nan" not in str(payload) and len(str(payload)) < 1000 else None, "payload_text": None, "expected": expected})
    # Replace oversized/NaN placeholders with explicit text-driven cases.
    cases = [c for c in cases if c["payload"] is not None or c["role"] == "other" and False]
    rows = [
        {"a": 1, "row_mac": "x"},
        {"a": 1},
        {"schema": "s", "run_id": "r", "n": [1, 2]},
    ]
    for row in rows:
        cases.append({"kind": "row", "row": row, "expected": crypto.row_hmac(session, row)})
    return cases


# --------------------------------------------------------------- receipt section
def receipt_cases() -> list[dict[str, object]]:
    cases: list[dict[str, object]] = []

    def add(value: object) -> None:
        cases.append({"receipt": value, "projection": crypto.receipt_projection(value)})

    good = receipt()
    add(good)
    add(receipt(event_name="PostToolUse", model_output_action="allow_original", payload_kind="source_file_ref"))
    add(receipt(event_name="UserPromptSubmit", prompt_risk_classes=["local_env_read", "exfil_intent"]))
    add(receipt(event_name="UserPromptSubmit", prompt_risk_classes=["exfil_intent", "local_env_read"]))
    add(receipt(event_name="UserPromptSubmit", payload_kind="source_file_ref"))
    add(receipt(event_name="UserPromptSubmit", prompt_risk_classes=[]))
    add(receipt(event_name="PreToolUse", prompt_risk_classes=["local_env_read"]))
    add(receipt(command_extensions=BINDING))
    add(receipt(command_extensions={**BINDING, "control_revision": -1}))
    add(receipt(command_extensions={**BINDING, "extra": 1}))
    add(receipt(command_extensions={**BINDING, "program_digest": "z" * 64}))
    add(receipt(command_extensions="nope"))
    add(receipt(origin_authentication="b" * 64))
    add(receipt(origin_authentication="short"))
    add(receipt(execution_intent_digest="c" * 64))
    add(receipt(business_review_binding="d" * 64))
    add(receipt(policy_digest="e" * 64, rule_digest="f" * 64, runtime_identity="1" * 64, reviewed_output_sha256="2" * 64))
    add(receipt(policy_digest="E" * 64))
    add(receipt(decision="deny", reason_code="native_block", policy_action="block"))
    add(receipt(decision="maybe"))
    add(receipt(policy_action="bogus"))
    add(receipt(policy_action=None, observed_policy_action="review"))
    add(receipt(deadline_budget_ms=None))
    add(receipt(deadline_budget_ms=0))
    add(receipt(deadline_budget_ms=9001))
    add(receipt(deadline_budget_ms=9000))
    add(receipt(deadline_budget_ms=True))
    add(receipt(deadline_budget_ms=1.5))
    add(receipt(policy_generation=0))
    add(receipt(policy_generation=2**63 - 1))
    add(receipt(policy_generation=2**63))
    add(receipt(policy_generation=True))
    add(receipt(workspace_bound="no"))
    add(receipt(observe_mode=1))
    add(receipt(authority="python"))
    add(receipt(schema="x"))
    add(receipt(version=2))
    add(receipt(harness="Codex"))
    add(receipt(harness="a" * 65))
    add(receipt(request_id="Upper"))
    add(receipt(request_id="x" * 256))
    add(receipt(request_id="x" * 257))
    add(receipt(reason_code="x" * 512))
    add(receipt(reason_code="X"))
    add(receipt(event_name="PermissionRequest"))
    add(receipt(payload_kind="weird"))
    add(receipt(decision_id="0" * 64))
    add(receipt(decision_id="A" * 64))
    wrong_id = dict(good)
    wrong_id["request_digest"] = "b" * 64
    add(wrong_id)
    missing = dict(good)
    del missing["reason_code"]
    add(missing)
    extra = dict(good)
    extra["surprise"] = 1
    add(extra)
    add("not a mapping")
    add(None)
    add([])
    return cases


# ----------------------------------------------------------------- fs scenarios
def apply_setup(guard_home: Path, setup: list[list[object]]) -> None:
    for step in setup:
        kind = step[0]
        path = guard_home / str(step[1])
        if kind == "mkdir":
            path.mkdir(parents=True, exist_ok=True)
            os.chmod(path, int(step[2]))  # type: ignore[arg-type]
        elif kind == "write":
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(str(step[2]).encode("utf-8"))
            os.chmod(path, int(step[3]))  # type: ignore[arg-type]
        elif kind == "symlink":
            os.symlink(str(step[2]), path)
        elif kind == "hardlink":
            os.link(guard_home / str(step[2]), path)
        elif kind == "chmod":
            os.chmod(path, int(step[2]))  # type: ignore[arg-type]
        else:
            raise AssertionError(kind)


def normalized_output(path: Path, session: crypto.CaptureSession) -> object:
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8")
    lines = []
    for line in text.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            lines.append({"unparsed": line})
            continue
        sealed = row.get("sealed_receipt") if isinstance(row, dict) else None
        if sealed is not None:
            opened = crypto.open_receipt(session, row, sealed)
            row["sealed_receipt"] = {"opened": opened}
        lines.append(row)
    return {"line_count": len(lines), "rows": lines, "trailing_newline": text.endswith("\n") or text == ""}


def run_scenario(name: str, setup: list[list[object]], ops: list[dict[str, object]], *, marker_overrides: dict[str, object] | None = None, expiry_after: int | None = None) -> dict[str, object]:
    root = Path(tempfile.mkdtemp(prefix="bc-")).resolve()
    try:
        guard_home = root / "home"
        guard_home.mkdir(mode=0o700)
        os.chmod(guard_home, 0o700)
        apply_setup(guard_home, setup)
        results = []
        for op in ops:
            if op["op"] == "bridge":
                result = cap.record_bridge_ingress(
                    guard_home=guard_home,
                    raw_payload=str(op["raw"]),
                    forwarded_payload=op.get("forwarded"),  # type: ignore[arg-type]
                    event_name=str(op["event"]),
                    harness=str(op.get("harness", "codex")),
                )
            else:
                result = cap.record_native_worker(
                    guard_home=guard_home,
                    payload=op["payload"],  # type: ignore[arg-type]
                    harness=str(op.get("harness", "codex")),
                    event_name=str(op["event"]),
                    receipt=op["receipt"],
                )
            results.append(result)
        output = guard_home / "diagnostics" / f"codex-binding-capture.{RUN_ID}.jsonl"
        output_text = output.read_text(encoding="utf-8") if output.exists() else None
        session = session_for(**(marker_overrides or {}))
        return {
            "name": name,
            "setup": setup,
            "ops": ops,
            "results": results,
            "output": normalized_output(output, session),
            "raw_output": output_text,
        }
    finally:
        shutil.rmtree(root, ignore_errors=True)


MARKER_PATH = "diagnostics/codex-binding-capture.v2.json"
OUTPUT_PATH = f"diagnostics/codex-binding-capture.{RUN_ID}.jsonl"


def enabled_setup(marker: str | None = None, *, dir_mode: int = 0o700, marker_mode: int = 0o600) -> list[list[object]]:
    return [
        ["mkdir", "diagnostics", dir_mode],
        ["write", MARKER_PATH, marker if marker is not None else marker_text(), marker_mode],
    ]


PRE = {"hook_event_name": "PreToolUse", "tool_use_id": "call-1", "tool_input": {"command": "echo hi"}}
POST = {"hook_event_name": "PostToolUse", "tool_use_id": "call-2", "tool_response": {"ok": True}}


def bridge(raw: object, event: str = "PreToolUse", forwarded: object = None, harness: str = "codex") -> dict[str, object]:
    op: dict[str, object] = {"op": "bridge", "raw": raw if isinstance(raw, str) else json_text(raw), "event": event, "harness": harness}
    if forwarded is not None:
        op["forwarded"] = forwarded if isinstance(forwarded, str) else json_text(forwarded)
    return op


def native(payload: object, event: str = "PreToolUse", rcpt: object = None, harness: str = "codex") -> dict[str, object]:
    return {"op": "native", "payload": payload, "event": event, "receipt": rcpt if rcpt is not None else receipt(event_name=event), "harness": harness}


def scenarios() -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    add = out.append
    ok = enabled_setup()
    add(run_scenario("bridge_basic", ok, [bridge(PRE)]))
    add(run_scenario("bridge_post_event", ok, [bridge(POST, "PostToolUse")]))
    add(run_scenario("bridge_event_aliases", ok, [bridge(PRE, "pre_tool_use"), bridge({**PRE, "tool_use_id": "c2"}, "BeforeShellExecution"), bridge(POST, "after-shell-execution")]))
    add(run_scenario("bridge_permission_request", ok, [bridge({"hook_event_name": "PermissionRequest"}, "PermissionRequest")]))
    add(run_scenario("bridge_user_prompt", ok, [bridge({"hook_event_name": "UserPromptSubmit", "prompt": "hello"}, "UserPromptSubmit")]))
    add(run_scenario("bridge_unmanaged_event", ok, [bridge(PRE, "Stop")]))
    add(run_scenario("bridge_empty_event", ok, [bridge(PRE, "")]))
    add(run_scenario("bridge_event_with_space", ok, [bridge(PRE, "Pre Tool")]))
    add(run_scenario("bridge_event_non_ascii", ok, [bridge(PRE, "PreTooléUse")]))
    add(run_scenario("bridge_long_event", ok, [bridge(PRE, "P" * 65)]))
    add(run_scenario("bridge_non_codex_harness", ok, [bridge(PRE, harness="claude")]))
    add(run_scenario("bridge_missing_tool_use_id", ok, [bridge({"hook_event_name": "PreToolUse"})]))
    add(run_scenario("bridge_unsupported_tool_use_id", ok, [bridge({**PRE, "tool_use_id": "bad id!"}), bridge({**PRE, "tool_use_id": 5}), bridge({**PRE, "tool_use_id": "é"}), bridge({**PRE, "tool_use_id": "x" * 257}), bridge({**PRE, "tool_use_id": ""})]))
    add(run_scenario("bridge_tool_use_id_max", ok, [bridge({**PRE, "tool_use_id": "x" * 256})]))
    add(run_scenario("bridge_transport_fields_stripped", ok, [bridge({**PRE, "guard_remaining_seconds": 5, "guard_remaining_ms": 5000, "hook_env": {"A": "1"}})]))
    add(run_scenario("bridge_forwarded_differs", ok, [bridge(PRE, forwarded={**PRE, "stamped": "yes"})]))
    add(run_scenario("bridge_forwarded_invalid", ok, [bridge(PRE, forwarded="not json")]))
    add(run_scenario("bridge_forwarded_array", ok, [bridge(PRE, forwarded="[1]")]))
    add(run_scenario("bridge_raw_invalid", ok, [bridge("not json")]))
    add(run_scenario("bridge_raw_duplicate_keys", ok, [bridge('{"tool_use_id":"a","tool_use_id":"b"}')]))
    add(run_scenario("bridge_raw_oversize", ok, [bridge('{"a":"' + "x" * 65536 + '"}')]))
    add(run_scenario("bridge_raw_unicode", ok, [bridge({**PRE, "tool_input": {"command": "echo é\U0001f600"}})]))
    add(run_scenario("bridge_raw_float", ok, [bridge('{"hook_event_name":"PreToolUse","tool_use_id":"f1","n":1e16,"m":1.0,"k":0.1}')]))
    add(run_scenario("bridge_two_rows", ok, [bridge(PRE), bridge({**PRE, "tool_use_id": "call-9"})]))
    add(run_scenario("bridge_no_marker", [["mkdir", "diagnostics", 0o700]], [bridge(PRE)]))
    add(run_scenario("bridge_no_diagnostics_dir", [], [bridge(PRE)]))
    add(run_scenario("bridge_diag_dir_mode", enabled_setup(dir_mode=0o755), [bridge(PRE)]))
    add(run_scenario("bridge_marker_mode", enabled_setup(marker_mode=0o644), [bridge(PRE)]))
    add(run_scenario("bridge_marker_symlink", [["mkdir", "diagnostics", 0o700], ["write", "real.json", marker_text(), 0o600], ["symlink", "diagnostics/real-link", "../real.json"]] + [["symlink", MARKER_PATH, "../real.json"]], [bridge(PRE)]))
    add(run_scenario("bridge_diag_dir_symlink", [["mkdir", "elsewhere", 0o700], ["write", "elsewhere/codex-binding-capture.v2.json", marker_text(), 0o600], ["symlink", "diagnostics", "elsewhere"]], [bridge(PRE)]))
    add(run_scenario("bridge_marker_hardlinked_ok", enabled_setup() + [["hardlink", "diagnostics/marker-copy", MARKER_PATH]], [bridge(PRE)]))
    add(run_scenario("bridge_marker_expired", enabled_setup(marker_text(expires_at=NOW)), [bridge(PRE)], marker_overrides={"expires_at": NOW + 600}))
    add(run_scenario("bridge_marker_too_far", enabled_setup(marker_text(expires_at=NOW + 3601)), [bridge(PRE)]))
    add(run_scenario("bridge_marker_bad_json", enabled_setup("not json"), [bridge(PRE)]))
    add(run_scenario("bridge_marker_oversize", enabled_setup(marker_text() + " " * 5000), [bridge(PRE)]))
    add(run_scenario("bridge_marker_extra_field", enabled_setup(marker_text(extra=1)), [bridge(PRE)]))
    add(run_scenario("bridge_max_records_1", enabled_setup(marker_text(max_records=1)), [bridge(PRE), bridge({**PRE, "tool_use_id": "z"})], marker_overrides={"max_records": 1}))
    add(run_scenario("bridge_max_bytes_small", enabled_setup(marker_text(max_bytes=700)), [bridge(PRE), bridge({**PRE, "tool_use_id": "z"}), bridge({**PRE, "tool_use_id": "y"})], marker_overrides={"max_bytes": 700}))
    add(run_scenario("bridge_max_bytes_tiny", enabled_setup(marker_text(max_bytes=64)), [bridge(PRE)], marker_overrides={"max_bytes": 64}))
    add(run_scenario("bridge_output_symlink", enabled_setup() + [["write", "diagnostics/other", "", 0o600], ["symlink", OUTPUT_PATH, "other"]], [bridge(PRE)]))
    add(run_scenario("bridge_output_mode", enabled_setup() + [["write", OUTPUT_PATH, "", 0o644]], [bridge(PRE)]))
    add(run_scenario("bridge_output_hardlinked", enabled_setup() + [["write", "diagnostics/other", "", 0o600], ["hardlink", OUTPUT_PATH, "diagnostics/other"]], [bridge(PRE)]))
    add(run_scenario("bridge_output_garbage", enabled_setup() + [["write", OUTPUT_PATH, "garbage\n", 0o600]], [bridge(PRE)]))
    add(run_scenario("bridge_output_no_trailing_newline", enabled_setup() + [["write", OUTPUT_PATH, "{}", 0o600]], [bridge(PRE)]))
    add(run_scenario("bridge_output_empty_existing", enabled_setup() + [["write", OUTPUT_PATH, "", 0o600]], [bridge(PRE)]))

    # Python-sealed seed files: native rows then replay with additional ops.
    pair = run_scenario("native_pair", ok, [bridge(PRE), native(PRE)])
    add(pair)
    add(run_scenario("native_basic", ok, [native(PRE)]))
    add(run_scenario("native_post", ok, [native(POST, "PostToolUse")]))
    add(run_scenario("native_prompt", ok, [native({"hook_event_name": "UserPromptSubmit", "prompt": "p"}, "UserPromptSubmit", receipt(event_name="UserPromptSubmit", prompt_risk_classes=["local_env_read"]))]))
    add(run_scenario("native_command_extensions", ok, [native(PRE, rcpt=receipt(command_extensions=BINDING))]))
    add(run_scenario("native_non_codex", ok, [native(PRE, harness="claude")]))
    add(run_scenario("native_event_mismatch", ok, [native(PRE, "PostToolUse", receipt(event_name="PreToolUse"))]))
    add(run_scenario("native_receipt_harness_mismatch", ok, [native(PRE, rcpt=receipt(harness="other"))]))
    add(run_scenario("native_invalid_receipt", ok, [native(PRE, rcpt=receipt(decision_id="0" * 64))]))
    add(run_scenario("native_receipt_not_mapping", ok, [native(PRE, rcpt="x")]))
    add(run_scenario("native_payload_float", ok, [native({**PRE, "n": 1.5, "m": 2.0})]))
    add(run_scenario("native_payload_oversize", ok, [native({**PRE, "big": "x" * 70000})]))
    add(run_scenario("native_missing_tool_use_id", ok, [native({"hook_event_name": "PreToolUse"})]))
    add(run_scenario("native_unmanaged_event", ok, [native(PRE, "Stop", receipt(event_name="PreToolUse"))]))
    add(run_scenario("native_receipt_projection_drops", ok, [native(PRE, rcpt=receipt(origin_authentication="b" * 64, business_review_binding="d" * 64))]))
    add(run_scenario("mixed_sequence", ok, [bridge(PRE), native(PRE), bridge(POST, "PostToolUse"), native(POST, "PostToolUse"), native({"hook_event_name": "PreToolUse"})]))

    seed = str(pair["raw_output"])
    add(run_scenario("seed_python_sealed_then_bridge", ok + [["write", OUTPUT_PATH, seed, 0o600]], [bridge({**PRE, "tool_use_id": "next"})]))
    add(run_scenario("seed_python_sealed_then_native", ok + [["write", OUTPUT_PATH, seed, 0o600]], [native({**PRE, "tool_use_id": "next"})]))
    add(run_scenario("seed_wrong_key", enabled_setup(marker_text(key_id="f" * 32)) + [["write", OUTPUT_PATH, seed, 0o600]], [bridge(PRE)], marker_overrides={"key_id": "f" * 32}))
    tampered = seed.replace('"tool_use_id":"call-1"', '"tool_use_id":"call-X"', 1)
    add(run_scenario("seed_tampered_row", ok + [["write", OUTPUT_PATH, tampered, 0o600]], [bridge(PRE)]))
    add(run_scenario("seed_two_lines_cap", enabled_setup(marker_text(max_records=2)) + [["write", OUTPUT_PATH, seed, 0o600]], [bridge(PRE)], marker_overrides={"max_records": 2}))
    return out


# -------------------------------------------------------------------- join cases
def join_cases(scenario_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    session = session_for()
    cases: list[dict[str, object]] = []

    def rows_of(name: str) -> list[dict[str, object]]:
        for scenario in scenario_rows:
            if scenario["name"] == name:
                text = scenario["raw_output"]
                return [json.loads(line) for line in str(text).splitlines()]
        raise KeyError(name)

    def add(name: str, records: list[object], with_session: bool = True, **session_overrides: object) -> None:
        active = session_for(**session_overrides) if with_session else None
        result = join_binding_records(records, capture_session=active)
        cases.append(
            {
                "name": name,
                "records": records,
                "session_overrides": session_overrides if with_session else None,
                "session": with_session,
                "result": json.loads(json.dumps(result)),
            }
        )

    pair = rows_of("native_pair")
    add("pair_bound", pair)
    add("pair_no_session", pair, with_session=False)
    add("pair_reversed", list(reversed(pair)))
    add("bridge_only", [pair[0]])
    add("native_only", [pair[1]])
    add("duplicate_bridge", [pair[0], pair[0], pair[1]])
    add("duplicate_native", [pair[0], pair[1], pair[1]])
    mismatch = rows_of("mixed_sequence")
    add("mixed_sequence", mismatch)
    add("not_object", ["x", 1, None, pair[0]])
    add("empty", [])
    tampered = json.loads(json.dumps(pair))
    tampered[0]["forwarded_payload_hmac_sha256"] = "0" * 64
    add("tampered_row_mac", tampered)
    extra = json.loads(json.dumps(pair))
    extra[0]["extra"] = 1
    add("extra_field", extra)
    wrong_run = json.loads(json.dumps(pair))
    wrong_run[0]["run_id"] = "other"
    add("wrong_run", wrong_run)
    add("expired_session", pair, expires_at=NOW + 1)
    add("key_mismatch", pair, key_id="e" * 32)
    over = [pair[0]] * 17
    add("record_limit", over)
    add("record_limit_session_small", pair + pair, max_records=3)
    add("aggregate_limit", pair, max_bytes=300)
    # unmatched forwarded fingerprints
    bridge_forwarded = rows_of("bridge_forwarded_differs")
    add("bridge_forwarded_differs", bridge_forwarded)
    for name in ("bridge_missing_tool_use_id", "bridge_unsupported_tool_use_id", "bridge_permission_request", "bridge_user_prompt", "bridge_event_aliases", "native_post", "native_prompt", "native_missing_tool_use_id"):
        rows = rows_of(name)
        add(name, rows)
    # forged mismatch between native and bridge forwarded fingerprints
    scenario = rows_of("native_pair")
    other = rows_of("native_basic")
    add("two_runs_native_mixed", [pair[0], other[0]])

    # valid_existing_records
    vcases = []
    seed_text = "".join(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n" for r in pair)
    for name, raw, ovr in (
        ("empty", "", {}),
        ("valid", seed_text, {}),
        ("no_newline", seed_text.rstrip("\n"), {}),
        ("over_records", seed_text, {"max_records": 1}),
        ("over_bytes", seed_text, {"max_bytes": 300}),
        ("garbage", "x\n", {}),
        ("blank_line", "\n", {}),
        ("wrong_run", seed_text, {"run_id": "other"}),
    ):
        active = session_for(**ovr) if not (name == "wrong_run") else session_for()
        run_id = "other" if name == "wrong_run" else RUN_ID
        value = valid_existing_records(raw.encode(), run_id=run_id, capture_session=active)
        vcases.append({"name": name, "raw": raw, "session_overrides": ovr, "run_id": run_id, "count": value})
    cases_out = {"joins": cases, "existing": vcases}
    return cases_out  # type: ignore[return-value]


def main() -> None:
    scenario_list = scenarios()
    vectors = {
        "now": NOW,
        "key_hex": KEY.hex(),
        "key_id": KEY_ID,
        "run_id": RUN_ID,
        "json": json_cases(),
        "markers": marker_cases(),
        "hmac": hmac_cases(),
        "receipts": receipt_cases(),
        "scenarios": scenario_list,
        "join": join_cases(scenario_list),
    }
    target = Path(__file__).with_name("vectors.json")
    target.write_text(json.dumps(vectors, indent=1, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")
    time.time = _real_time  # type: ignore[assignment]
    sys.stderr.write(f"wrote {target}\n")


if __name__ == "__main__":
    main()
