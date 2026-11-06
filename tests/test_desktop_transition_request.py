"""Desktop activation requests contain receipts, never caller-provided inverses."""

import argparse
import hashlib
import io
import json
import sys
import time
import uuid
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import desktop_runtime_transition as command
from codex_plugin_scanner.guard.cli.desktop_transition_request import REQUEST_SCHEMA, load_desktop_transition_request
from codex_plugin_scanner.guard.runtime_transition import TransitionError


@pytest.fixture
def transition_request(tmp_path):
    root = tmp_path / "core"
    root.mkdir(mode=0o700)
    digests = {}
    for side in ("previous", "candidate"):
        executable = root / side
        executable.write_bytes(side.encode())
        executable.chmod(0o700)
        digests["predecessor" if side == "previous" else side] = hashlib.sha256(side.encode()).hexdigest()
    shim = root / "current-hol-guard"
    shim.write_bytes(b"fixture stable launcher")
    shim.chmod(0o700)
    previous = {
        "schema": "hol-guard-core-install.v1",
        "version": "3.15.2",
        "sourceCommit": "a" * 40,
        "target": "fixture",
        "relativePath": "previous",
        "sha256": digests["predecessor"],
        "installedAt": "2026-10-01T00:00:00Z",
    }
    pointer = root / "current.json"
    pointer.write_text(json.dumps(previous))
    pointer.chmod(0o600)
    candidate = {**previous, "relativePath": "candidate"}
    receipt = {
        "format": "onedir-zip",
        "archiveSha256": "b" * 64,
        "bootstrapSchema": "bootstrap.v2",
        "minimumDesktopVersion": "3.0.117",
    }
    identity = [
        candidate["version"],
        candidate["sourceCommit"],
        candidate["target"],
        "onedir-zip",
        "b" * 64,
        receipt["bootstrapSchema"],
        receipt["minimumDesktopVersion"],
        digests["candidate"],
    ]
    receipt["generation"] = hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()
    candidate["artifact"] = receipt
    operation_id = str(uuid.uuid4())
    context = HarnessContext(tmp_path, None, tmp_path / "guard")
    payload = {
        "schema": REQUEST_SCHEMA,
        "operation_id": operation_id,
        "guard_home": str(context.guard_home),
        "home_dir": str(tmp_path),
        "managed_root": str(root),
        "previous_pointer_sha256": hashlib.sha256(pointer.read_bytes()).hexdigest(),
        "candidate_pointer": candidate,
        "executable_digests": digests,
        "native_runtimes": {},
    }
    private = tmp_path / "request"
    private.mkdir(mode=0o700)
    path = private / "request.json"
    path.write_text(json.dumps(payload))
    path.chmod(0o600)
    return path, payload, context


def load(request):
    path, payload, context = request
    path.write_text(json.dumps(payload))
    return load_desktop_transition_request(
        path,
        context=context,
        operation_id=payload["operation_id"],
        deadline_epoch=time.time() + 20,
        deadline_monotonic=time.monotonic() + 20,
        request_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
    )


def test_equal_version_legacy_to_onedir_request_derives_exact_selection(transition_request):
    path, payload, _ = transition_request
    before = (Path(payload["managed_root"]) / "current.json").read_bytes()
    prepared = load(transition_request)
    assert prepared.predecessor["version"] == prepared.candidate["version"]
    assert prepared.predecessor["format"] == "onefile" and prepared.candidate["format"] == "onedir-zip"
    assert prepared.candidate["sha256"] == "b" * 64
    assert prepared.executable_digests["candidate"] != prepared.candidate["sha256"]
    assert prepared.selection_files[0].before == before
    assert json.loads(prepared.selection_files[0].after) == payload["candidate_pointer"]
    assert prepared.selection_dependencies[0].expected_digest is not None
    assert prepared.selection_files[0].path.read_bytes() == before
    assert path.exists()


@pytest.mark.parametrize(
    "fault,reason",
    [
        ("inverse", "transition_request_invalid"),
        ("operation", "plan_context_mismatch"),
        ("home", "plan_context_mismatch"),
        ("relative", "selection_path_invalid"),
        ("generation", "artifact_generation_changed"),
        ("previous", "selection_generation_changed"),
        ("root", "selection_path_invalid"),
        ("missing_receipt", "selection_receipt_missing"),
        ("private", "transition_request_unavailable"),
    ],
)
def test_request_refuses_untrusted_context_and_receipts(transition_request, fault, reason):
    path, payload, context = transition_request
    if fault == "inverse":
        payload["files"] = [{"path": "foreign", "before": "caller supplied inverse"}]
    elif fault == "operation":
        payload["operation_id"] = str(uuid.uuid4())
        path.write_text(json.dumps(payload))
        with pytest.raises(TransitionError, match=reason):
            load_desktop_transition_request(
                path,
                context=context,
                operation_id=str(uuid.uuid4()),
                deadline_epoch=time.time() + 10,
                deadline_monotonic=time.monotonic() + 10,
                request_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            )
        return
    elif fault == "home":
        payload["home_dir"] = str(context.home_dir / "foreign")
    elif fault == "relative":
        payload["candidate_pointer"]["relativePath"] = "../outside"
    elif fault == "generation":
        payload["candidate_pointer"]["artifact"]["generation"] = "f" * 64
    elif fault == "previous":
        payload["previous_pointer_sha256"] = "f" * 64
    elif fault == "root":
        payload["managed_root"] = str(context.home_dir.parent)
    elif fault == "missing_receipt":
        del payload["candidate_pointer"]["artifact"]
    elif fault == "private":
        path.chmod(0o644)
    with pytest.raises(TransitionError, match=reason):
        load(transition_request)


def test_activation_refuses_source_process_and_consumes_factor_before_any_launch(transition_request, monkeypatch):
    from codex_plugin_scanner.guard.store import GuardStore

    _, payload, context = transition_request
    store = GuardStore(context.guard_home)
    monkeypatch.setenv("HOL_GUARD_DESKTOP", "1")
    monkeypatch.setenv("HOL_GUARD_APPROVAL_PASSWORD", "fixture-only-unused-factor")
    monkeypatch.setattr(command, "lifecycle_authority_home", lambda *args, **kwargs: context.guard_home)
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    args = argparse.Namespace(
        desktop_command="transition-activate",
        operation_id=payload["operation_id"],
        deadline_epoch=time.time() + 10,
        request=str(transition_request[0]),
    )
    output = io.StringIO()
    assert command.run_desktop_runtime_transition(args, context=context, store=store, output_stream=output) == 1
    assert json.loads(output.getvalue())["reason_code"] == "packaged_transition_runtime_required"
    import os

    assert "HOL_GUARD_APPROVAL_PASSWORD" not in os.environ
    assert not (context.guard_home / "managed/runtime-transition.json").exists()


@pytest.mark.parametrize("fault", ["duplicate", "nonfinite"])
def test_request_refuses_ambiguous_json(transition_request, fault):
    path, payload, context = transition_request
    raw = json.dumps(payload)
    suffix = ', "schema": "duplicate"}' if fault == "duplicate" else ', "foreign": NaN}'
    raw = raw[:-1] + suffix
    path.write_text(raw)
    with pytest.raises(TransitionError, match="transition_request_invalid"):
        load_desktop_transition_request(
            path,
            context=context,
            operation_id=payload["operation_id"],
            deadline_epoch=time.time() + 10,
            deadline_monotonic=time.monotonic() + 10,
            request_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        )


def test_request_is_bound_to_desktop_staged_digest(transition_request):
    path, payload, context = transition_request
    expected = hashlib.sha256(path.read_bytes()).hexdigest()
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(TransitionError, match="transition_request_generation_changed"):
        load_desktop_transition_request(
            path,
            context=context,
            operation_id=payload["operation_id"],
            deadline_epoch=time.time() + 10,
            deadline_monotonic=time.monotonic() + 10,
            request_sha256=expected,
        )


def test_activation_parser_requires_request_and_defers_generic_gate(transition_request):
    from codex_plugin_scanner.cli import _build_parser
    from codex_plugin_scanner.guard.cli.commands_lifecycle_gate import lifecycle_gate_requirement

    path, payload, _ = transition_request
    args = _build_parser("hol-guard", program_mode="hol-guard").parse_args(
        [
            "desktop",
            "transition-activate",
            "--json",
            "--operation-id",
            payload["operation_id"],
            "--deadline-epoch",
            "1",
            "--request",
            str(path),
            "--request-sha256",
            "a" * 64,
        ]
    )
    assert args.desktop_command == "transition-activate" and args.request == str(path)
    assert lifecycle_gate_requirement(args) is None  # The prepared exact subject is not available at parsing.


def test_finalize_parser_requires_generation_and_has_no_forward_grant(transition_request):
    from codex_plugin_scanner.cli import _build_parser
    from codex_plugin_scanner.guard.cli.commands_lifecycle_gate import lifecycle_gate_requirement

    _, payload, _ = transition_request
    parser = _build_parser("hol-guard", program_mode="hol-guard")
    argv = [
        "desktop",
        "transition-finalize",
        "--json",
        "--operation-id",
        payload["operation_id"],
        "--deadline-epoch",
        "1",
    ]
    with pytest.raises(SystemExit) as missing:
        parser.parse_args(argv)
    assert missing.value.code == 2
    args = parser.parse_args([*argv, "--artifact-generation", "a" * 64])
    assert args.desktop_command == "transition-finalize"
    assert args.artifact_generation == "a" * 64
    assert lifecycle_gate_requirement(args) is None
