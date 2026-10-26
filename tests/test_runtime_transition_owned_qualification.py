from __future__ import annotations

import argparse
import io
import json
import time
import uuid
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import runtime_transition_owned_qualification as qualification
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import desktop_owned_qualification as cli
from codex_plugin_scanner.guard.codex_hook_file_integrity import CodexHookIntegrityError
from codex_plugin_scanner.guard.daemon.live_identity import DaemonArtifactBinding
from codex_plugin_scanner.guard.native_runtime import NativeRuntimeIdentity
from codex_plugin_scanner.guard.runtime_transition import TransitionError
from codex_plugin_scanner.guard.runtime_transition_admission import NativeProtectionAdmission, _seal_verified_admission
from codex_plugin_scanner.guard.runtime_transition_native_capture import OwnedNativeCandidate, ProcessSnapshot


@pytest.fixture
def enrolled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    home = tmp_path / "home"
    home.mkdir()
    guard = tmp_path / "guard"
    guard.mkdir(mode=0o700)
    context = HarnessContext(home, None, guard, {})
    config = home / ".codex" / "config.toml"
    rows = [
        {"harness": "codex", "active": True, "workspace": None, "manifest": {"managed_hook_config_path": str(config)}}
    ]

    class Store:
        guard_home = guard

        def list_managed_installs(self):
            return rows

    store = Store()
    binding = DaemonArtifactBinding(tmp_path / "hol-guard", "a" * 64, "3.12.3")
    identity = NativeRuntimeIdentity(tmp_path / "hol-guard-runtime", 6, 123, "b" * 64)
    owner = ProcessSnapshot(100, 1, 501, "main", binding.executable)
    native = ProcessSnapshot(101, 100, 501, "native", identity.path)
    candidate = OwnedNativeCandidate(identity, owner, (native,), ())
    captures, observations = [], []

    def capture(*args, **kwargs):
        captures.append((args, kwargs))
        return candidate

    def observe(**kwargs):
        observations.append(kwargs)
        return _seal_verified_admission(
            NativeProtectionAdmission(
                kwargs["operation_id"],
                kwargs["artifact_generation"],
                kwargs["expected_runtime"],
                1,
                "c" * 64,
                {"decision": "allow"},
                {"decision": "deny"},
                guard,
                time.monotonic(),
                installed_hook_evidence={"harness": "codex"},
            )
        )

    monkeypatch.setattr(qualification, "capture_owned_native_candidate", capture)
    monkeypatch.setattr(qualification, "observe_configured_codex_hook", observe)
    return context, store, binding, candidate, rows, captures, observations


def run(enrolled, **overrides):
    context, store, binding, *_ = enrolled
    values = dict(
        operation_id=str(uuid.uuid4()),
        artifact_generation="d" * 64,
        context=context,
        store=store,
        expected_artifact=binding,
        deadline_monotonic=time.monotonic() + 2,
    )
    values.update(overrides)
    return qualification.qualify_owned_codex_native(**values)


def test_capture_receipts_and_recapture_share_original_deadline(enrolled):
    *_, captures, observations = enrolled
    deadline = time.monotonic() + 2
    result = run(enrolled, deadline_monotonic=deadline)
    assert result.candidate == enrolled[3]
    assert len(captures) == 2 and len(observations) == 1
    assert all(kwargs["deadline_monotonic"] == deadline for _, kwargs in captures)
    assert observations[0]["deadline_monotonic"] == deadline
    assert observations[0]["artifact_binding"] == enrolled[2]
    assert observations[0]["receipt_store"] is enrolled[1]
    assert observations[0]["config_path"] == enrolled[0].home_dir / ".codex" / "config.toml"


@pytest.mark.parametrize("fault", ["additional_harness", "inactive", "duplicate", "missing_config", "workspace"])
def test_invalid_inventory_never_captures_or_observes(enrolled, fault):
    *_, rows, captures, observations = enrolled
    if fault == "additional_harness":
        rows.append({"harness": "claude", "active": True})
    elif fault == "inactive":
        rows[0]["active"] = False
    elif fault == "duplicate":
        rows.append(rows[0].copy())
    elif fault == "missing_config":
        rows[0]["manifest"] = {}
    else:
        rows[0]["workspace"] = "relative"
    with pytest.raises(TransitionError):
        run(enrolled)
    assert not captures and not observations


@pytest.mark.parametrize("fault", ["daemon", "binary", "inventory"])
def test_change_after_receipts_refuses_qualification(enrolled, monkeypatch, fault):
    _, _, _, candidate, rows, _, _ = enrolled
    captures = 0

    def capture(*args, **kwargs):
        nonlocal captures
        captures += 1
        if captures == 2:
            if fault == "daemon":
                return replace(candidate, daemon=replace(candidate.daemon, start_token="reused"))
            if fault == "binary":
                return replace(candidate, identity=replace(candidate.identity, sha256="e" * 64))
            rows[0]["workspace"] = "/changed"
        return candidate

    monkeypatch.setattr(qualification, "capture_owned_native_candidate", capture)
    with pytest.raises(TransitionError, match="generation_changed"):
        run(enrolled)


def test_unsealed_observation_never_qualifies(enrolled, monkeypatch):
    monkeypatch.setattr(qualification, "observe_configured_codex_hook", lambda **kwargs: {})
    with pytest.raises(TransitionError, match="functional_proof_missing"):
        run(enrolled)


def test_expired_deadline_never_captures(enrolled):
    with pytest.raises(TransitionError, match="deadline"):
        run(enrolled, deadline_monotonic=time.monotonic() - 1)
    assert not enrolled[-2] and not enrolled[-1]


def cli_args(enrolled):
    binding = enrolled[2]
    return argparse.Namespace(
        desktop_command="qualify-owned",
        operation_id=str(uuid.uuid4()),
        artifact_generation="d" * 64,
        deadline_epoch=time.time() + 2,
        daemon_executable=str(binding.executable),
        daemon_executable_sha256=binding.executable_sha256,
        daemon_package_version=binding.package_version,
    )


def test_cli_returns_owned_qualification_not_replay_authority(enrolled):
    args = cli_args(enrolled)
    output = io.StringIO()
    assert cli.run_desktop_owned_qualification(args, context=enrolled[0], store=enrolled[1], output_stream=output) == 0
    document = json.loads(output.getvalue())
    assert document["qualified"] is True
    assert document["schema"] == cli.OWNED_QUALIFICATION_SCHEMA
    assert document["daemon_artifact"] == {
        "path": args.daemon_executable,
        "sha256": args.daemon_executable_sha256,
        "version": args.daemon_package_version,
    }
    assert document["native_admission"]["operation_id"] == args.operation_id
    assert "_seal" not in output.getvalue() and "grant" not in document


def test_cli_caps_observation_output_without_partial_proof(enrolled, monkeypatch):
    result = run(enrolled)
    result.admission.allow_receipt["padding"] = "x" * cli.MAX_OWNED_QUALIFICATION_BYTES
    _seal_verified_admission(result.admission)
    monkeypatch.setattr(cli, "qualify_owned_codex_native", lambda **kwargs: result)
    output = io.StringIO()
    assert (
        cli.run_desktop_owned_qualification(
            cli_args(enrolled), context=enrolled[0], store=enrolled[1], output_stream=output
        )
        == 2
    )
    document = json.loads(output.getvalue())
    assert document["reason_code"] == "owned_qualification_capacity"
    assert document["qualified"] is False and "native_admission" not in document
    assert len(output.getvalue().encode()) <= cli.MAX_OWNED_QUALIFICATION_BYTES


@pytest.mark.parametrize(
    "failure,reason",
    [
        (TransitionError("native_capture_missing"), "native_capture_missing"),
        (CodexHookIntegrityError("codex_hook_manifest_missing", "secret-shaped detail"), "codex_hook_manifest_missing"),
        (TimeoutError("secret-shaped detail"), "owned_qualification_deadline"),
    ],
)
def test_cli_preserves_typed_cause_without_partial_proof(enrolled, monkeypatch, failure, reason):
    def refuse(**kwargs):
        raise failure

    monkeypatch.setattr(cli, "qualify_owned_codex_native", refuse)
    output = io.StringIO()
    assert (
        cli.run_desktop_owned_qualification(
            cli_args(enrolled), context=enrolled[0], store=enrolled[1], output_stream=output
        )
        == 2
    )
    document = json.loads(output.getvalue())
    assert document["reason_code"] == reason and document["qualified"] is False
    assert "native_admission" not in document and "daemon_artifact" not in document
    assert "secret-shaped" not in output.getvalue()


def test_hidden_parser_and_dispatch_preserve_exact_filters(enrolled):
    from codex_plugin_scanner.cli import _build_parser
    from codex_plugin_scanner.guard.cli.commands_dispatch_desktop import _run_guard_desktop_command
    from codex_plugin_scanner.guard.cli.commands_lifecycle_gate import lifecycle_gate_requirement

    args = cli_args(enrolled)
    parser = _build_parser("hol-guard", program_mode="guard")
    parsed = parser.parse_args(
        [
            "desktop",
            "qualify-owned",
            "--json",
            "--operation-id",
            args.operation_id,
            "--artifact-generation",
            args.artifact_generation,
            "--deadline-epoch",
            str(args.deadline_epoch),
            "--daemon-executable",
            args.daemon_executable,
            "--daemon-executable-sha256",
            args.daemon_executable_sha256,
            "--daemon-package-version",
            args.daemon_package_version,
        ]
    )
    assert lifecycle_gate_requirement(parsed) is None
    output = io.StringIO()
    assert _run_guard_desktop_command(parsed, context=enrolled[0], store=enrolled[1], output_stream=output) == 0
    assert json.loads(output.getvalue())["qualified"] is True
