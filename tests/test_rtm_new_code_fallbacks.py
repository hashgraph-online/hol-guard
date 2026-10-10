"""Cover resident-fallback and payload-coercion branches added on this branch.

These are the fail-closed paths Sonar marks uncovered: malformed native
payloads, missing capabilities, and digest mismatches must not be treated as
success.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import local_supply_chain, native_package_authority
from codex_plugin_scanner.guard.approval_gate import (
    _config_from_wire,
    _grant_from_wire,
    input_from_mapping,
)
from codex_plugin_scanner.guard.native_policy_snapshot_publisher_transport import (
    _stamp_runtime_program_digest,
)
from codex_plugin_scanner.guard.runtime.package_intent_common import PackageIntent

DIGEST = "a" * 64
OTHER = "b" * 64


def _intent_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "package_manager": "npm",
        "intent_kind": "install",
        "redacted_command": "npm install left-pad",
        "targets": [
            {"ecosystem": "npm", "package_name": "left-pad", "raw_spec": "left-pad"},
            "not-a-target",
            {"ecosystem": "", "package_name": "dropped"},
        ],
        "manifest_paths": ["package.json", 1],
        "local_executions": [
            {
                "manager_name": "npm",
                "manager": {"status": "weird", "path": "npm", "resolved_path": 3},
                "manifests": [{"status": "available", "path": "package.json"}, "skip"],
                "typescript_launch": {"status": "unknown", "schema_version": "nope", "reasons": ["x", 1]},
            },
            "skip",
        ],
    }
    payload.update(overrides)
    return payload


def test_package_intent_from_dict_rejects_incomplete_payloads() -> None:
    with pytest.raises(ValueError, match="package_manager"):
        PackageIntent.from_dict({"intent_kind": "install"})
    with pytest.raises(ValueError, match="intent_kind"):
        PackageIntent.from_dict({"package_manager": "npm", "intent_kind": "remove"})


def test_package_intent_from_dict_coerces_malformed_collections() -> None:
    intent = PackageIntent.from_dict(_intent_payload(command_tokens="not-a-list"))
    assert intent.command_tokens == ("npm", "install", "left-pad")
    assert intent.targets[0].package_name == "left-pad"
    assert len(intent.targets) == 1
    assert intent.manifest_paths == ("package.json",)
    execution = intent.local_executions[0]
    assert execution.manager is not None
    assert execution.manager.status == "missing"
    assert execution.manager.resolved_path is None
    assert execution.typescript_launch is not None
    assert execution.typescript_launch.status == "incomplete"
    assert execution.typescript_launch.schema_version == 0
    assert execution.typescript_launch.reasons == ("x",)

    empty = PackageIntent.from_dict(_intent_payload(targets="nope", local_executions=None, manifest_paths=None))
    assert empty.targets == ()
    assert empty.local_executions == ()
    assert empty.manifest_paths == ()


def test_approval_wire_helpers_reject_incomplete_payloads() -> None:
    assert _grant_from_wire(["not", "a", "dict"]) is None
    assert _grant_from_wire({"grant_id": "g"}) is None
    assert _config_from_wire("nope") is None
    assert _config_from_wire({}) is None
    assert input_from_mapping(["nope"]) is None
    parsed = input_from_mapping(
        {
            "approval_password": "secret",
            "approval_gate": {"totp_code": "123456", "current_password": "newer"},
        }
    )
    assert parsed is not None
    assert parsed.password == "newer"
    assert parsed.totp_code == "123456"


def _status(**overrides: object) -> SimpleNamespace:
    identity = SimpleNamespace(path=Path("/tmp/hol-guard-runtime"), sha256=DIGEST)
    capabilities = SimpleNamespace(features=["resident-protocol-v2", "package-authority-v1"])
    status = SimpleNamespace(available=True, compatible=True, identity=identity, capabilities=capabilities)
    for key, value in overrides.items():
        setattr(status, key, value)
    return status


def _patch_authority(monkeypatch: pytest.MonkeyPatch, status: SimpleNamespace, response: bytes | None) -> None:
    monkeypatch.setattr(native_package_authority, "native_runtime_status", lambda: status)
    monkeypatch.setattr(native_package_authority, "native_resident_client_request", lambda **_kwargs: response)
    monkeypatch.setattr(native_package_authority, "native_record_resident_failure", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(native_package_authority, "native_record_resident_success", lambda *_args, **_kwargs: None)


def test_package_authority_refuses_unavailable_or_malformed_resident(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    home = tmp_path / "home"
    _patch_authority(monkeypatch, _status(available=False), b"{}")
    assert native_package_authority.package_intent_parse_native("npm install left-pad", guard_home=home) is None

    _patch_authority(monkeypatch, _status(identity=None, capabilities=None), b"{}")
    assert native_package_authority.package_intent_parse_native("npm install left-pad", guard_home=home) is None

    missing = _status()
    missing.capabilities = SimpleNamespace(features=["resident-protocol-v2"])
    _patch_authority(monkeypatch, missing, b"{}")
    assert native_package_authority.package_intent_parse_native("npm install left-pad", guard_home=home) is None

    _patch_authority(monkeypatch, _status(), None)
    assert native_package_authority.package_intent_parse_native("npm install left-pad", guard_home=home) is None

    _patch_authority(monkeypatch, _status(), b"\xff")
    assert native_package_authority.package_intent_parse_native("npm install left-pad", guard_home=home) is None

    _patch_authority(monkeypatch, _status(), b"[]")
    assert native_package_authority.package_intent_parse_native("npm install left-pad", guard_home=home) is None

    _patch_authority(monkeypatch, _status(), b'{"schema":"other","status":"ok","payload":{}}')
    assert native_package_authority.package_intent_parse_native("npm install left-pad", guard_home=home) is None

    _patch_authority(
        monkeypatch,
        _status(),
        b'{"schema":"guard-package-authority-result.v1","status":"error","payload":{}}',
    )
    assert native_package_authority.package_intent_parse_native("npm install left-pad", guard_home=home) is None

    _patch_authority(
        monkeypatch,
        _status(),
        b'{"schema":"guard-package-authority-result.v1","status":"ok","payload":["nope"]}',
    )
    assert native_package_authority.package_intent_parse_native("npm install left-pad", guard_home=home) is None

    huge = "x" * (256 * 1024 + 1)
    _patch_authority(monkeypatch, _status(), b"{}")
    assert native_package_authority.package_intent_parse_native(huge, guard_home=home) is None

    assert (
        native_package_authority.package_authority_decide_native(
            "npm install left-pad",
            store_path=tmp_path / "store",
            guard_home=home,
        )
        is None
    )


def test_program_digest_stamp_keeps_snapshot_when_runtime_digests_disagree() -> None:
    extensions = {"program_digest": OTHER, "catalog_digest": DIGEST, "trust_digest": DIGEST}
    assert _stamp_runtime_program_digest(extensions, None) is extensions
    mismatched = SimpleNamespace(program_digest="short", catalog_digest=DIGEST, trust_digest=DIGEST)
    assert _stamp_runtime_program_digest(extensions, mismatched) is extensions
    catalog_miss = SimpleNamespace(program_digest=DIGEST, catalog_digest=OTHER, trust_digest=DIGEST)
    assert _stamp_runtime_program_digest(extensions, catalog_miss) is extensions
    already = SimpleNamespace(program_digest=OTHER, catalog_digest=DIGEST, trust_digest=DIGEST)
    assert _stamp_runtime_program_digest(extensions, already) is extensions
    stamped = _stamp_runtime_program_digest(
        extensions,
        SimpleNamespace(program_digest=DIGEST, catalog_digest=DIGEST, trust_digest=DIGEST),
    )
    assert stamped["program_digest"] == DIGEST
    assert extensions["program_digest"] == OTHER


def _raise_transport(*_args: object, **_kwargs: object) -> dict[str, object]:
    raise RuntimeError("transport")


def test_supply_chain_native_bridge_rejects_bad_call_shapes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        local_supply_chain,
        "_native_package_authority_module",
        lambda: SimpleNamespace(package_intent_parse_native=_raise_transport),
    )
    assert (
        local_supply_chain._parse_package_intent_native(
            "npm install left-pad",
            environment={"PATH": "/usr/bin"},
            workspace=tmp_path,
            guard_home=tmp_path,
        )
        is None
    )
    monkeypatch.setattr(
        local_supply_chain,
        "_native_package_authority_module",
        lambda: SimpleNamespace(package_intent_parse_native=lambda *_args, **_kwargs: {"intent_kind": "nope"}),
    )
    assert (
        local_supply_chain._parse_package_intent_native(
            "npm install left-pad",
            environment=None,
            workspace=tmp_path,
            guard_home=tmp_path,
        )
        is None
    )


def test_package_evaluation_without_resident_blocks_and_never_runs_python_evaluator(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from codex_plugin_scanner.guard import native_supply_chain_eval
    from codex_plugin_scanner.guard.runtime import supply_chain_package_eval as evaluator

    monkeypatch.setattr(
        evaluator,
        "evaluate_package_request_artifact",
        lambda **_: pytest.fail("Python must not evaluate a non-retaining package request"),
    )
    monkeypatch.setattr(native_supply_chain_eval, "ensure_resident_prerequisite", lambda _home: False)
    result = local_supply_chain.evaluate_package_request_artifact(
        artifact=SimpleNamespace(
            artifact_id="package:npm:left-pad",
            to_dict=lambda: {"artifact_id": "package:npm:left-pad"},
        ),
        store=SimpleNamespace(guard_home=tmp_path, path=tmp_path / "guard.db", get_cloud_workspace_id=lambda: None),
        workspace_dir=tmp_path,
    )
    assert result.decision == "block"
    assert result.policy_action == "block"
    assert result.reasons[0]["code"] == "native_supply_chain_eval_unavailable"


def test_retained_archive_evaluation_is_the_only_python_evaluator_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from codex_plugin_scanner.guard import native_supply_chain_eval
    from codex_plugin_scanner.guard.runtime import supply_chain_package_eval as evaluator

    sentinel = object()
    seen: dict[str, object] = {}

    def python_evaluator(**kwargs: object) -> object:
        seen.update(kwargs)
        return sentinel

    monkeypatch.setattr(evaluator, "evaluate_package_request_artifact", python_evaluator)
    monkeypatch.setattr(
        native_supply_chain_eval,
        "evaluate_package_request_native",
        lambda **_: pytest.fail("a retained-blob request needs the live archive handle"),
    )
    result = local_supply_chain.evaluate_package_request_artifact(
        artifact=SimpleNamespace(),
        store=SimpleNamespace(),
        workspace_dir=tmp_path,
        external_archive_network_authorized=True,
        retain_external_archive_blob=True,
    )
    assert result is sentinel
    assert seen["retain_external_archive_blob"] is True
    assert seen["external_archive_network_authorized"] is True
