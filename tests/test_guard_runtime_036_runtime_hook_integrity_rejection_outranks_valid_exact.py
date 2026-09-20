"""Runtime regression tests: runtime hook integrity rejection outranks valid exact."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    APPROVAL_CONTEXT_TOKEN_PREFIX,
    GuardActionEnvelope,
    GuardArtifact,
    GuardConfig,
    GuardStore,
    HarnessContext,
    Path,
    PolicyDecision,
    _runtime_hook_approval_context_token,
    approval_context_tokens_validation_reason,
    argparse,
    artifact_hash,
    guard_commands_module,
    io,
    json,
    main,
    os,
    pytest,
    replace,
    shlex,
    sqlite3,
    sys,
)
from tests.guard_runtime_test_support import (
    _build_guard_fixture,
    _run_guard_hook,
    _write_text,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


def test_runtime_hook_integrity_rejection_outranks_valid_exact_one_shot_allow(tmp_path) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    store = GuardStore(home_dir)
    config = GuardConfig(
        guard_home=home_dir,
        workspace=workspace_dir,
        default_action="allow",
        approval_wait_timeout_seconds=0,
    )
    artifact = GuardArtifact(
        artifact_id="codex:project:tool-action:integrity-collision",
        name="Codex integrity collision action",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=str(workspace_dir / ".codex" / "config.toml"),
        command="echo",
        args=("integrity-collision",),
        metadata={"guard_default_action": "review", "action_class": "routine shell command"},
    )
    args = argparse.Namespace(harness="codex", policy_action=None, json=True)
    context = HarnessContext(home_dir=tmp_path, workspace_dir=workspace_dir, guard_home=home_dir)
    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "echo integrity-collision"},
        "source_scope": "project",
    }
    first = guard_commands_module._evaluate_runtime_artifact_hook(
        args,
        action_envelope=None,
        config=config,
        context=context,
        data_flow_signals=(),
        guard_home=home_dir,
        payload=payload,
        runtime_artifact=artifact,
        runtime_workspace=workspace_dir,
        store=store,
    )
    assert not isinstance(first, int)
    approval_id = store.record_local_once_approval(
        request_id="request-integrity-collision",
        harness="codex",
        artifact_id=artifact.artifact_id,
        artifact_hash=first.runtime_artifact_hash,
        workspace=str(workspace_dir),
        publisher=None,
        action="allow",
        created_at="2026-07-17T12:00:00+00:00",
        expires_at="2027-07-17T13:00:00+00:00",
    )
    assert approval_id is not None
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="global",
            action="block",
            artifact_id=None,
            artifact_hash=None,
            reason="tampered broader block must invalidate reuse",
            source="manual",
        ),
        "2026-07-17T12:01:00+00:00",
    )
    broader_block = next(policy for policy in store.list_policy_decisions("codex") if policy["action"] == "block")
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "update policy_decisions set payload_mac = ? where decision_id = ?",
            ("00", broader_block["decision_id"]),
        )

    second = guard_commands_module._evaluate_runtime_artifact_hook(
        args,
        action_envelope=None,
        config=config,
        context=context,
        data_flow_signals=(),
        guard_home=home_dir,
        payload=payload,
        runtime_artifact=artifact,
        runtime_workspace=workspace_dir,
        store=store,
        trusted_request_override_hash=first.runtime_artifact_hash,
    )
    with sqlite3.connect(store.path) as connection:
        claimed_at = connection.execute(
            "select claimed_at from guard_local_once_approvals where approval_id = ?",
            (approval_id,),
        ).fetchone()[0]

    assert not isinstance(second, int)
    assert second.policy_action == "require-reapproval"
    assert second.response_payload["approval_reuse"]["status"] == "rejected"
    assert second.response_payload["approval_reuse"]["reason_code"] == "approval_reuse_integrity_failure"
    assert second.response_payload["remembered_rule_rejection"]["integrity_status"] == "tampered"
    assert second.response_payload["policy_composition"]["trusted_request_override"] is False
    assert second.response_payload["policy_composition"]["trusted_request_override_reason"] == (
        "trusted_request_override_integrity_failure"
    )
    assert claimed_at is None


def test_runtime_hook_saved_allow_invalidates_when_path_resolves_executable_elsewhere(
    tmp_path,
    capsys,
    monkeypatch,
):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    first_bin = tmp_path / "bin-a"
    second_bin = tmp_path / "bin-b"
    _build_guard_fixture(home_dir, workspace_dir)
    _write_text(
        home_dir / "config.toml",
        'approval_wait_timeout_seconds = 0\n[risk_actions]\ndestructive_shell = "review"\n',
    )
    execution_markers: list[Path] = []
    for bin_dir, marker in ((first_bin, "first"), (second_bin, "second")):
        executable = bin_dir / "rm"
        execution_marker = tmp_path / f"{marker}-executable-ran"
        execution_markers.append(execution_marker)
        _write_text(executable, f"#!/bin/sh\nprintf ran > {shlex.quote(str(execution_marker))}\n")
        executable.chmod(0o755)
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf build"},
        "source_scope": "project",
    }
    original_path = os.environ.get("PATH", "")
    monkeypatch.setenv("PATH", f"{first_bin}{os.pathsep}{original_path}")

    first_rc, first_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event=event,
        capsys=capsys,
        monkeypatch=monkeypatch,
        as_json=True,
    )
    store = GuardStore(home_dir)
    first_token = str(store.list_receipts(limit=1)[0]["artifact_hash"])
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=str(first_output["artifact_id"]),
            artifact_hash=first_token,
            reason="Reviewed executable from first PATH entry",
            source="manual",
        ),
        "2026-07-17T12:00:00+00:00",
    )
    monkeypatch.setenv("PATH", f"{second_bin}{os.pathsep}{original_path}")

    second_rc, second_output = _run_guard_hook(
        home_dir=home_dir,
        workspace_dir=workspace_dir,
        harness="codex",
        event=event,
        capsys=capsys,
        monkeypatch=monkeypatch,
        as_json=True,
    )

    assert first_rc == 1
    assert first_output["policy_action"] == "block"
    assert second_rc == 1
    assert second_output["policy_action"] == "block"
    assert second_output["approval_reuse"]["status"] == "rejected"
    assert second_output["approval_reuse"]["reason_code"] == "approval_reuse_identity_changed"
    assert all(not marker.exists() for marker in execution_markers)


@pytest.mark.parametrize(
    ("changed_dimension", "expected_reason"),
    (
        ("workspace", "approval_reuse_identity_changed"),
        ("content", "approval_reuse_content_changed"),
        ("capability", "approval_reuse_capability_changed"),
        ("scanner", "approval_reuse_capability_changed"),
        ("policy", "approval_reuse_policy_changed"),
        ("sandbox", "approval_reuse_sandbox_changed"),
        ("unrelated_ux", None),
    ),
)
def test_runtime_hook_approval_context_invalidates_one_changed_dimension(
    tmp_path,
    changed_dimension,
    expected_reason,
):
    workspace = tmp_path / "workspace"
    artifact = GuardArtifact(
        artifact_id="codex:project:tool-action:stable",
        name="Bash destructive shell command",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=str(workspace / ".codex" / "config.toml"),
        command="rm -rf build-cache",
        metadata={"action_class": "destructive shell command", "risk_classes": ["destructive_shell"]},
    )
    envelope = GuardActionEnvelope(
        schema_version=1,
        action_id="stable-action",
        harness="codex",
        event_name="PreToolUse",
        action_type="shell_command",
        workspace=str(workspace),
        workspace_hash="workspace-hash",
        tool_name="Bash",
        command="rm -rf build-cache",
        prompt_excerpt=None,
        prompt_text=None,
        target_paths=(str(workspace / "build-cache"),),
        network_hosts=(),
        mcp_server=None,
        mcp_tool=None,
        package_manager=None,
        package_name=None,
        script_name=None,
        raw_payload_redacted={},
    )
    config = GuardConfig(
        guard_home=tmp_path / "home",
        workspace=workspace,
        risk_actions={"destructive_shell": "review"},
    )

    def _token(
        *,
        runtime_workspace=workspace,
        content_hash="artifact-content-v1",
        action_envelope=envelope,
        effective_config=config,
        scanner_evidence=(),
    ):
        return _runtime_hook_approval_context_token(
            artifact=artifact,
            content_hash=content_hash,
            runtime_workspace=runtime_workspace,
            action_envelope=action_envelope,
            config=effective_config,
            current_config_action="review",
            trusted_cli_action=None,
            untrusted_payload_action=None,
            package_action=None,
            data_flow_action=None,
            scanner_action=None,
            current_action="review",
            data_flow_signals=(),
            scanner_evidence=scanner_evidence,
        )

    saved_token = _token()
    if changed_dimension == "workspace":
        current_token = _token(runtime_workspace=tmp_path / "other-workspace")
    elif changed_dimension == "content":
        current_token = _token(content_hash="artifact-content-v2")
    elif changed_dimension == "capability":
        current_token = _token(
            action_envelope=replace(
                envelope,
                target_paths=(*envelope.target_paths, str(workspace / "other-target")),
            )
        )
    elif changed_dimension == "scanner":
        current_token = _token(scanner_evidence=({"signal_id": "scanner:new-capability"},))
    elif changed_dimension == "policy":
        current_token = _token(effective_config=replace(config, new_network_domain_action="block"))
    elif changed_dimension == "sandbox":
        current_token = _token(effective_config=replace(config, sandbox_analysis="strict"))
    else:
        current_token = _token(
            effective_config=replace(
                config,
                approval_browser_delay_seconds=99,
                desktop_notifications=not config.desktop_notifications,
                telemetry=not config.telemetry,
            )
        )

    assert approval_context_tokens_validation_reason(saved_token, current_token) == expected_reason


def test_runtime_hook_package_without_workspace_rejects_legacy_exact_allow(
    tmp_path,
    capsys,
    monkeypatch,
):
    from codex_plugin_scanner.guard.runtime.supply_chain_package_eval import (
        PackageRequestEvaluation,
        SupplyChainUserCopy,
    )

    home_dir = tmp_path / "home"
    cwd = tmp_path / "inherited-cwd"
    cwd.mkdir()
    _write_text(
        home_dir / "config.toml",
        'approval_wait_timeout_seconds = 0\n[risk_actions]\npackage_script = "review"\n',
    )
    event = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "npm install minimist@1.2.8"},
        "source_scope": "project",
    }
    action_envelope = guard_commands_module._hook_action_envelope(
        harness="codex",
        payload=event,
        home_dir=home_dir,
        workspace=None,
    )
    artifact = guard_commands_module._hook_runtime_artifact(
        harness="codex",
        payload=event,
        action_envelope=action_envelope,
        home_dir=home_dir,
        guard_home=home_dir,
        workspace=None,
    )
    assert artifact is not None
    assert artifact.artifact_type == "package_request"
    GuardStore(home_dir).upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id=artifact.artifact_id,
            artifact_hash=artifact_hash(artifact),
            reason="legacy exact package allow",
            source="manual",
        ),
        "2026-07-17T12:00:00+00:00",
    )
    evaluation = PackageRequestEvaluation(
        decision="review",
        policy_action="review",
        enforcement="policy",
        entitlement_state="active",
        cache_status="hit",
        package_intent_hash="intent-hash",
        policy_version="policy-v1",
        bundle_version="bundle-v1",
        workspace_fingerprint="no-workspace",
        reasons=({"code": "package_review", "message": "Review package install."},),
        packages=({"name": "minimist", "decision": "review", "reasons": ()},),
        risk_summary="Review package install.",
        user_copy=SupplyChainUserCopy(
            title="Review package install",
            summary="Review package install.",
            next_step="Review the exact request.",
            dashboard_url=None,
            harness_message="Review package install.",
        ),
    )
    monkeypatch.chdir(cwd)
    monkeypatch.setattr(guard_commands_module, "evaluate_package_request_artifact", lambda **_kwargs: evaluation)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))

    rc = main(
        [
            "guard",
            "hook",
            "--home",
            str(home_dir),
            "--harness",
            "codex",
            "--json",
        ]
    )
    output = json.loads(capsys.readouterr().out)
    receipt = GuardStore(home_dir).list_receipts(limit=1)[0]

    assert rc == 1
    assert output["policy_action"] == "review"
    assert output["approval_reuse"]["status"] == "rejected"
    assert output["approval_reuse"]["reason_code"] == "approval_reuse_content_changed"
    assert receipt["artifact_hash"].startswith(APPROVAL_CONTEXT_TOKEN_PREFIX)
    assert receipt["artifact_hash"] != artifact_hash(artifact)
