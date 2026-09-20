"""Runtime regression tests: guard run headless redetects before persisted resume."""

from __future__ import annotations

from tests.guard_runtime_test_dependencies import (
    GuardAction,
    GuardArtifact,
    GuardConfig,
    GuardStore,
    HarnessContext,
    HarnessDetection,
    Path,
    apply_approval_resolution,
    argparse,
    artifact_hash,
    decide_action,
    evaluate_detection,
    guard_commands_module,
    guard_runner_module,
    pytest,
    subprocess,
    sys,
    threading,
)
from tests.guard_runtime_test_support import (
    _build_guard_fixture,
    _make_pinnable_harness_executable,
    _write_text,
)
from tests.guard_runtime_test_support import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)


def test_guard_run_headless_redetects_before_persisted_resume(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _write_text(home_dir / "config.toml", "approval_wait_timeout_seconds = 1\n")

    store = GuardStore(home_dir)
    baseline = GuardArtifact(
        artifact_id="claude-code:project:mcp:workspace-tools",
        name="workspace-tools",
        harness="claude-code",
        artifact_type="mcp_server",
        source_scope="project",
        config_path=str(workspace_dir / ".mcp.json"),
        command="python",
        args=("-m", "http.server", "9100"),
        transport="stdio",
    )
    baseline_hash = artifact_hash(baseline)
    store.save_snapshot(
        "claude-code",
        baseline.artifact_id,
        {**baseline.to_dict(), "artifact_hash": baseline_hash},
        baseline_hash,
        "2026-04-10T00:00:00+00:00",
    )
    detections = [
        HarnessDetection(
            harness="claude-code",
            installed=True,
            command_available=True,
            config_paths=(str(workspace_dir / ".mcp.json"),),
            artifacts=(
                GuardArtifact(
                    artifact_id=baseline.artifact_id,
                    name="workspace-tools",
                    harness="claude-code",
                    artifact_type="mcp_server",
                    source_scope="project",
                    config_path=str(workspace_dir / ".mcp.json"),
                    command="python",
                    args=("-m", "http.server", "9100", "--changed-1"),
                    transport="stdio",
                ),
            ),
        ),
        HarnessDetection(
            harness="claude-code",
            installed=True,
            command_available=True,
            config_paths=(str(workspace_dir / ".mcp.json"),),
            artifacts=(
                GuardArtifact(
                    artifact_id=baseline.artifact_id,
                    name="workspace-tools",
                    harness="claude-code",
                    artifact_type="mcp_server",
                    source_scope="project",
                    config_path=str(workspace_dir / ".mcp.json"),
                    command="python",
                    args=("-m", "http.server", "9100", "--changed-2"),
                    transport="stdio",
                ),
            ),
        ),
    ]
    call_count = {"detect": 0}
    monkeypatch.setattr(
        guard_commands_module, "schedule_guard_daemon_ensure", lambda _guard_home, **_kwargs: "http://127.0.0.1:4455"
    )
    monkeypatch.setattr(
        guard_runner_module.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
    )

    def fake_detect(harness: str, context):
        call_count["detect"] += 1
        index = min(call_count["detect"] - 1, len(detections) - 1)
        return detections[index]

    monkeypatch.setattr(guard_runner_module, "detect_harness", fake_detect)

    def resolve_pending() -> None:
        for _ in range(100):
            pending = store.list_approval_requests(limit=10)
            if pending:
                apply_approval_resolution(
                    store=store,
                    request_id=str(pending[0]["request_id"]),
                    action="allow",
                    scope="artifact",
                    workspace=None,
                    reason="approved from test",
                )
                return
            threading.Event().wait(0.05)

    worker = threading.Thread(target=resolve_pending, daemon=True)
    worker.start()

    config = GuardConfig(guard_home=home_dir, workspace=workspace_dir, approval_wait_timeout_seconds=5)
    blocked_resolver = guard_commands_module._headless_approval_resolver(
        args=argparse.Namespace(harness="claude-code"),
        context=HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=home_dir),
        store=store,
        config=config,
    )
    result = guard_runner_module.guard_run(
        "claude-code",
        HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=home_dir),
        store,
        config,
        dry_run=False,
        passthrough_args=[],
        default_action=None,
        interactive_resolver=None,
        blocked_resolver=blocked_resolver,
    )

    assert result["blocked"] is True
    assert isinstance(result["approval_wait"]["resolved"], bool)
    assert result["artifacts"][0]["changed_fields"] == ["args"]
    assert result["artifacts"][0]["artifact_hash"] == artifact_hash(detections[-1].artifacts[0])
    assert call_count["detect"] >= 2


def test_guard_run_interactive_allow_once_redetects_before_resume(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True)
    _make_pinnable_harness_executable(tmp_path, monkeypatch, "codex")
    artifact_id = "codex:project:interactive-redetect"
    detections = [
        HarnessDetection(
            harness="codex",
            installed=True,
            command_available=True,
            config_paths=(str(workspace_dir / ".codex" / "config.toml"),),
            artifacts=(
                GuardArtifact(
                    artifact_id=artifact_id,
                    name="interactive-redetect",
                    harness="codex",
                    artifact_type="tool_action_request",
                    source_scope="project",
                    config_path=str(workspace_dir / ".codex" / "config.toml"),
                    command="codex",
                    args=("-c", "print('before')"),
                ),
            ),
        ),
        HarnessDetection(
            harness="codex",
            installed=True,
            command_available=True,
            config_paths=(str(workspace_dir / ".codex" / "config.toml"),),
            artifacts=(
                GuardArtifact(
                    artifact_id=artifact_id,
                    name="interactive-redetect",
                    harness="codex",
                    artifact_type="tool_action_request",
                    source_scope="project",
                    config_path=str(workspace_dir / ".codex" / "config.toml"),
                    command="codex",
                    args=("-c", "print('after')"),
                ),
            ),
        ),
    ]
    call_count = {"detect": 0}

    def fake_detect(_harness: str, _context: HarnessContext) -> HarnessDetection:
        index = min(call_count["detect"], len(detections) - 1)
        call_count["detect"] += 1
        return detections[index]

    def allow_once(_detection: HarnessDetection, evaluation: dict[str, object]) -> dict[str, object]:
        items = evaluation.get("artifacts")
        assert isinstance(items, list)
        item = items[0]
        assert isinstance(item, dict)
        item["policy_action"] = "allow"
        item["user_override"] = "allow-once"
        evaluation["blocked"] = False
        return evaluation

    launch_calls: list[object] = []
    monkeypatch.setattr(guard_runner_module, "detect_harness", fake_detect)
    monkeypatch.setattr(
        guard_runner_module.subprocess,
        "run",
        lambda *args, **kwargs: launch_calls.append((args, kwargs)),
    )
    store = GuardStore(home_dir)
    result = guard_runner_module.guard_run(
        "codex",
        HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=home_dir),
        store,
        GuardConfig(
            guard_home=home_dir,
            workspace=workspace_dir,
            artifact_actions={artifact_id: "require-reapproval"},
        ),
        dry_run=False,
        passthrough_args=[],
        interactive_resolver=allow_once,
    )

    assert result["blocked"] is True
    assert result["launched"] is False
    assert result["artifacts"][0]["policy_action"] == "require-reapproval"
    assert result["artifacts"][0]["trusted_request_override"]["applied"] is False
    assert call_count["detect"] >= 2
    assert launch_calls == []
    receipts = store.list_receipts(limit=10)
    assert len(receipts) == 1
    assert receipts[0]["policy_decision"] == "require-reapproval"
    assert receipts[0]["user_override"] is None


@pytest.mark.parametrize("terminal_action", ("sandbox-required", "block"))
def test_guard_run_interactive_allow_once_cannot_lower_terminal_action(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    terminal_action: GuardAction,
) -> None:
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True)
    artifact_id = "codex:project:interactive-terminal"
    artifact = GuardArtifact(
        artifact_id=artifact_id,
        name="interactive-terminal",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path=str(workspace_dir / ".codex" / "config.toml"),
        command=sys.executable,
        args=("-c", "pass"),
    )
    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(artifact.config_path,),
        artifacts=(artifact,),
    )

    def allow_once(_detection: HarnessDetection, evaluation: dict[str, object]) -> dict[str, object]:
        items = evaluation.get("artifacts")
        assert isinstance(items, list)
        item = items[0]
        assert isinstance(item, dict)
        item["policy_action"] = "allow"
        item["user_override"] = "allow-once"
        evaluation["blocked"] = False
        return evaluation

    launch_calls: list[object] = []
    monkeypatch.setattr(guard_runner_module, "detect_harness", lambda _harness, _context: detection)
    monkeypatch.setattr(
        guard_runner_module.subprocess,
        "run",
        lambda *args, **kwargs: launch_calls.append((args, kwargs)),
    )
    store = GuardStore(home_dir)
    result = guard_runner_module.guard_run(
        "codex",
        HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=home_dir),
        store,
        GuardConfig(
            guard_home=home_dir,
            workspace=workspace_dir,
            artifact_actions={artifact_id: terminal_action},
        ),
        dry_run=False,
        passthrough_args=[],
        interactive_resolver=allow_once,
    )

    assert result["blocked"] is True
    assert result["launched"] is False
    assert result["artifacts"][0]["policy_action"] == terminal_action
    assert result["artifacts"][0]["trusted_request_override"]["applied"] is False
    assert launch_calls == []
    receipts = store.list_receipts(limit=10)
    assert len(receipts) == 1
    assert receipts[0]["policy_decision"] == terminal_action
    assert receipts[0]["user_override"] is None


def test_guard_headless_blocked_run_persists_receipts_and_diffs(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    _build_guard_fixture(home_dir, workspace_dir)
    store = GuardStore(home_dir)
    baseline = GuardArtifact(
        artifact_id="claude-code:project:mcp:workspace-tools",
        name="workspace-tools",
        harness="claude-code",
        artifact_type="mcp_server",
        source_scope="project",
        config_path=str(workspace_dir / ".mcp.json"),
        command="python",
        args=("-m", "http.server", "9100"),
        transport="stdio",
    )
    baseline_hash = artifact_hash(baseline)
    store.save_snapshot(
        "claude-code",
        baseline.artifact_id,
        {**baseline.to_dict(), "artifact_hash": baseline_hash},
        baseline_hash,
        "2026-04-10T00:00:00+00:00",
    )
    changed = GuardArtifact(
        artifact_id=baseline.artifact_id,
        name=baseline.name,
        harness=baseline.harness,
        artifact_type=baseline.artifact_type,
        source_scope=baseline.source_scope,
        config_path=baseline.config_path,
        command="python",
        args=("-m", "http.server", "9100", "--changed"),
        transport="stdio",
    )
    detection = HarnessDetection(
        harness="claude-code",
        installed=True,
        command_available=True,
        config_paths=(baseline.config_path,),
        artifacts=(changed,),
    )

    monkeypatch.setattr(guard_runner_module, "detect_harness", lambda _harness, _context: detection)

    config = GuardConfig(guard_home=home_dir, workspace=workspace_dir, approval_wait_timeout_seconds=1)
    result = guard_runner_module.guard_run(
        "claude-code",
        HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=home_dir),
        store,
        config,
        dry_run=False,
        passthrough_args=[],
        default_action=None,
        interactive_resolver=None,
        blocked_resolver=lambda _detection, evaluation: evaluation,
    )

    latest_diff = store.get_latest_diff("claude-code", baseline.artifact_id)
    latest_receipt = store.get_latest_receipt("claude-code", baseline.artifact_id)

    assert result["blocked"] is True
    assert result["artifacts"][0]["action_envelope_json"]["action_type"] == "harness_start"
    assert result["artifacts"][0]["action_envelope_json"]["harness"] == "claude-code"
    assert latest_diff is not None
    assert latest_diff["current_hash"] == artifact_hash(changed)
    assert latest_receipt is not None
    assert latest_receipt["policy_decision"] == "require-reapproval"


def test_guard_invalid_changed_hash_action_falls_back_to_reapproval(tmp_path):
    store = GuardStore(tmp_path / "guard-home")
    baseline = GuardArtifact(
        artifact_id="codex:project:workspace-tools",
        name="workspace-tools",
        harness="codex",
        artifact_type="mcp_server",
        source_scope="project",
        config_path=str(tmp_path / "workspace" / ".codex" / "config.toml"),
        command="node",
        args=("workspace.js",),
        transport="stdio",
    )
    changed = GuardArtifact(
        artifact_id=baseline.artifact_id,
        name=baseline.name,
        harness=baseline.harness,
        artifact_type=baseline.artifact_type,
        source_scope=baseline.source_scope,
        config_path=baseline.config_path,
        command="node",
        args=("workspace.js", "--changed"),
        transport="stdio",
    )
    baseline_hash = artifact_hash(baseline)
    store.save_snapshot(
        "codex",
        baseline.artifact_id,
        {**baseline.to_dict(), "artifact_hash": baseline_hash},
        baseline_hash,
        "2026-04-10T00:00:00+00:00",
    )
    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(baseline.config_path,),
        artifacts=(changed,),
    )
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=None,
        changed_hash_action="require_reapproval",  # type: ignore[arg-type]
    )

    evaluation = evaluate_detection(detection, store, config, default_action="allow", persist=False)

    assert evaluation["blocked"] is True
    assert evaluation["artifacts"][0]["policy_action"] == "require-reapproval"


def test_guard_invalid_default_action_falls_back_to_reapproval(tmp_path):
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=None,
        default_action="blok",  # type: ignore[arg-type]
    )

    action = decide_action(configured_action=None, default_action=None, config=config, changed=False)

    assert action == "require-reapproval"
