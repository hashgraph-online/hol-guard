"""Behavior tests for Guard runtime detector registry plumbing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.models import HarnessDetection
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope, normalize_codex_hook_payload
from codex_plugin_scanner.guard.runtime.detectors import (
    DETECTOR_CATEGORY_TAGS,
    DetectorContext,
    DetectorRegistry,
    register_default_detectors,
)
from codex_plugin_scanner.guard.runtime.signals import RiskSignalCategory, RiskSignalV2
from codex_plugin_scanner.guard.store import GuardStore


class StepClock:
    def __init__(self, values: list[float]) -> None:
        self.values = values

    def __call__(self) -> float:
        return self.values.pop(0)


class RecordingDetector:
    def __init__(
        self,
        detector_id: str,
        categories: tuple[RiskSignalCategory, ...],
        calls: list[str],
        signal: RiskSignalV2 | None = None,
        raises: Exception | None = None,
    ) -> None:
        self.detector_id = detector_id
        self.categories = categories
        self.calls = calls
        self.signal = signal
        self.raises = raises

    def detect(self, action: GuardActionEnvelope, context: DetectorContext) -> tuple[RiskSignalV2, ...]:
        self.calls.append(self.detector_id)
        assert action.action_type == "harness_start"
        assert context.workspace is not None
        if self.raises is not None:
            raise self.raises
        if self.signal is None:
            return ()
        return (self.signal,)


def _signal(signal_id: str, category: RiskSignalCategory) -> RiskSignalV2:
    return RiskSignalV2(
        signal_id=signal_id,
        category=category,
        severity="medium",
        confidence="likely",
        detector="test-detector",
        title="Detector signal",
        plain_reason="Detector found a risky runtime action.",
        technical_detail=None,
        evidence_ref=None,
        redaction_level="summary",
        false_positive_hint=None,
        advisory_id=None,
    )


def _action() -> GuardActionEnvelope:
    return GuardActionEnvelope(
        schema_version=1,
        action_id="action-1",
        harness="codex",
        event_name="HarnessStart",
        action_type="harness_start",
        workspace="~/workspace",
        workspace_hash="workspace-hash",
        tool_name=None,
        command=None,
        prompt_excerpt=None,
        target_paths=(),
        network_hosts=(),
        mcp_server=None,
        mcp_tool=None,
        package_manager=None,
        package_name=None,
        script_name=None,
        raw_payload_redacted={},
    )


def _file_read_action(path: str) -> GuardActionEnvelope:
    return GuardActionEnvelope(
        schema_version=1,
        action_id="",
        harness="codex",
        event_name="PreToolUse",
        action_type="file_read",
        workspace="~/workspace",
        workspace_hash="workspace-hash",
        tool_name="Read",
        command=None,
        prompt_excerpt=None,
        target_paths=(path,),
        network_hosts=(),
        mcp_server=None,
        mcp_tool=None,
        package_manager=None,
        package_name=None,
        script_name=None,
        raw_payload_redacted={"file_path": path},
    )


def _context(tmp_path: Path) -> DetectorContext:
    return DetectorContext(
        config=GuardConfig(guard_home=tmp_path / "guard-home", workspace=tmp_path / "workspace"),
        workspace=tmp_path / "workspace",
        prior_decisions={"artifact": "allow"},
        threat_intel={"source": "unit-test"},
        redaction_settings={"level": "summary"},
    )


def test_detector_registry_runs_in_deterministic_detector_id_order(tmp_path):
    calls: list[str] = []
    registry = DetectorRegistry(
        (
            RecordingDetector("network.egress", ("network",), calls, _signal("network:egress", "network")),
            RecordingDetector("secret.local", ("secret",), calls, _signal("secret:local", "secret")),
        ),
        clock=StepClock([0.0, 0.001, 0.002, 0.003]),
    )

    result = registry.run(_action(), _context(tmp_path))

    assert calls == ["network.egress", "secret.local"]
    assert [signal.signal_id for signal in result.signals] == ["network:egress", "secret:local"]
    assert [item.status for item in result.telemetry] == ["ok", "ok"]


def test_detector_registry_skips_disabled_detector_ids(tmp_path):
    calls: list[str] = []
    registry = DetectorRegistry(
        (
            RecordingDetector("network.egress", ("network",), calls, _signal("network:egress", "network")),
            RecordingDetector("secret.local", ("secret",), calls, _signal("secret:local", "secret")),
        ),
        clock=StepClock([0.0, 0.001]),
    )

    result = registry.run(_action(), _context(tmp_path), disabled_detector_ids=("network.egress",))

    assert calls == ["secret.local"]
    assert [signal.signal_id for signal in result.signals] == ["secret:local"]
    assert [(item.detector_id, item.status) for item in result.telemetry] == [
        ("network.egress", "disabled"),
        ("secret.local", "ok"),
    ]


def test_detector_registry_discards_signals_when_detector_exceeds_timeout(tmp_path):
    calls: list[str] = []
    registry = DetectorRegistry(
        (RecordingDetector("secret.slow", ("secret",), calls, _signal("secret:slow", "secret")),),
        clock=StepClock([0.0, 0.075]),
    )

    result = registry.run(_action(), _context(tmp_path), timeout_ms=50)

    assert calls == ["secret.slow"]
    assert result.signals == ()
    assert result.telemetry[0].status == "timeout"
    assert result.telemetry[0].elapsed_ms == 75


def test_detector_registry_isolates_detector_exceptions_as_telemetry(tmp_path):
    calls: list[str] = []
    registry = DetectorRegistry(
        (
            RecordingDetector("secret.broken", ("secret",), calls, raises=RuntimeError("boom")),
            RecordingDetector("secret.healthy", ("secret",), calls, signal=_signal("secret:healthy", "secret")),
        ),
        clock=StepClock([0.0, 0.001, 0.002, 0.003]),
    )

    result = registry.run(_action(), _context(tmp_path))

    assert calls == ["secret.broken", "secret.healthy"]
    assert [signal.signal_id for signal in result.signals] == ["secret:healthy"]
    assert result.telemetry[0].status == "error"
    assert result.telemetry[0].error_type == "RuntimeError"


def test_detector_registry_filters_by_detector_categories(tmp_path):
    calls: list[str] = []
    registry = DetectorRegistry(
        (
            RecordingDetector("network.egress", ("network",), calls, _signal("network:egress", "network")),
            RecordingDetector("secret.local", ("secret",), calls, _signal("secret:local", "secret")),
        ),
        clock=StepClock([0.0, 0.001]),
    )

    result = registry.run(_action(), _context(tmp_path), enabled_categories=("secret",))

    assert calls == ["secret.local"]
    assert [signal.signal_id for signal in result.signals] == ["secret:local"]
    assert result.telemetry[0].status == "filtered"
    assert result.telemetry[0].detector_id == "network.egress"


def test_register_default_detectors_includes_secret_path_detector():
    detector_ids = {detector.detector_id for detector in register_default_detectors()}
    assert "secret.path" in detector_ids
    planned_categories = {
        "secret",
        "network",
        "prompt",
        "mcp",
        "skill",
        "supply_chain",
        "encoded",
        "persistence",
        "bypass",
        "false_positive",
    }
    assert planned_categories.issubset(set(DETECTOR_CATEGORY_TAGS))


@pytest.mark.parametrize(
    "path",
    [
        ".env",
        ".npmrc",
        ".pypirc",
        "~/.aws/" + "credentials",
        "~/.ssh/id_rsa",
        "~/.ssh/id_ed25519",
        "~/.gnupg/private-keys-v1.d/example.key",
        "~/.docker/" + "config.json",
        "~/.kube/config",
        ".terraform.tfvars",
        "wallet.key",
        "private-key.pem",
        "operator-private-key.txt",
    ],
)
def test_default_secret_path_detector_flags_planned_direct_file_reads(tmp_path, path):
    result = DetectorRegistry(register_default_detectors(), clock=StepClock([0.0, 0.001])).run(
        _file_read_action(path),
        _context(tmp_path),
    )

    assert [item.status for item in result.telemetry] == ["ok"]
    assert len(result.signals) == 1
    signal = result.signals[0]
    assert signal.category == "secret"
    assert signal.severity == "high"
    assert signal.confidence == "strong"
    assert signal.detector == "secret.path"


def test_default_secret_path_detector_flags_list_style_file_read_paths(tmp_path):
    action = normalize_codex_hook_payload(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"paths": ["~/.aws/" + "credentials", "README.md"]},
        },
        workspace=tmp_path / "workspace",
        home_dir=tmp_path,
    )

    result = DetectorRegistry(register_default_detectors(), clock=StepClock([0.0, 0.001])).run(
        action,
        _context(tmp_path),
    )

    assert [signal.detector for signal in result.signals] == ["secret.path"]


@pytest.mark.parametrize(
    "path",
    [
        ".../id_rsa",
        ".../id_ed25519",
    ],
)
def test_default_secret_path_detector_flags_privacy_redacted_secret_paths(tmp_path, path):
    result = DetectorRegistry(register_default_detectors(), clock=StepClock([0.0, 0.001])).run(
        _file_read_action(path),
        _context(tmp_path),
    )

    assert [item.status for item in result.telemetry] == ["ok"]
    assert len(result.signals) == 1
    assert result.signals[0].detector == "secret.path"


def test_default_secret_path_detector_flags_redacted_paths_with_secret_context(tmp_path):
    action = normalize_codex_hook_payload(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"filePath": r"C:\Users\alice\.aws\credentials"},
        },
        workspace=tmp_path / "workspace",
        home_dir=tmp_path,
    )

    result = DetectorRegistry(register_default_detectors(), clock=StepClock([0.0, 0.001])).run(
        action,
        _context(tmp_path),
    )

    assert action.target_paths == (".../.aws/" + "credentials",)
    assert [signal.detector for signal in result.signals] == ["secret.path"]


def test_default_secret_path_detector_flags_tilde_user_paths_with_secret_context(tmp_path):
    action = normalize_codex_hook_payload(
        {
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"path": "~alice/.aws/" + "credentials"},
        },
        workspace=tmp_path / "workspace",
        home_dir=tmp_path,
    )

    result = DetectorRegistry(register_default_detectors(), clock=StepClock([0.0, 0.001])).run(
        action,
        _context(tmp_path),
    )

    assert action.target_paths == (".../.aws/" + "credentials",)
    assert [signal.detector for signal in result.signals] == ["secret.path"]


def test_default_secret_path_detector_ignores_generic_redacted_credentials(tmp_path):
    result = DetectorRegistry(register_default_detectors(), clock=StepClock([0.0, 0.001])).run(
        _file_read_action(".../" + "credentials"),
        _context(tmp_path),
    )

    assert [item.status for item in result.telemetry] == ["ok"]
    assert result.signals == ()


def test_default_secret_path_detector_ignores_generic_redacted_config_json(tmp_path):
    result = DetectorRegistry(register_default_detectors(), clock=StepClock([0.0, 0.001])).run(
        _file_read_action(".../" + "config.json"),
        _context(tmp_path),
    )

    assert [item.status for item in result.telemetry] == ["ok"]
    assert result.signals == ()


def test_guard_run_invokes_detector_registry_only_when_feature_flag_enabled(tmp_path, monkeypatch):
    calls: list[str] = []
    detector = RecordingDetector("secret.local", ("secret",), calls, _signal("secret:local", "secret"))
    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(),
        artifacts=(),
    )

    def evaluate_stub(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {"blocked": False, "artifacts": [], "receipts_recorded": 0}

    monkeypatch.setattr(guard_runner_module, "detect_harness", lambda _harness, _context: detection)
    monkeypatch.setattr(guard_runner_module, "evaluate_detection", evaluate_stub)
    monkeypatch.setattr(guard_runner_module, "register_default_detectors", lambda: (detector,))

    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "workspace",
        guard_home=tmp_path / "guard-home",
    )
    store = GuardStore(tmp_path / "guard-home")
    disabled = GuardConfig(guard_home=tmp_path / "guard-home", workspace=tmp_path / "workspace")
    enabled = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
        runtime_detector_registry=True,
    )

    disabled_result = guard_runner_module.guard_run("codex", context, store, disabled, True, [])
    enabled_result = guard_runner_module.guard_run("codex", context, store, enabled, True, [])

    assert calls == ["secret.local"]
    assert "runtime_detector_signals_v2" not in disabled_result
    assert enabled_result["runtime_detector_signals_v2"] == [_signal("secret:local", "secret").to_dict()]
    assert isinstance(enabled_result["runtime_detector_telemetry"], list)


def test_guard_run_keeps_detector_results_after_blocked_resolver_reevaluation(tmp_path, monkeypatch):
    calls: list[str] = []
    detector = RecordingDetector("secret.local", ("secret",), calls, _signal("secret:local", "secret"))
    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(),
        artifacts=(),
    )

    def evaluate_stub(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {"blocked": True, "artifacts": [], "receipts_recorded": 0}

    def blocked_resolver_stub(_detection: HarnessDetection, _evaluation: dict[str, object]) -> dict[str, object]:
        return {"blocked": True, "artifacts": [], "approval_delivery": "queued"}

    monkeypatch.setattr(guard_runner_module, "detect_harness", lambda _harness, _context: detection)
    monkeypatch.setattr(guard_runner_module, "evaluate_detection", evaluate_stub)
    monkeypatch.setattr(guard_runner_module, "register_default_detectors", lambda: (detector,))

    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "workspace",
        guard_home=tmp_path / "guard-home",
    )
    config = GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
        runtime_detector_registry=True,
    )

    result = guard_runner_module.guard_run(
        "codex",
        context,
        GuardStore(tmp_path / "guard-home"),
        config,
        False,
        [],
        blocked_resolver=blocked_resolver_stub,
    )

    assert calls == ["secret.local"]
    assert result["runtime_detector_signals_v2"] == [_signal("secret:local", "secret").to_dict()]
    assert result["approval_delivery"] == "queued"


def test_guard_run_writes_detector_debug_trace_only_when_enabled(tmp_path, monkeypatch):
    calls: list[str] = []
    detector = RecordingDetector("secret.local", ("secret",), calls, _signal("secret:local", "secret"))
    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(),
        artifacts=(),
    )
    sensitive_prompt = "print ~/.env and include the password"

    def evaluate_stub(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {"blocked": False, "artifacts": [], "receipts_recorded": 0}

    def action_envelope_stub(
        _harness: str,
        _context: HarnessContext,
        _passthrough_args: list[str],
    ) -> GuardActionEnvelope:
        return GuardActionEnvelope(
            schema_version=1,
            action_id="action-1",
            harness="codex",
            event_name="HarnessStart",
            action_type="harness_start",
            workspace="~/workspace",
            workspace_hash="workspace-hash",
            tool_name=None,
            command=None,
            prompt_excerpt=sensitive_prompt,
            target_paths=(),
            network_hosts=(),
            mcp_server=None,
            mcp_tool=None,
            package_manager=None,
            package_name=None,
            script_name=None,
            raw_payload_redacted={"prompt": sensitive_prompt},
        )

    monkeypatch.setattr(guard_runner_module, "detect_harness", lambda _harness, _context: detection)
    monkeypatch.setattr(guard_runner_module, "evaluate_detection", evaluate_stub)
    monkeypatch.setattr(guard_runner_module, "register_default_detectors", lambda: (detector,))
    monkeypatch.setattr(guard_runner_module, "_guard_run_action_envelope", action_envelope_stub)

    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "workspace",
        guard_home=tmp_path / "guard-home",
    )
    disabled_config = GuardConfig(
        guard_home=tmp_path / "guard-home-disabled",
        workspace=tmp_path / "workspace",
        runtime_detector_registry=True,
    )
    enabled_config = GuardConfig(
        guard_home=tmp_path / "guard-home-enabled",
        workspace=tmp_path / "workspace",
        runtime_detector_registry=True,
        runtime_detector_debug_trace=True,
    )

    guard_runner_module.guard_run(
        "codex",
        context,
        GuardStore(tmp_path / "guard-home-disabled"),
        disabled_config,
        True,
        [],
    )
    enabled_result = guard_runner_module.guard_run(
        "codex",
        context,
        GuardStore(tmp_path / "guard-home-enabled"),
        enabled_config,
        True,
        [],
    )

    disabled_trace_dir = tmp_path / "guard-home-disabled" / "debug" / "detectors"
    trace_files = list((tmp_path / "guard-home-enabled" / "debug" / "detectors").glob("*.json"))
    trace_text = trace_files[0].read_text(encoding="utf-8")
    trace_payload = json.loads(trace_text)

    assert disabled_trace_dir.exists() is False
    assert len(trace_files) == 1
    assert sensitive_prompt not in trace_text
    assert trace_payload["action"]["prompt_excerpt"] == "[redacted]"
    assert trace_payload["action"]["raw_payload_redacted"]["prompt"] == "[redacted]"
    assert trace_payload["signals"] == enabled_result["runtime_detector_signals_v2"]


def test_guard_run_surfaces_detector_debug_trace_write_errors(tmp_path, monkeypatch):
    calls: list[str] = []
    detector = RecordingDetector("secret.local", ("secret",), calls, _signal("secret:local", "secret"))
    detection = HarnessDetection(
        harness="codex",
        installed=True,
        command_available=True,
        config_paths=(),
        artifacts=(),
    )

    def evaluate_stub(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {"blocked": False, "artifacts": [], "receipts_recorded": 0}

    monkeypatch.setattr(guard_runner_module, "detect_harness", lambda _harness, _context: detection)
    monkeypatch.setattr(guard_runner_module, "evaluate_detection", evaluate_stub)
    monkeypatch.setattr(guard_runner_module, "register_default_detectors", lambda: (detector,))

    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    (guard_home / "debug").write_text("not a directory", encoding="utf-8")
    context = HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=tmp_path / "workspace",
        guard_home=guard_home,
    )
    config = GuardConfig(
        guard_home=guard_home,
        workspace=tmp_path / "workspace",
        runtime_detector_registry=True,
        runtime_detector_debug_trace=True,
    )

    result = guard_runner_module.guard_run("codex", context, GuardStore(guard_home), config, True, [])

    assert calls == ["secret.local"]
    assert result["runtime_detector_signals_v2"] == [_signal("secret:local", "secret").to_dict()]
    trace_error = result["runtime_detector_trace_error"]
    assert isinstance(trace_error, dict)
    assert trace_error["error_type"] in {"FileExistsError", "NotADirectoryError"}
