"""Tests for GuardBypassDetector and composition_rules."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope
from codex_plugin_scanner.guard.runtime.composition_rules import compose_action_from_signals
from codex_plugin_scanner.guard.runtime.detectors import DetectorContext, GuardBypassDetector
from codex_plugin_scanner.guard.runtime.signals import RiskSignalV2


def _make_signal(
    signal_id: str = "test:signal",
    category: str = "bypass",
    severity: str = "high",
    confidence: str = "strong",
    detector: str = "test.detector",
) -> RiskSignalV2:
    return RiskSignalV2(
        signal_id=signal_id,
        category=category,
        severity=severity,
        confidence=confidence,
        detector=detector,
        title="Test",
        plain_reason="test reason",
        technical_detail=None,
        evidence_ref=None,
        redaction_level="none",
        false_positive_hint=None,
        advisory_id=None,
    )


def _bypass_envelope(command: str) -> GuardActionEnvelope:
    return GuardActionEnvelope(
        schema_version=1,
        action_id="",
        harness="codex",
        event_name="BashCommand",
        action_type="shell_command",
        workspace=None,
        workspace_hash=None,
        tool_name="bash",
        command=command,
        prompt_excerpt=None,
        prompt_text=None,
        target_paths=(),
        network_hosts=(),
        mcp_server=None,
        mcp_tool=None,
        package_manager=None,
        package_name=None,
        script_name=None,
        raw_payload_redacted={},
    )


def _detector_context(tmp_path: Path) -> DetectorContext:
    return DetectorContext(
        config=GuardConfig(guard_home=tmp_path / "guard-home", workspace=tmp_path / "workspace"),
        workspace=tmp_path / "workspace",
        prior_decisions={},
        threat_intel={},
        redaction_settings={},
    )


class TestGuardBypassDetector:
    detector = GuardBypassDetector()

    def _detect(self, command: str, tmp_path: Path) -> tuple:
        ctx = _detector_context(tmp_path)
        env = _bypass_envelope(command)
        return self.detector.detect(env, ctx)

    def test_pip_uninstall_holguard(self, tmp_path: Path) -> None:
        signals = self._detect("pip uninstall holguard", tmp_path)
        assert any(s.signal_id == "bypass:guard-uninstall" for s in signals)
        assert all(s.severity == "critical" for s in signals)

    def test_pip3_uninstall_holguard_with_y(self, tmp_path: Path) -> None:
        signals = self._detect("pip3 uninstall -y holguard", tmp_path)
        assert any(s.signal_id == "bypass:guard-uninstall" for s in signals)

    def test_pip_uninstall_codex_plugin_scanner(self, tmp_path: Path) -> None:
        signals = self._detect("pip uninstall codex-plugin-scanner", tmp_path)
        assert any(s.signal_id == "bypass:guard-uninstall" for s in signals)

    def test_brew_uninstall_hol_guard(self, tmp_path: Path) -> None:
        signals = self._detect("brew uninstall hol-guard", tmp_path)
        assert any(s.signal_id == "bypass:guard-uninstall" for s in signals)

    def test_rm_guard_db(self, tmp_path: Path) -> None:
        signals = self._detect("rm ~/.hol-guard/guard.db", tmp_path)
        assert any(s.signal_id == "bypass:guard-config-destroy" for s in signals)

    def test_rm_guard_home(self, tmp_path: Path) -> None:
        signals = self._detect("rm -rf ~/.hol-guard", tmp_path)
        assert any(s.signal_id == "bypass:guard-config-destroy" for s in signals)

    def test_kill_guard_daemon(self, tmp_path: Path) -> None:
        signals = self._detect("kill -9 $(pgrep hol-guard)", tmp_path)
        assert any(s.signal_id == "bypass:guard-daemon-kill" for s in signals)

    def test_pkill_hol_guard(self, tmp_path: Path) -> None:
        signals = self._detect("pkill -f hol-guard", tmp_path)
        assert any(s.signal_id == "bypass:guard-daemon-kill" for s in signals)

    def test_pkill_wireguard_is_not_bypass(self, tmp_path: Path) -> None:
        signals = self._detect("pkill -f wireguard", tmp_path)
        assert not any(s.signal_id == "bypass:guard-daemon-kill" for s in signals)

    def test_rm_myguard_db_backup_is_not_bypass(self, tmp_path: Path) -> None:
        signals = self._detect("rm ./myguard.db.backup", tmp_path)
        assert not any(s.signal_id == "bypass:guard-config-destroy" for s in signals)

    def test_pkill_safeguard_worker_is_not_bypass(self, tmp_path: Path) -> None:
        signals = self._detect("pkill -f safeguard-worker", tmp_path)
        assert not any(s.signal_id == "bypass:guard-daemon-kill" for s in signals)

    def test_launchctl_unload_guard(self, tmp_path: Path) -> None:
        signals = self._detect("launchctl unload ~/Library/LaunchAgents/hol-guard.plist", tmp_path)
        assert any(s.signal_id == "bypass:guard-daemon-kill" for s in signals)

    def test_benign_pip_install_not_flagged(self, tmp_path: Path) -> None:
        signals = self._detect("pip install requests", tmp_path)
        assert signals == ()

    def test_benign_rm_log_not_flagged(self, tmp_path: Path) -> None:
        signals = self._detect("rm -rf /tmp/myproject.log", tmp_path)
        assert signals == ()

    def test_benign_kill_other_process_not_flagged(self, tmp_path: Path) -> None:
        signals = self._detect("kill -9 12345", tmp_path)
        assert signals == ()

    def test_npm_uninstall_hol_guard(self, tmp_path: Path) -> None:
        signals = self._detect("npm uninstall -g hol-guard", tmp_path)
        assert any(s.signal_id == "bypass:guard-uninstall" for s in signals)


class TestComposeActionFromSignals:
    """Tests for composition_rules.compose_action_from_signals."""

    def test_no_signals_returns_base_action(self) -> None:
        result = compose_action_from_signals((), "allow")
        assert result.action == "allow"
        assert not result.upgraded
        assert not result.downgraded

    def test_no_signals_block_base(self) -> None:
        result = compose_action_from_signals((), "block")
        assert result.action == "block"

    def test_bypass_signal_upgrades_to_block(self) -> None:
        signal = _make_signal(
            signal_id="bypass:guard-uninstall", category="bypass", severity="critical", confidence="strong"
        )
        result = compose_action_from_signals((signal,), "allow")
        assert result.action == "block"
        assert result.upgraded

    def test_persistence_signal_upgrades_to_ask(self) -> None:
        signal = _make_signal(signal_id="persist:cron", category="persistence", severity="high", confidence="strong")
        result = compose_action_from_signals((signal,), "allow")
        assert result.action in ("ask", "block")
        assert result.upgraded

    def test_critical_risk_signal_upgrades_to_block(self) -> None:
        signal = _make_signal(signal_id="risk:critical", category="data_flow", severity="critical", confidence="strong")
        result = compose_action_from_signals((signal,), "allow")
        assert result.action == "block"
        assert result.upgraded

    def test_strong_fp_with_no_risk_downgrades_block_to_ask(self) -> None:
        fp = _make_signal(
            signal_id="fp:source-search:grep", category="false_positive", severity="info", confidence="strong"
        )
        result = compose_action_from_signals((fp,), "block")
        assert result.action == "ask"
        assert result.downgraded

    def test_strong_fp_source_search_downgrades_ask_to_warn(self) -> None:
        fp = _make_signal(
            signal_id="fp:source-search:grep", category="false_positive", severity="info", confidence="strong"
        )
        result = compose_action_from_signals((fp,), "ask")
        assert result.action == "warn"
        assert result.downgraded

    def test_bypass_beats_fp_downgrade(self) -> None:
        bypass = _make_signal(
            signal_id="bypass:guard-uninstall", category="bypass", severity="critical", confidence="strong"
        )
        fp = _make_signal(
            signal_id="fp:source-search:grep", category="false_positive", severity="info", confidence="strong"
        )
        result = compose_action_from_signals((bypass, fp), "allow")
        assert result.action == "block"
        assert result.upgraded
        assert not result.downgraded

    def test_fp_weak_confidence_does_not_downgrade(self) -> None:
        fp = _make_signal(
            signal_id="fp:source-search:grep", category="false_positive", severity="info", confidence="weak"
        )
        result = compose_action_from_signals((fp,), "block")
        assert result.action == "block"
        assert not result.downgraded

    def test_composition_result_is_frozen(self) -> None:
        result = compose_action_from_signals((), "allow")
        with pytest.raises((AttributeError, TypeError)):
            result.action = "block"  # type: ignore[misc]
