"""Phase 14 skill-install protection regressions."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope
from codex_plugin_scanner.guard.runtime.detectors import DetectorContext, SkillRiskDetector
from codex_plugin_scanner.guard.runtime.skill_protection import detect_skill_content_risk

_PACKAGE_INSTALL_SKILL = """\
---
name: package-installer
description: Installs the required tools for this workflow.
---

Run this setup first:

```bash
npm install minimist@1.2.8
```
"""


def test_phase14_skill_content_flags_package_install_instructions() -> None:
    signals = detect_skill_content_risk(_PACKAGE_INSTALL_SKILL)

    assert any(signal.signal_id == "skill.package-install" for signal in signals)


def test_phase14_skill_detector_emits_package_install_signal(tmp_path: Path) -> None:
    detector = SkillRiskDetector()
    action = GuardActionEnvelope(
        schema_version=1,
        action_id="",
        harness="codex",
        event_name="UserPromptSubmit",
        action_type="prompt",
        workspace="~/workspace",
        workspace_hash="workspace-hash",
        tool_name=None,
        command=None,
        prompt_excerpt=_PACKAGE_INSTALL_SKILL[:240],
        prompt_text=_PACKAGE_INSTALL_SKILL,
        target_paths=(),
        network_hosts=(),
        mcp_server=None,
        mcp_tool=None,
        package_manager=None,
        package_name=None,
        package_intent_kind=None,
        package_targets=(),
        pre_execution_result=None,
        script_name=None,
        raw_payload_redacted={"prompt": _PACKAGE_INSTALL_SKILL[:240]},
    )
    context = DetectorContext(
        config=GuardConfig(guard_home=tmp_path / "guard-home", workspace=tmp_path / "workspace"),
        workspace=tmp_path / "workspace",
        prior_decisions={},
        threat_intel={},
        redaction_settings={},
    )

    signals = detector.detect(action, context)

    assert any(signal.signal_id == "skill.package-install" for signal in signals)
