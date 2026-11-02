"""Unit and integration tests for Gemma 4 security verifier."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from codex_plugin_scanner.integrations.gemma_verifier import (
    DEFAULT_GEMMA_MODEL,
    GemmaFindingVerification,
    GemmaVerificationVerdict,
    _parse_gemma_response,
    build_verification_prompt,
    is_gemma_available,
    verify_check_results_with_gemma,
    verify_finding_with_gemma,
)
from codex_plugin_scanner.models import CheckResult, Finding, Severity


class TestGemmaVerifierUnits:
    def test_is_gemma_available_no_key(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("GEMINI_API_KEY", raising=False)
        monkeypatch.delenv("GEMMA_API_KEY", raising=False)
        assert is_gemma_available(None) is False

    def test_is_gemma_available_with_key(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("GEMINI_API_KEY", "test-key")
        assert is_gemma_available() is True

    def test_build_verification_prompt(self):
        prompt = build_verification_prompt("DANGEROUS_DYNAMIC_EXECUTION", "eval(userInput)", "src/index.js")
        assert "DANGEROUS_DYNAMIC_EXECUTION" in prompt
        assert "src/index.js" in prompt
        assert "eval(userInput)" in prompt

    def test_parse_gemma_response_vulnerability(self):
        raw = """VERDICT: VULNERABILITY
CONFIDENCE: 0.95
EXPLANATION: Real dynamic code execution sink directly executing untrusted user input."""
        res = _parse_gemma_response(raw, "src/index.js", "DANGEROUS_DYNAMIC_EXECUTION", DEFAULT_GEMMA_MODEL)
        assert res.verdict == GemmaVerificationVerdict.VULNERABILITY
        assert res.confidence == 0.95
        assert "Real dynamic code execution" in res.explanation

    def test_parse_gemma_response_false_positive(self):
        raw = """VERDICT: FALSE_POSITIVE
CONFIDENCE: 0.99
EXPLANATION: String literal mentioning eval() for logging purposes."""
        res = _parse_gemma_response(raw, "src/logger.js", "DANGEROUS_DYNAMIC_EXECUTION", DEFAULT_GEMMA_MODEL)
        assert res.verdict == GemmaVerificationVerdict.FALSE_POSITIVE
        assert res.confidence == 0.99
        assert "String literal" in res.explanation

    def test_verify_check_results_filters_false_positives(self, tmp_path: Path):
        code_file = tmp_path / "msg.js"
        code_file.write_text('const msg = "eval() forbidden";\n', encoding="utf-8")

        mock_finding = Finding(
            rule_id="DANGEROUS_DYNAMIC_EXECUTION",
            severity=Severity.HIGH,
            category="code-quality",
            title="Dynamic code execution detected",
            description="msg.js uses eval()",
            remediation="Remove eval()",
            file_path="msg.js",
            line_number=1,
        )

        initial_result = CheckResult(
            name="No eval or Function constructor",
            passed=False,
            points=0,
            max_points=5,
            message="Found: msg.js: eval()",
            findings=(mock_finding,),
        )

        with patch("codex_plugin_scanner.integrations.gemma_verifier.verify_finding_with_gemma") as mock_verify:
            mock_verify.return_value = GemmaFindingVerification(
                file_path="msg.js",
                rule_id="DANGEROUS_DYNAMIC_EXECUTION",
                verdict=GemmaVerificationVerdict.FALSE_POSITIVE,
                confidence=0.95,
                explanation="String literal",
                model=DEFAULT_GEMMA_MODEL,
            )

            filtered, summary = verify_check_results_with_gemma(
                [initial_result],
                tmp_path,
                api_key="mock-key",
            )

            assert len(filtered) == 1
            assert filtered[0].passed is True
            assert filtered[0].points == 5
            assert summary.false_positives_filtered == 1


class TestLiveGemmaIntegration:
    @pytest.mark.skipif(
        not os.environ.get("GEMINI_API_KEY"),
        reason="GEMINI_API_KEY required for live test",
    )
    def test_live_gemma_eval_verification(self):
        finding = Finding(
            rule_id="DANGEROUS_DYNAMIC_EXECUTION",
            severity=Severity.HIGH,
            category="code-quality",
            title="Dynamic code execution detected",
            description="eval() usage",
            file_path="test.js",
        )
        res = verify_finding_with_gemma(
            finding,
            'const msg = "eval() is prohibited here";',
            api_key=os.environ.get("GEMINI_API_KEY"),
        )
        assert res.verdict == GemmaVerificationVerdict.FALSE_POSITIVE
        assert res.confidence >= 0.8
