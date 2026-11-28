"""Google Gemma 4 security finding verifier integration.

Utilizes Google's Gemma 4 open models (gemma-4-26b-a4b-it, gemma-4-31b-it) via
the Gemini API to evaluate and filter false-positive static security findings
such as DANGEROUS_DYNAMIC_EXECUTION, SHELL_INJECTION_PATTERN, and HARDCODED_SECRET (#3531, #3340).
"""

from __future__ import annotations

import os
import re
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from ..models import CheckResult, Finding

DEFAULT_GEMMA_MODEL = "gemma-4-26b-a4b-it"
GEMMA_31B_MODEL = "gemma-4-31b-it"
SUPPORTED_GEMMA_MODELS = (DEFAULT_GEMMA_MODEL, GEMMA_31B_MODEL)


class GemmaVerificationVerdict(str, Enum):
    """Verdict from Gemma 4 security verification."""

    VULNERABILITY = "VULNERABILITY"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass(frozen=True, slots=True)
class GemmaFindingVerification:
    """Individual finding verification result from Gemma 4."""

    file_path: str
    rule_id: str
    verdict: GemmaVerificationVerdict
    confidence: float
    explanation: str
    model: str


@dataclass(frozen=True, slots=True)
class GemmaVerificationSummary:
    """Overall summary of Gemma 4 findings verification."""

    verified_count: int
    vulnerabilities_confirmed: int
    false_positives_filtered: int
    model_used: str
    verifications: tuple[GemmaFindingVerification, ...]


def _get_api_key(api_key: str | None = None) -> str | None:
    if api_key:
        return api_key
    try:
        from dotenv import find_dotenv, load_dotenv

        env_file = find_dotenv(usecwd=True)
        if env_file:
            load_dotenv(env_file)
    except Exception:
        pass
    return os.environ.get("GEMINI_API_KEY") or os.environ.get("GEMMA_API_KEY")


def is_gemma_available(api_key: str | None = None) -> bool:
    """Check if the google-genai SDK and an API key are available."""
    if not _get_api_key(api_key):
        return False
    try:
        import google.genai  # noqa: F401

        return True
    except ImportError:
        return False


def build_verification_prompt(rule_id: str, snippet: str, file_path: str) -> str:
    """Construct an evaluation prompt for Gemma 4."""
    return f"""You are a specialized application security expert analyzing code for potential vulnerabilities.
A static analysis tool flagged the following code under rule '{rule_id}'.

File: {file_path}
Rule ID: {rule_id}

Code:
```
{snippet}
```

Instructions:
1. Carefully inspect the code context and determine whether this is an authentic, exploitable
   security vulnerability or a false positive.
   - For DANGEROUS_DYNAMIC_EXECUTION: Is eval() or new Function() executing dynamic code,
     or is it merely appearing inside a string literal, comment, regex pattern, or type?
   - For SHELL_INJECTION_PATTERN: Is untrusted input dynamically interpolated into a shell sink,
     or is this safe structured argv invocation, benign logging, or documentation example?
   - For HARDCODED_SECRET: Is this an active real credential, or a placeholder/test fixture?
2. Provide your verdict: VULNERABILITY or FALSE_POSITIVE.
3. Provide your confidence score between 0.0 and 1.0.
4. Provide a concise explanation.

Response Format:
VERDICT: [VULNERABILITY or FALSE_POSITIVE]
CONFIDENCE: [0.0 to 1.0]
EXPLANATION: [Concise rationale]
"""


def _parse_gemma_response(response_text: str, file_path: str, rule_id: str, model: str) -> GemmaFindingVerification:
    verdict = GemmaVerificationVerdict.INCONCLUSIVE
    confidence = 0.5
    explanation = response_text.strip()

    verdict_match = re.search(r"VERDICT:\s*(VULNERABILITY|FALSE_POSITIVE)", response_text, re.IGNORECASE)
    if verdict_match:
        verdict_str = verdict_match.group(1).upper()
        verdict = (
            GemmaVerificationVerdict.VULNERABILITY
            if verdict_str == "VULNERABILITY"
            else GemmaVerificationVerdict.FALSE_POSITIVE
        )

    conf_match = re.search(r"CONFIDENCE:\s*([0-1](?:\.\d+)?)", response_text, re.IGNORECASE)
    if conf_match:
        try:
            confidence = float(conf_match.group(1))
        except ValueError:
            confidence = 0.8

    expl_match = re.search(r"EXPLANATION:\s*(.+)", response_text, re.IGNORECASE | re.DOTALL)
    if expl_match:
        explanation = expl_match.group(1).strip()

    return GemmaFindingVerification(
        file_path=file_path,
        rule_id=rule_id,
        verdict=verdict,
        confidence=confidence,
        explanation=explanation,
        model=model,
    )


def verify_finding_with_gemma(
    finding: Finding,
    snippet: str,
    *,
    api_key: str | None = None,
    model: str = DEFAULT_GEMMA_MODEL,
) -> GemmaFindingVerification:
    """Verify a single finding using Gemma 4 with high thinking level reasoning."""
    resolved_key = _get_api_key(api_key)
    if not resolved_key:
        return GemmaFindingVerification(
            file_path=finding.file_path or "",
            rule_id=finding.rule_id,
            verdict=GemmaVerificationVerdict.INCONCLUSIVE,
            confidence=0.0,
            explanation="API key unavailable",
            model=model,
        )

    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=resolved_key)
        prompt = build_verification_prompt(finding.rule_id, snippet, finding.file_path or "")

        response = client.models.generate_content(
            model=model,
            contents=prompt,
            config=types.GenerateContentConfig(thinking_config=types.ThinkingConfig(thinking_level="high")),
        )

        resp_text = response.text or ""
        return _parse_gemma_response(resp_text, finding.file_path or "", finding.rule_id, model)
    except Exception as exc:
        return GemmaFindingVerification(
            file_path=finding.file_path or "",
            rule_id=finding.rule_id,
            verdict=GemmaVerificationVerdict.INCONCLUSIVE,
            confidence=0.0,
            explanation=f"Gemma model verification error: {exc}",
            model=model,
        )


def _extract_finding_snippet(base_dir: Path, finding: Finding, window_lines: int = 10) -> str:
    """Extract code context for a finding."""
    if not finding.file_path:
        return finding.description
    target = base_dir / finding.file_path
    if not target.is_file():
        return finding.description
    try:
        lines = target.read_text(encoding="utf-8", errors="ignore").splitlines()
        target_line = (finding.line_number or 1) - 1
        start = max(0, target_line - window_lines // 2)
        end = min(len(lines), start + window_lines)
        return "\n".join(lines[start:end])
    except OSError:
        return finding.description


def verify_check_results_with_gemma(
    check_results: Sequence[CheckResult],
    base_dir: Path,
    *,
    api_key: str | None = None,
    model: str = DEFAULT_GEMMA_MODEL,
    confidence_threshold: float = 0.8,
) -> tuple[tuple[CheckResult, ...], GemmaVerificationSummary]:
    """Filter or annotate check results using Gemma 4 reasoning."""
    verifications: list[GemmaFindingVerification] = []
    filtered_results: list[CheckResult] = []
    false_positives_filtered = 0
    vulnerabilities_confirmed = 0

    target_rules = {"DANGEROUS_DYNAMIC_EXECUTION", "SHELL_INJECTION_PATTERN", "HARDCODED_SECRET"}

    for result in check_results:
        if result.passed or not result.findings:
            filtered_results.append(result)
            continue

        retained_findings: list[Finding] = []
        for finding in result.findings:
            if finding.rule_id not in target_rules:
                retained_findings.append(finding)
                continue

            snippet = _extract_finding_snippet(base_dir, finding)
            verification = verify_finding_with_gemma(finding, snippet, api_key=api_key, model=model)
            verifications.append(verification)

            if (
                verification.verdict == GemmaVerificationVerdict.FALSE_POSITIVE
                and verification.confidence >= confidence_threshold
            ):
                false_positives_filtered += 1
            else:
                if verification.verdict == GemmaVerificationVerdict.VULNERABILITY:
                    vulnerabilities_confirmed += 1
                retained_findings.append(finding)

        if not retained_findings and result.findings:
            # All findings were verified false positives by Gemma 4!
            filtered_results.append(
                CheckResult(
                    name=result.name,
                    passed=True,
                    points=result.max_points,
                    max_points=result.max_points,
                    message=f"{result.message} (false positives filtered by Gemma 4)",
                    findings=(),
                    applicable=result.applicable,
                )
            )
        else:
            filtered_results.append(
                CheckResult(
                    name=result.name,
                    passed=bool(result.passed or not retained_findings),
                    points=result.max_points if not retained_findings else result.points,
                    max_points=result.max_points,
                    message=result.message,
                    findings=tuple(retained_findings),
                    applicable=result.applicable,
                )
            )

    summary = GemmaVerificationSummary(
        verified_count=len(verifications),
        vulnerabilities_confirmed=vulnerabilities_confirmed,
        false_positives_filtered=false_positives_filtered,
        model_used=model,
        verifications=tuple(verifications),
    )

    return tuple(filtered_results), summary
