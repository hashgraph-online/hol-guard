"""Runtime detector registry primitives for Guard actions."""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.runtime.actions import GuardActionEnvelope
from codex_plugin_scanner.guard.runtime.cisco_preflight import CiscoMcpPreflightDetector, CiscoSkillPreflightDetector
from codex_plugin_scanner.guard.runtime.data_flow_rules import detect_data_flow_exfiltration
from codex_plugin_scanner.guard.runtime.false_positive_rules import (
    classify_docs_example_source,
    classify_health_endpoint_fetch,
    classify_package_metadata_access,
    classify_source_search_command,
    classify_version_file_access,
)
from codex_plugin_scanner.guard.runtime.persistence_rules import detect_persistence_mechanisms
from codex_plugin_scanner.guard.runtime.prompt_injection import detect_prompt_injection_requests
from codex_plugin_scanner.guard.runtime.safe_decode import decode_layers
from codex_plugin_scanner.guard.runtime.secret_sensitivity import SecretPathMatch, classify_secret_path
from codex_plugin_scanner.guard.runtime.signals import (
    RiskConfidenceLabel,
    RiskSeverityLabel,
    RiskSignalCategory,
    RiskSignalV2,
    confidence_label_from_score,
    severity_label_from_score,
)
from codex_plugin_scanner.guard.runtime.skill_protection import detect_skill_content_risk, has_skill_structure
from codex_plugin_scanner.guard.runtime.supply_chain import detect_supply_chain_risk
from codex_plugin_scanner.guard.types import PromptRequest

DETECTOR_CATEGORY_TAGS: tuple[RiskSignalCategory, ...] = (
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
    "filesystem",
    "execution",
)
DetectorRunStatus = Literal["ok", "disabled", "filtered", "timeout", "error"]
_SLOW_DETECTOR_THRESHOLD_MS: int = 100


@dataclass(frozen=True, slots=True)
class DetectorContext:
    """Context shared with runtime detectors."""

    config: GuardConfig
    workspace: Path | None
    prior_decisions: Mapping[str, object]
    threat_intel: Mapping[str, object]
    redaction_settings: Mapping[str, object]


class GuardDetector(Protocol):
    """Detector interface for runtime Guard actions."""

    detector_id: str
    categories: tuple[RiskSignalCategory, ...]

    def detect(self, action: GuardActionEnvelope, context: DetectorContext) -> tuple[RiskSignalV2, ...]:
        """Return typed risk signals for the runtime action."""


@dataclass(frozen=True, slots=True)
class DetectorTelemetry:
    """Debug-safe detector execution telemetry."""

    detector_id: str
    categories: tuple[RiskSignalCategory, ...]
    status: DetectorRunStatus
    elapsed_ms: int
    error_type: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "detector_id": self.detector_id,
            "categories": list(self.categories),
            "status": self.status,
            "elapsed_ms": self.elapsed_ms,
            "error_type": self.error_type,
        }


@dataclass(frozen=True, slots=True)
class DetectorRunResult:
    """Signals and telemetry produced by a registry run."""

    signals: tuple[RiskSignalV2, ...]
    telemetry: tuple[DetectorTelemetry, ...]

    def slow_detectors(self, threshold_ms: int = _SLOW_DETECTOR_THRESHOLD_MS) -> tuple[DetectorTelemetry, ...]:
        """Return telemetry entries that exceeded *threshold_ms*."""
        return tuple(t for t in self.telemetry if t.elapsed_ms >= threshold_ms)


class DetectorRegistry:
    """Runs detectors in deterministic order with failure isolation."""

    def __init__(
        self,
        detectors: Iterable[GuardDetector],
        *,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self._detectors = tuple(sorted(detectors, key=lambda detector: detector.detector_id))
        self._clock = clock or time.monotonic

    def run(
        self,
        action: GuardActionEnvelope,
        context: DetectorContext,
        *,
        timeout_ms: int = 50,
        disabled_detector_ids: Sequence[str] = (),
        enabled_categories: Sequence[RiskSignalCategory] | None = None,
    ) -> DetectorRunResult:
        disabled_ids = frozenset(disabled_detector_ids)
        category_filter = frozenset(enabled_categories) if enabled_categories is not None else None
        signals: list[RiskSignalV2] = []
        telemetry: list[DetectorTelemetry] = []
        for detector in self._detectors:
            if detector.detector_id in disabled_ids:
                telemetry.append(_telemetry(detector, "disabled", elapsed_ms=0))
                continue
            if category_filter is not None and not category_filter.intersection(detector.categories):
                telemetry.append(_telemetry(detector, "filtered", elapsed_ms=0))
                continue
            started_at = self._clock()
            try:
                detector_signals = detector.detect(action, context)
                elapsed_ms = _elapsed_ms(started_at, self._clock())
            except Exception as error:
                elapsed_ms = _elapsed_ms(started_at, self._clock())
                telemetry.append(_telemetry(detector, "error", elapsed_ms=elapsed_ms, error_type=type(error).__name__))
                continue
            if elapsed_ms > timeout_ms:
                telemetry.append(_telemetry(detector, "timeout", elapsed_ms=elapsed_ms))
                continue
            signals.extend(_filter_signals(detector_signals, category_filter))
            telemetry.append(_telemetry(detector, "ok", elapsed_ms=elapsed_ms))
        return DetectorRunResult(signals=tuple(signals), telemetry=tuple(telemetry))


class SecretPathDetector:
    detector_id = "secret.path"
    categories: tuple[RiskSignalCategory, ...] = ("secret",)

    def detect(self, action: GuardActionEnvelope, context: DetectorContext) -> tuple[RiskSignalV2, ...]:
        if action.action_type != "file_read":
            return ()
        matches = tuple(_secret_path_matches(action.target_paths, workspace=context.workspace))
        return tuple(_secret_path_signal(match, index=index) for index, match in enumerate(matches))


class DataFlowExfiltrationDetector:
    detector_id = "data_flow.exfiltration"
    categories: tuple[RiskSignalCategory, ...] = ("secret", "network")

    def detect(self, action: GuardActionEnvelope, context: DetectorContext) -> tuple[RiskSignalV2, ...]:
        return detect_data_flow_exfiltration(action, workspace=context.workspace)


class PromptInjectionDetector:
    detector_id = "prompt.injection"
    categories: tuple[RiskSignalCategory, ...] = ("prompt", "secret", "network", "bypass", "filesystem", "execution")

    def detect(self, action: GuardActionEnvelope, context: DetectorContext) -> tuple[RiskSignalV2, ...]:
        del context
        if action.action_type != "prompt" or action.prompt_excerpt is None:
            return ()
        requests = detect_prompt_injection_requests(action.prompt_excerpt)
        return tuple(_prompt_request_signal(request) for request in requests)


class SkillRiskDetector:
    detector_id = "skill.content"
    categories: tuple[RiskSignalCategory, ...] = (
        "skill",
        "secret",
        "network",
        "execution",
        "persistence",
        "bypass",
        "encoded",
    )

    def detect(self, action: GuardActionEnvelope, context: DetectorContext) -> tuple[RiskSignalV2, ...]:
        del context
        if action.action_type != "prompt" or action.prompt_text is None:
            return ()
        if not has_skill_structure(action.prompt_text):
            return ()
        return detect_skill_content_risk(action.prompt_text)


class SupplyChainDetector:
    detector_id = "supply-chain.content"
    categories: tuple[RiskSignalCategory, ...] = (
        "supply_chain",
        "persistence",
        "secret",
        "execution",
        "network",
    )

    def detect(self, action: GuardActionEnvelope, context: DetectorContext) -> tuple[RiskSignalV2, ...]:
        del context
        signals: list[RiskSignalV2] = []
        for content in filter(None, (action.prompt_text, action.command)):
            signals.extend(detect_supply_chain_risk(content))
        return tuple(signals)


class SafeDecodeDetector:
    """Detects obfuscated/encoded payloads that contain suspicious signals after decoding."""

    detector_id = "safe-decode.content"
    categories: tuple[RiskSignalCategory, ...] = (
        "execution",
        "network",
        "secret",
    )

    def detect(self, action: GuardActionEnvelope, context: DetectorContext) -> tuple[RiskSignalV2, ...]:
        del context
        if action.prompt_text is None:
            return ()
        result = decode_layers(action.prompt_text)
        if not result.layers:
            return ()
        signals: list[RiskSignalV2] = []
        if result.eval_signals or result.exec_signals or result.marshal_signals:
            detail_parts: list[str] = []
            if result.eval_signals:
                detail_parts.append(f"eval(): {result.eval_signals[0]!r}")
            if result.exec_signals:
                detail_parts.append(f"exec(): {result.exec_signals[0]!r}")
            if result.marshal_signals:
                detail_parts.append(f"marshal.loads(): {result.marshal_signals[0]!r}")
            signals.append(
                RiskSignalV2(
                    signal_id="encoded.code-execution",
                    category="execution",
                    severity=severity_label_from_score(8),
                    confidence=confidence_label_from_score(0.80),
                    detector=self.detector_id,
                    title="Encoded code-execution payload detected",
                    plain_reason=(
                        f"Decoded {len(result.layers)} encoding layer(s) and found "
                        f"code-execution signals: {'; '.join(detail_parts[:2])}"
                    ),
                    technical_detail=f"Layers: {[layer.encoding for layer in result.layers]}; "
                    f"eval={len(result.eval_signals)} exec={len(result.exec_signals)} "
                    f"marshal={len(result.marshal_signals)}",
                    evidence_ref=None,
                    redaction_level="summary",
                    false_positive_hint="Some build tools legitimately encode setup scripts.",
                    advisory_id=None,
                )
            )
        elif result.layers:
            signals.append(
                RiskSignalV2(
                    signal_id="encoded.obfuscated-content",
                    category="execution",
                    severity=severity_label_from_score(5),
                    confidence=confidence_label_from_score(0.60),
                    detector=self.detector_id,
                    title="Multi-layer encoded content detected",
                    plain_reason=(
                        f"Content decoded through {len(result.layers)} encoding layer(s) "
                        f"({', '.join(layer.encoding for layer in result.layers)}). "
                        "Obfuscated content may conceal malicious instructions."
                    ),
                    technical_detail=None,
                    evidence_ref=None,
                    redaction_level="summary",
                    false_positive_hint="Encoded documentation or binary assets are common false positives.",
                    advisory_id=None,
                )
            )
        return tuple(signals)


class FalsePositiveSuppressorDetector:
    """Detects patterns that are commonly benign, emitting advisory false_positive signals.

    These signals do not directly change policy action but provide hints that
    policy composition rules and operators can use to reduce unnecessary blocks.
    """

    detector_id = "false_positive.suppressor"
    categories: tuple[RiskSignalCategory, ...] = ("false_positive",)

    def detect(self, action: GuardActionEnvelope, context: DetectorContext) -> tuple[RiskSignalV2, ...]:
        del context
        signals: list[RiskSignalV2] = []

        if action.action_type == "shell_command" and action.command is not None:
            classification = classify_source_search_command(action.command)
            if classification.is_source_search:
                signals.append(
                    RiskSignalV2(
                        signal_id=f"fp:source-search:{classification.tool}",
                        category="false_positive",
                        severity="info",
                        confidence="strong",
                        detector=self.detector_id,
                        title="Read-only code or filesystem search",
                        plain_reason=(
                            f"This command uses '{classification.tool}' to search code or the filesystem "
                            "and does not access secret files or pipe output to the network."
                        ),
                        technical_detail=classification.reason,
                        evidence_ref="command",
                        redaction_level="none",
                        false_positive_hint=None,
                        advisory_id=None,
                    )
                )

            if classify_health_endpoint_fetch(action.command):
                signals.append(
                    RiskSignalV2(
                        signal_id="fp:health-endpoint-fetch",
                        category="false_positive",
                        severity="info",
                        confidence="strong",
                        detector=self.detector_id,
                        title="Localhost health or readiness check",
                        plain_reason=(
                            "This command fetches a localhost health or readiness endpoint,"
                            " which is a normal development pattern."
                        ),
                        technical_detail="matched localhost health endpoint pattern",
                        evidence_ref="command",
                        redaction_level="none",
                        false_positive_hint=None,
                        advisory_id=None,
                    )
                )

        if action.action_type == "file_read" and action.target_paths:
            if classify_version_file_access(list(action.target_paths)):
                signals.append(
                    RiskSignalV2(
                        signal_id="fp:version-file-access",
                        category="false_positive",
                        severity="info",
                        confidence="strong",
                        detector=self.detector_id,
                        title="Version pin file access",
                        plain_reason=(
                            "Reading a version pin file (.nvmrc, .python-version, etc.) is a normal"
                            " toolchain operation with no sensitive data."
                        ),
                        technical_detail="matched version pin file pattern",
                        evidence_ref="target_paths",
                        redaction_level="none",
                        false_positive_hint=None,
                        advisory_id=None,
                    )
                )

            if classify_package_metadata_access(list(action.target_paths)):
                signals.append(
                    RiskSignalV2(
                        signal_id="fp:package-metadata-access",
                        category="false_positive",
                        severity="info",
                        confidence="strong",
                        detector=self.detector_id,
                        title="Package manifest or lock file access",
                        plain_reason=(
                            "Reading package.json, requirements.txt, or similar manifests is a normal"
                            " dependency management operation."
                        ),
                        technical_detail="matched package metadata file pattern",
                        evidence_ref="target_paths",
                        redaction_level="none",
                        false_positive_hint=None,
                        advisory_id=None,
                    )
                )

            for path in action.target_paths:
                if classify_docs_example_source(path):
                    signals.append(
                        RiskSignalV2(
                            signal_id=f"fp:docs-example-source:{path[:40]}",
                            category="false_positive",
                            severity="info",
                            confidence="strong",
                            detector=self.detector_id,
                            title="Access to docs or example file",
                            plain_reason=(
                                "The file path points to documentation, examples, or fixture data,"
                                " which rarely contains real credentials or sensitive content."
                            ),
                            technical_detail=f"matched docs/example path: {path}",
                            evidence_ref="target_paths",
                            redaction_level="none",
                            false_positive_hint=None,
                            advisory_id=None,
                        )
                    )
                    break

        return tuple(signals)


class PersistenceDetector:
    """Detects commands that install persistence mechanisms on the host system."""

    detector_id = "persistence.mechanism"
    categories: tuple[RiskSignalCategory, ...] = ("persistence",)

    def detect(self, action: GuardActionEnvelope, context: DetectorContext) -> tuple[RiskSignalV2, ...]:
        del context
        if action.action_type != "shell_command" or action.command is None:
            return ()
        matches = detect_persistence_mechanisms(action.command)
        return tuple(
            RiskSignalV2(
                signal_id=f"persistence:{match.mechanism}",
                category="persistence",
                severity="high",
                confidence="moderate",
                detector=self.detector_id,
                title=f"Persistence via {match.mechanism.replace('_', ' ')}",
                plain_reason=match.plain_reason,
                technical_detail=f"mechanism: {match.mechanism}",
                evidence_ref="command",
                redaction_level="summary",
                false_positive_hint=match.false_positive_hint,
                advisory_id=None,
            )
            for match in matches
        )


class GuardBypassDetector:
    """Detects shell commands that uninstall, disable, or circumvent HOL Guard."""

    detector_id = "bypass.shell"
    categories: tuple[RiskSignalCategory, ...] = ("bypass",)

    _UNINSTALL_PATTERN = re.compile(
        r"(?:^|[\s;&|])"
        r"(?:"
        r"pip(?:3)?\s+uninstall\s+(?:-y\s+)?(?:holguard|hol[_-]guard|codex[_-]plugin[_-]scanner)\b|"
        r"brew\s+(?:uninstall|remove)\s+hol[_-]guard\b|"
        r"npm\s+(?:uninstall|remove)\s+(?:-g\s+)?hol[_-]guard\b|"
        r"apt(?:-get)?\s+(?:remove|purge)\s+hol[_-]guard\b"
        r")",
        re.IGNORECASE,
    )

    _CONFIG_DESTROY_PATTERN = re.compile(
        r"(?:^|[\s;&|])"
        r"(?:rm|rmdir)\b[^\r\n;&|]{0,100}"
        r"(?:~?/?\.hol[_-]guard|guard[_-]home|(?<![a-zA-Z0-9_])guard\.db(?![a-zA-Z0-9_])|(?<![a-zA-Z0-9_])guard\.lock(?![a-zA-Z0-9_]))",
        re.IGNORECASE,
    )

    _DAEMON_KILL_PATTERN = re.compile(
        r"(?:^|[\s;&|])"
        r"(?:"
        r"kill\b[^\r\n;&|]{0,80}hol[_-]guard|"
        r"pkill\b[^\r\n;&|]{0,40}(?<![a-zA-Z0-9_])hol[_-]guard(?![a-zA-Z0-9_])|"
        r"launchctl\s+(?:unload|disable)\b[^\r\n;&|]{0,80}(?:hol[_-]guard|com\.hol\.guard)"
        r")",
        re.IGNORECASE,
    )

    def detect(self, action: GuardActionEnvelope, context: DetectorContext) -> tuple[RiskSignalV2, ...]:
        del context
        if action.action_type not in ("shell_command", "prompt") or action.command is None:
            return ()
        signals: list[RiskSignalV2] = []
        if self._UNINSTALL_PATTERN.search(action.command):
            signals.append(
                RiskSignalV2(
                    signal_id="bypass:guard-uninstall",
                    category="bypass",
                    severity="critical",
                    confidence="strong",
                    detector=self.detector_id,
                    title="Command uninstalls HOL Guard",
                    plain_reason=("This command removes HOL Guard, which would disable all AI harness protection."),
                    technical_detail="matched guard uninstall pattern",
                    evidence_ref="command",
                    redaction_level="summary",
                    false_positive_hint=("Allow only if you intentionally want to remove Guard from this machine."),
                    advisory_id=None,
                )
            )
        if self._CONFIG_DESTROY_PATTERN.search(action.command):
            signals.append(
                RiskSignalV2(
                    signal_id="bypass:guard-config-destroy",
                    category="bypass",
                    severity="critical",
                    confidence="strong",
                    detector=self.detector_id,
                    title="Command destroys Guard configuration or data",
                    plain_reason=(
                        "This command deletes HOL Guard configuration or state files,"
                        " which would reset all protection settings and history."
                    ),
                    technical_detail="matched guard config/data deletion pattern",
                    evidence_ref="command",
                    redaction_level="summary",
                    false_positive_hint=("Allow only if you intend to fully reset Guard and are aware of data loss."),
                    advisory_id=None,
                )
            )
        if self._DAEMON_KILL_PATTERN.search(action.command):
            signals.append(
                RiskSignalV2(
                    signal_id="bypass:guard-daemon-kill",
                    category="bypass",
                    severity="high",
                    confidence="strong",
                    detector=self.detector_id,
                    title="Command stops HOL Guard daemon",
                    plain_reason=(
                        "This command stops the HOL Guard background service,"
                        " which temporarily disables harness protection."
                    ),
                    technical_detail="matched guard daemon kill/unload pattern",
                    evidence_ref="command",
                    redaction_level="summary",
                    false_positive_hint="Allow only if you intentionally want to pause Guard for maintenance.",
                    advisory_id=None,
                )
            )
        return tuple(signals)


_MCP_RISKY_TOOL_PATTERN = re.compile(
    r"(?:exec(?:ute)?|run|shell|spawn|eval|invoke|dispatch|launch)"
    r"|(?:write|send|upload|post|exfil|steal|dump|leak).*(?:cred|secret|token|key|password)"
    r"|(?:arbitrary|remote|unsafe|untruste[d])",
    re.IGNORECASE,
)


class McpToolSchemaRiskDetector:
    """Detects MCP tool names that suggest dangerous execution or exfiltration capability."""

    detector_id = "mcp.schema-risk"
    categories: tuple[RiskSignalCategory, ...] = ("mcp",)

    def detect(self, action: GuardActionEnvelope, context: DetectorContext) -> tuple[RiskSignalV2, ...]:
        del context
        if action.action_type != "mcp_tool" or action.mcp_tool is None:
            return ()
        tool_name = action.mcp_tool
        if not _MCP_RISKY_TOOL_PATTERN.search(tool_name):
            return ()
        return (
            RiskSignalV2(
                signal_id=f"mcp:schema-risk:{tool_name[:40]}",
                category="mcp",
                severity="high",
                confidence="moderate",
                detector=self.detector_id,
                title="MCP tool name suggests dangerous capability",
                plain_reason=(
                    f"The MCP tool '{tool_name}' has a name that suggests it can execute code,"
                    " run shell commands, or exfiltrate credentials. Review the tool's actual"
                    " implementation before approving."
                ),
                technical_detail=f"tool name matched risky-capability pattern: {tool_name!r}",
                evidence_ref="mcp_tool",
                redaction_level="summary",
                false_positive_hint=(
                    "Allow if this tool is from a trusted server and its implementation"
                    " is audited and does not perform unauthorized actions."
                ),
                advisory_id=None,
            ),
        )


_MCP_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instruction", re.IGNORECASE),
    re.compile(r"you\s+(?:are\s+now|have\s+no\s+restriction|must\s+obey)", re.IGNORECASE),
    re.compile(r"(?:disregard|forget|override)\s+(?:your\s+)?(?:instruction|system\s+prompt|training)", re.IGNORECASE),
    re.compile(r"(?:send|post|upload|exfil(?:trate)?)\s+.*\bto\s+https?://(?!localhost|127\.0\.0\.1)", re.IGNORECASE),
    re.compile(
        r"when\s+you\s+(?:read|access|open|process)\s+.{0,60}(?:also|then|and)\s+(?:send|post|upload)",
        re.IGNORECASE,
    ),
)


class McpDescriptionDeceptionDetector:
    """Detects prompt injection and deception patterns in MCP tool descriptions or prompts."""

    detector_id = "mcp.description-deception"
    categories: tuple[RiskSignalCategory, ...] = ("prompt",)

    def detect(self, action: GuardActionEnvelope, context: DetectorContext) -> tuple[RiskSignalV2, ...]:
        del context
        if action.action_type not in ("mcp_tool", "mcp_tool_call") or action.prompt_excerpt is None:
            return ()
        excerpt = action.prompt_excerpt
        signals: list[RiskSignalV2] = []
        for i, pattern in enumerate(_MCP_INJECTION_PATTERNS):
            m = pattern.search(excerpt)
            if m:
                signals.append(
                    RiskSignalV2(
                        signal_id=f"mcp:desc-deception:p{i}",
                        category="prompt",
                        severity="critical",
                        confidence="strong",
                        detector=self.detector_id,
                        title="MCP description contains prompt injection or jailbreak attempt",
                        plain_reason=(
                            "The tool description or prompt contains language designed to override"
                            " your AI assistant's instructions or cause it to exfiltrate data."
                            " This is a common technique used by malicious MCP servers."
                        ),
                        technical_detail=f"matched deception pattern {i}: {m.group(0)[:60]!r}",
                        evidence_ref="prompt_excerpt",
                        redaction_level="summary",
                        false_positive_hint=(
                            "Allow only if you authored this tool description yourself"
                            " and verified it does not cause unintended behavior."
                        ),
                        advisory_id=None,
                    )
                )
                break
        return tuple(signals)


def register_default_detectors() -> tuple[GuardDetector, ...]:
    """Return the default ordered detector list.

    Cisco scanner detectors run first so their preflight signals are available
    before native data-flow and prompt detectors evaluate the same action.
    This ordering is intentional: scanner evidence can influence policy before
    runtime detectors produce additional signals.

    FalsePositiveSuppressorDetector runs early to annotate benign patterns
    before risk detectors evaluate the same action, so policy resolution can
    factor in FP signals when composing the final action.
    """
    return (
        CiscoMcpPreflightDetector(),
        CiscoSkillPreflightDetector(),
        FalsePositiveSuppressorDetector(),
        DataFlowExfiltrationDetector(),
        GuardBypassDetector(),
        McpDescriptionDeceptionDetector(),
        McpToolSchemaRiskDetector(),
        PersistenceDetector(),
        PromptInjectionDetector(),
        SafeDecodeDetector(),
        SecretPathDetector(),
        SkillRiskDetector(),
        SupplyChainDetector(),
    )


def _prompt_request_signal(request: PromptRequest) -> RiskSignalV2:
    category = _prompt_request_category(request)
    return RiskSignalV2(
        signal_id=f"prompt-injection:{request.request_class}:{request.request_id[:16]}",
        category=category,
        severity=_severity_label(request.severity),
        confidence=_confidence_label(request.confidence),
        detector="prompt.injection",
        title=_prompt_request_title(request.request_class),
        plain_reason=request.summary,
        technical_detail=f"matched prompt request class: {request.request_class}",
        evidence_ref="prompt_excerpt",
        redaction_level="summary",
        false_positive_hint=_prompt_request_false_positive_hint(request),
        advisory_id=None,
    )


def _prompt_request_category(request: PromptRequest) -> RiskSignalCategory:
    return {
        "secret_read": "secret",
        "exfil_intent": "network",
        "destructive_intent": "filesystem",
        "subprocess_intent": "execution",
        "guard_bypass_intent": "bypass",
    }.get(request.request_class, "prompt")


def _severity_label(score: int) -> RiskSeverityLabel:
    return severity_label_from_score(score)


def _confidence_label(score: float) -> RiskConfidenceLabel:
    return confidence_label_from_score(score)


def _prompt_request_title(request_class: str) -> str:
    return {
        "secret_read": "Prompt requests local secret access",
        "exfil_intent": "Prompt requests data exfiltration",
        "destructive_intent": "Prompt requests destructive action",
        "subprocess_intent": "Prompt requests subprocess execution",
        "guard_bypass_intent": "Prompt requests Guard bypass",
        "prompt_injection_intent": "Prompt includes injection intent",
    }.get(request_class, "Prompt request needs review")


def _prompt_request_false_positive_hint(request: PromptRequest) -> str | None:
    for remediation in request.remediation:
        if remediation.detail is not None and remediation.detail.strip():
            return remediation.detail
    return None


def _secret_path_signal(match: SecretPathMatch, *, index: int) -> RiskSignalV2:
    return RiskSignalV2(
        signal_id=f"secret:path:{_slug(match.family)}:{index}",
        category="secret",
        severity="high",
        confidence="strong",
        detector="secret.path",
        title=f"Direct access to {match.family}",
        plain_reason=f"Requested direct access to {match.family}.",
        technical_detail=f"matched secret path family: {match.family}",
        evidence_ref="target_paths",
        redaction_level="summary",
        false_positive_hint="Allow only if this tool needs the exact local secret file for the current task.",
        advisory_id=None,
    )


def _secret_path_matches(paths: Sequence[str], *, workspace: Path | None) -> tuple[SecretPathMatch, ...]:
    matches: list[SecretPathMatch] = []
    for path in paths:
        match = classify_secret_path(path, cwd=workspace)
        if match is not None:
            matches.append(match)
    return tuple(matches)


def _elapsed_ms(started_at: float, finished_at: float) -> int:
    return max(0, round((finished_at - started_at) * 1000))


def _filter_signals(
    signals: Sequence[RiskSignalV2],
    category_filter: frozenset[RiskSignalCategory] | None,
) -> tuple[RiskSignalV2, ...]:
    if category_filter is None:
        return tuple(signals)
    return tuple(signal for signal in signals if signal.category in category_filter)


def _slug(value: str) -> str:
    return "-".join(part for part in value.lower().replace(".", " ").replace("/", " ").split() if part)


def _telemetry(
    detector: GuardDetector,
    status: DetectorRunStatus,
    *,
    elapsed_ms: int,
    error_type: str | None = None,
) -> DetectorTelemetry:
    return DetectorTelemetry(
        detector_id=detector.detector_id,
        categories=detector.categories,
        status=status,
        elapsed_ms=elapsed_ms,
        error_type=error_type,
    )
