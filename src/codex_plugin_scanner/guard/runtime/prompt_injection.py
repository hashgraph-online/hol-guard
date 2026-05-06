"""Prompt injection intent classification for Guard prompt surfaces."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable

from codex_plugin_scanner.guard.types import PromptRequest, RemediationAction

_SAME_SENTENCE_120 = r"[^.!?;\n]{0,120}"
_INSTRUCTION_OVERRIDE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bignore\s+(?:all\s+)?(?:previous|prior|earlier)\s+instructions?\b", re.IGNORECASE),
    re.compile(r"\bignore\s+(?:the\s+)?system\s+prompt\b", re.IGNORECASE),
)
_STEALTH_INSTRUCTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:do\s+not|don't)\s+(?:tell|notify|alert|inform)\s+(?:the\s+)?users?\b", re.IGNORECASE),
    re.compile(r"\bhide\s+(?:this|it|the\s+(?:action|instruction|request))\s+from\s+(?:the\s+)?logs?\b", re.IGNORECASE),
)
_DOCUMENTATION_CONTEXT_TERM_PATTERN = re.compile(
    r"\b(?:document|explain|describe|write\s+docs?|security\s+docs?|test\s+fixture)\b",
    re.IGNORECASE,
)
_DOCUMENTATION_SUBJECT_PATTERN = re.compile(
    r"\b(?:prompt\s+injection|attacks?|examples?|phrase|phrases?|string|strings?|fixture|fixtures?|say|says)\b",
    re.IGNORECASE,
)
_STEALTH_DOCUMENTATION_SUBJECT_PATTERN = re.compile(
    r"\b(?:prompt\s+injection|attacks?|bypass\s+prompt|examples?|phrases?|strings?|malicious|adversarial|unsafe)\b",
    re.IGNORECASE,
)
_GUARD_DOCUMENTATION_SUBJECT_PATTERN = re.compile(
    r"\b(?:HOL\s+Guard|guard|approval_policy|policy|config|configuration|hooks?|opencode|codex|claude|attacks?|bypass\s+prompt)\b",
    re.IGNORECASE,
)
_REPORTED_PHRASE_PREFIX_WORDS = frozenset(
    {"say", "says", "said", "called", "named", "phrase", "phrases", "string", "strings"}
)
_NON_ACTIONABLE_FIXTURE_PATTERN = re.compile(r"\bdo\s+not\s+actually\s+run\s+this\b", re.IGNORECASE)
_UNTRUSTED_CONTEXT_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bquoted\s+log\b", re.IGNORECASE), "quoted log"),
    (re.compile(r"\bPR\s+comment(?:\s+text)?\b", re.IGNORECASE), "PR comment"),
    (re.compile(r"\bissue\s+comment(?:\s+text)?\b", re.IGNORECASE), "issue comment"),
    (re.compile(r"\bwebpage\s+scrape\b", re.IGNORECASE), "webpage scrape"),
    (re.compile(r"\b(?:repository\s+)?README\b", re.IGNORECASE), "repository README"),
)
_GUARD_POLICY_TAMPER_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:disable|turn\s+off|uninstall|bypass)\s+HOL\s+Guard\b", re.IGNORECASE),
    re.compile(
        r"\b(?:edit|modify|change|write)\b"
        rf"{_SAME_SENTENCE_120}\.codex/config\.toml"
        rf"{_SAME_SENTENCE_120}\b(?:approval_policy|never|weaken|disable|remove)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:remove|delete|strip|disable)\b"
        rf"{_SAME_SENTENCE_120}\b(?:hook|hooks|HOL\s+Guard|guard)\b"
        rf"{_SAME_SENTENCE_120}\.claude/settings\.local\.json",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:remove|delete|disable)\b"
        rf"{_SAME_SENTENCE_120}\b(?:OpenCode|opencode)\b"
        rf"{_SAME_SENTENCE_120}\b(?:Guard|guard|config|configuration)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bif\s+(?:blocked|denied|rejected)\b"
        rf"(?={_SAME_SENTENCE_120}\b(?:HOL\s+)?Guard\b)"
        rf"{_SAME_SENTENCE_120}\b(?:try|use|run)\b"
        rf"{_SAME_SENTENCE_120}\b(?:shell|bash|sh|terminal)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:if\s+)?(?:HOL\s+)?Guard\s+(?:blocks?|blocked|denies|denied|rejects?|rejected)\b"
        rf"{_SAME_SENTENCE_120}\b(?:try|use|run)\b"
        rf"{_SAME_SENTENCE_120}\b(?:shell|bash|sh|terminal)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:if\s+)?(?:HOL\s+)?Guard\s+(?:blocks?|blocked|denies|denied|rejects?|rejected)\b"
        rf"{_SAME_SENTENCE_120}\buse\s+another\s+MCP\s+servers?\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\buse\s+another\s+MCP\s+servers?\b"
        rf"{_SAME_SENTENCE_120}\b(?:if|when)\s+(?:blocked|denied|rejected)\b"
        rf"(?={_SAME_SENTENCE_120}\b(?:HOL\s+)?Guard\b)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bif\s+(?:blocked|denied|rejected)\b"
        rf"(?={_SAME_SENTENCE_120}\b(?:HOL\s+)?Guard\b)"
        rf"{_SAME_SENTENCE_120}\buse\s+another\s+MCP\s+servers?\b",
        re.IGNORECASE,
    ),
)
_EXACT_SECRET_READ_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"\b(?:read|open|print|show|dump|cat)\b"
            rf"{_SAME_SENTENCE_120}(?<![\w-])\.env(?!\.example\b)(?:\.[A-Za-z0-9_-]+)?"
            rf"{_SAME_SENTENCE_120}\b(?:exactly|full|contents?|every\s+line)\b",
            re.IGNORECASE,
        ),
        "Prompt asks for exact local .env contents.",
    ),
    (
        re.compile(
            r"\b(?:read|open|print|show|dump|cat)\b"
            rf"{_SAME_SENTENCE_120}\.npmrc"
            rf"{_SAME_SENTENCE_120}\b(?:exactly|full|contents?|every\s+line)\b",
            re.IGNORECASE,
        ),
        "Prompt asks for exact npm registry credentials.",
    ),
    (
        re.compile(
            r"\b(?:print|show|dump|cat|read|open)\b"
            rf"{_SAME_SENTENCE_120}(?:~?/\.ssh|\.ssh)/(?:id_rsa|id_ed25519)\b",
            re.IGNORECASE,
        ),
        "Prompt asks to print SSH private-key material.",
    ),
    (
        re.compile(
            r"\b(?:print|show|dump|cat|read|open)\b"
            rf"{_SAME_SENTENCE_120}\b(?:SSH\s+)?private\s+key\b"
            rf"{_SAME_SENTENCE_120}\b(?:contents?|material|full|exact)\b",
            re.IGNORECASE,
        ),
        "Prompt asks to print SSH private-key material.",
    ),
)
_UPLOAD_OR_ENCODE_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(?:upload|send|post|transfer)\b"
        rf"{_SAME_SENTENCE_120}\b(?:local\s+)?(?:credential|secret|token|key)\s+file\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:base64|encode|encoded)\b"
        rf"{_SAME_SENTENCE_120}\.env(?:\.[A-Za-z0-9_-]+)?"
        rf"{_SAME_SENTENCE_120}\b(?:send|post|upload|transfer|endpoint|webhook|url)\b",
        re.IGNORECASE,
    ),
)


def detect_prompt_injection_requests(prompt_text: str) -> tuple[PromptRequest, ...]:
    normalized = " ".join(prompt_text.split())
    if not normalized:
        return ()
    requests: list[PromptRequest] = []
    override_detection = _first_override_detection(normalized)
    if override_detection is not None:
        override_match, embedded_context = override_detection
        confidence = 0.62 if embedded_context is not None else 0.86
        severity = 6 if embedded_context is not None else 8
        summary = (
            f"Untrusted {embedded_context} includes prompt-injection instructions."
            if embedded_context is not None
            else "Prompt asks the harness to override prior or system instructions."
        )
        requests.append(
            _request(
                request_class="prompt_injection_intent",
                matched_text=override_match.group(0).strip(),
                summary=summary,
                severity=severity,
                confidence=confidence,
                remediation=(
                    RemediationAction(kind="approve_once", label="Approve once", detail="Review prompt intent first."),
                    RemediationAction(
                        kind="open_investigation",
                        label="Investigate",
                        detail="Inspect prompt source for injection.",
                    ),
                ),
                normalized_prompt=normalized,
            )
        )
    stealth_match = _first_actionable_match(
        _STEALTH_INSTRUCTION_PATTERNS,
        normalized,
        _is_documentation_context_stealth,
    )
    if stealth_match is not None:
        requests.append(
            _request(
                request_class="prompt_injection_intent",
                matched_text=stealth_match.group(0).strip(),
                summary="Prompt asks the harness to conceal actions from the user or logs.",
                severity=8,
                confidence=0.84,
                remediation=(
                    RemediationAction(kind="approve_once", label="Approve once", detail="Review concealment intent."),
                    RemediationAction(
                        kind="open_investigation",
                        label="Investigate",
                        detail="Inspect prompt source for stealth instructions.",
                    ),
                ),
                normalized_prompt=normalized,
            )
        )
    guard_match = _first_actionable_match(
        _GUARD_POLICY_TAMPER_PATTERNS,
        normalized,
        _is_documentation_context_guard,
    )
    if guard_match is not None:
        requests.append(
            _request(
                request_class="guard_bypass_intent",
                matched_text=guard_match.group(0).strip(),
                summary="Prompt asks to weaken or bypass Guard policy.",
                severity=10,
                confidence=0.93,
                remediation=(
                    RemediationAction(kind="block_and_remove", label="Block", detail="Do not allow policy bypass."),
                    RemediationAction(
                        kind="open_investigation",
                        label="Investigate",
                        detail="Escalate Guard policy tampering.",
                    ),
                ),
                normalized_prompt=normalized,
            )
        )
    for pattern, summary in _EXACT_SECRET_READ_PATTERNS:
        match = pattern.search(normalized)
        if match is None:
            continue
        requests.append(
            _request(
                request_class="secret_read",
                matched_text=match.group(0).strip(),
                summary=summary,
                severity=8,
                confidence=0.9,
                remediation=(
                    RemediationAction(kind="approve_once", label="Approve once", detail="Allow one guarded read."),
                    RemediationAction(
                        kind="rotate_exposed_secret",
                        label="Rotate secret",
                        detail="Rotate credentials if exposure was unintended.",
                    ),
                ),
                normalized_prompt=normalized,
            )
        )
    exfil_match = _first_match(_UPLOAD_OR_ENCODE_SECRET_PATTERNS, normalized)
    if exfil_match is not None:
        requests.append(
            _request(
                request_class="exfil_intent",
                matched_text=exfil_match.group(0).strip(),
                summary="Prompt asks to upload or encode local secret material.",
                severity=9,
                confidence=0.86,
                remediation=(
                    RemediationAction(
                        kind="review_network_destination",
                        label="Review destination",
                        detail="Validate destination before transfer.",
                    ),
                    RemediationAction(
                        kind="defer_and_notify_team",
                        label="Notify team",
                        detail="Escalate for review.",
                    ),
                ),
                normalized_prompt=normalized,
            )
        )
    return tuple(_dedupe_requests(requests))


def _request(
    *,
    request_class: str,
    matched_text: str,
    summary: str,
    severity: int,
    confidence: float,
    remediation: tuple[RemediationAction, ...],
    normalized_prompt: str,
) -> PromptRequest:
    return PromptRequest(
        request_id=_request_id(request_class, matched_text, normalized_prompt),
        request_class=request_class,
        summary=summary,
        matched_text=matched_text,
        severity=severity,
        confidence=confidence,
        remediation=remediation,
    )


def _request_id(request_class: str, matched_text: str, normalized_prompt: str) -> str:
    return hashlib.sha256(f"{request_class}:{matched_text}:{normalized_prompt.lower()}".encode()).hexdigest()


def _first_match(patterns: tuple[re.Pattern[str], ...], text: str) -> re.Match[str] | None:
    for pattern in patterns:
        match = pattern.search(text)
        if match is not None:
            return match
    return None


def _first_actionable_match(
    patterns: tuple[re.Pattern[str], ...],
    text: str,
    is_documentation_context: Callable[[str, re.Match[str]], bool],
) -> re.Match[str] | None:
    for pattern in patterns:
        for match in pattern.finditer(text):
            if not is_documentation_context(text, match):
                return match
    return None


def _first_override_detection(text: str) -> tuple[re.Match[str], str | None] | None:
    for pattern in _INSTRUCTION_OVERRIDE_PATTERNS:
        for match in pattern.finditer(text):
            if _is_non_actionable_fixture(text, match):
                continue
            embedded_context = _embedded_context_label(text, match.start())
            if embedded_context is not None or not _is_documentation_context_override(text, match):
                return match, embedded_context
    return None


def _is_documentation_context_override(text: str, match: re.Match[str]) -> bool:
    boundary = max(
        text.rfind(".", 0, match.start()),
        text.rfind("!", 0, match.start()),
        text.rfind("?", 0, match.start()),
        text.rfind(";", 0, match.start()),
        text.rfind("\n", 0, match.start()),
    )
    context_start = boundary + 1
    prefix = text[context_start : match.start()]
    local_context = text[context_start : min(len(text), match.end() + 80)]
    return (
        _DOCUMENTATION_CONTEXT_TERM_PATTERN.search(prefix) is not None
        and _DOCUMENTATION_SUBJECT_PATTERN.search(local_context) is not None
        and _has_reported_phrase_prefix(prefix)
    )


def _is_non_actionable_fixture(text: str, match: re.Match[str]) -> bool:
    context = text[max(0, match.start() - 120) : min(len(text), match.end() + 120)]
    return _NON_ACTIONABLE_FIXTURE_PATTERN.search(context) is not None


def _is_documentation_context_stealth(text: str, match: re.Match[str]) -> bool:
    return _is_documentation_context_with_subject(text, match, _STEALTH_DOCUMENTATION_SUBJECT_PATTERN)


def _is_documentation_context_guard(text: str, match: re.Match[str]) -> bool:
    boundary = max(
        text.rfind(".", 0, match.start()),
        text.rfind("!", 0, match.start()),
        text.rfind("?", 0, match.start()),
        text.rfind(";", 0, match.start()),
        text.rfind("\n", 0, match.start()),
    )
    context_start = boundary + 1
    prefix = text[context_start : match.start()]
    subject_context = _reported_phrase_subject_context(text, prefix, match)
    return (
        _DOCUMENTATION_CONTEXT_TERM_PATTERN.search(prefix) is not None
        and _GUARD_DOCUMENTATION_SUBJECT_PATTERN.search(subject_context) is not None
        and _has_quoted_reported_phrase_prefix(prefix)
    )


def _is_documentation_context_with_subject(
    text: str,
    match: re.Match[str],
    subject_pattern: re.Pattern[str],
) -> bool:
    boundary = max(
        text.rfind(".", 0, match.start()),
        text.rfind("!", 0, match.start()),
        text.rfind("?", 0, match.start()),
        text.rfind(";", 0, match.start()),
        text.rfind("\n", 0, match.start()),
    )
    context_start = boundary + 1
    prefix = text[context_start : match.start()]
    subject_context = _reported_phrase_subject_context(text, prefix, match)
    return (
        _DOCUMENTATION_CONTEXT_TERM_PATTERN.search(prefix) is not None
        and subject_pattern.search(subject_context) is not None
        and _has_quoted_reported_phrase_prefix(prefix)
    )


def _reported_phrase_subject_context(text: str, prefix: str, match: re.Match[str]) -> str:
    suffix = text[match.end() : min(len(text), match.end() + 80)]
    return f"{prefix} {suffix}"


def _has_quoted_reported_phrase_prefix(prefix: str) -> bool:
    stripped = prefix.rstrip()
    return bool(stripped) and stripped[-1] in {"'", '"', "`"} and _has_reported_phrase_prefix(prefix)


def _has_reported_phrase_prefix(prefix: str) -> bool:
    cleaned = prefix.rstrip().rstrip("\"'`").rstrip().lower()
    if not cleaned:
        return False
    tokens = [token.strip(".,:;!?()[]{}\"'`-") for token in cleaned.split()]
    return bool(tokens) and tokens[-1] in _REPORTED_PHRASE_PREFIX_WORDS


def _embedded_context_label(text: str, start: int) -> str | None:
    if text[:start].count("```") % 2 == 1:
        return "markdown code fence"
    prefix = text[max(0, start - 140) : start]
    for pattern, label in _UNTRUSTED_CONTEXT_PATTERNS:
        if pattern.search(prefix) is not None:
            return label
    return None


def _dedupe_requests(requests: list[PromptRequest]) -> tuple[PromptRequest, ...]:
    deduped: dict[tuple[str, str], PromptRequest] = {}
    for request in requests:
        deduped[(request.request_class, request.matched_text)] = request
    return tuple(deduped.values())
