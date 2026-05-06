"""Prompt injection intent classification for Guard prompt surfaces."""

from __future__ import annotations

import hashlib
import re

from codex_plugin_scanner.guard.types import PromptRequest, RemediationAction

_SAME_SENTENCE_120 = r"[^.!?;\n]{0,120}"
_INSTRUCTION_OVERRIDE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bignore\s+(?:all\s+)?(?:previous|prior|earlier)\s+instructions?\b", re.IGNORECASE),
    re.compile(r"\bignore\s+(?:the\s+)?system\s+prompt\b", re.IGNORECASE),
)
_DOCUMENTATION_CONTEXT_TERM_PATTERN = re.compile(
    r"\b(?:document|explain|describe|write\s+docs?|security\s+docs?|test\s+fixture)\b",
    re.IGNORECASE,
)
_DOCUMENTATION_SUBJECT_PATTERN = re.compile(
    r"\b(?:prompt\s+injection|attacks?|examples?|phrase|phrases?|string|strings?|fixture|fixtures?|say|says)\b",
    re.IGNORECASE,
)
_REPORTED_PHRASE_PREFIX_PATTERN = re.compile(
    r"\b(?:say|says|said|called|named|phrase|phrases?|string|strings?|example|examples?)\s+[\"'`]?\s*$",
    re.IGNORECASE,
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
)
_EXACT_SECRET_READ_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"\b(?:read|open|print|show|dump|cat)\b"
            rf"{_SAME_SENTENCE_120}\.env(?:\.[A-Za-z0-9_-]+)?"
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
            rf"{_SAME_SENTENCE_120}\b(?:SSH\s+private\s+key|id_rsa|id_ed25519)\b",
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
    override_match = _first_match(_INSTRUCTION_OVERRIDE_PATTERNS, normalized)
    if override_match is not None and not _is_documentation_context_override(normalized, override_match):
        requests.append(
            _request(
                request_class="prompt_injection_intent",
                matched_text=override_match.group(0).strip(),
                summary="Prompt asks the harness to override prior or system instructions.",
                severity=8,
                confidence=0.86,
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
    guard_match = _first_match(_GUARD_POLICY_TAMPER_PATTERNS, normalized)
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
        and _REPORTED_PHRASE_PREFIX_PATTERN.search(prefix) is not None
    )


def _dedupe_requests(requests: list[PromptRequest]) -> tuple[PromptRequest, ...]:
    deduped: dict[tuple[str, str], PromptRequest] = {}
    for request in requests:
        deduped[(request.request_class, request.matched_text)] = request
    return tuple(deduped.values())
