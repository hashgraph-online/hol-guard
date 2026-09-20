"""Initial runner policy, prompt, transport, and receipt constants."""

from __future__ import annotations

from .runner_dependencies import __version__, re

_POLICY_DOCUMENT_VERSIONS = ("guard.hashgraphonline.com/v1alpha1",)

_POLICY_BUNDLE_VERSIONS = ("guard-policy-bundle.v1", "guard-policy-bundle.v2")

_POLICY_CONTRACTS = ("guard-policy-bundle/v1", "guard-policy-bundle/v2")

_POLICY_YAML_IMPORT_ENV = "HOL_GUARD_POLICY_YAML_IMPORT"

_POLICY_CANONICAL_ENFORCEMENT_ENV = "HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT"

_APPROVAL_METADATA_KEYS = (
    "approval_center_url",
    "approval_delivery",
    "approval_requests",
    "approval_wait",
    "review_hint",
)

_RUNTIME_DETECTOR_REVIEW_REASON = "runtime_detector_review"

_RUNTIME_DETECTOR_WARN_REASON = "runtime_detector_warn"

_APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM = "approval_reuse_context_changed_after_claim"

# Every prepared launch-environment entry is authority-hashed except this
# explicit execution-boundary credential. Inherited values are removed before
# hashing; only Guard's freshly resolved Hermes credential may be added later.
_HERMES_GUARD_TOKEN_ENV_KEY = "HERMES_GUARD_TOKEN"

_GUARD_RUN_LATE_CREDENTIAL_ENV_KEYS = frozenset({_HERMES_GUARD_TOKEN_ENV_KEY})

_INTERACTIVE_ALLOW_OVERRIDE_LABELS = frozenset({"allow-once", "allow-artifact", "allow-publisher", "allow-harness"})

_INSTALL_TIME_STOP_EVENTS = frozenset(
    {
        "install_time_block",
        "install_time_review",
        "install_time_require-reapproval",
        "install_time_sandbox-required",
    }
)

_PAIN_SIGNAL_EVENTS = frozenset(
    {
        "changed_artifact_caught",
        *_INSTALL_TIME_STOP_EVENTS,
        "install_time_warn",
        "supply_chain_bundle_refresh_requested",
        "approval_gate/remote_policy_sync_blocked",
    }
)

_EXCEPTION_EXPIRY_ALERT_WINDOW_HOURS = 7 * 24

_SECRET_REQUEST_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?<![\w-])\.env(?!\.example\b)(?:\.[\w.-]+)?\b"), "local .env file"),
    (re.compile(r"(?:^|[\s'\"`])~?/.ssh(?:/|\b)"), "SSH material"),
    (re.compile(r"(?:^|[\s'\"`])~?/.aws/(?:credentials|config)\b"), "AWS credentials"),
    (re.compile(r"(?:^|[\s'\"`])~?/.kube/config\b"), "kubeconfig"),
    (re.compile(r"(?:^|[\s'\"`])~?/.docker/config\.json\b"), "Docker credentials"),
    (re.compile(r"(?<![\w-])\.npmrc\b"), "npm registry credentials"),
    (re.compile(r"(?<![\w-])\.pypirc\b"), "Python package credentials"),
    (re.compile(r"(?<![\w-])\.git-credentials\b"), "Git credential store"),
)

_SECRET_ABSOLUTE_HINTS: tuple[tuple[str, str], ...] = (
    ("/.ssh/", "SSH material"),
    ("/.aws/credentials", "AWS credentials"),
    ("/.aws/config", "AWS credentials"),
    ("/.kube/config", "kubeconfig"),
    ("/.docker/config.json", "Docker credentials"),
)

_SECRET_READ_INTENT_PATTERN = re.compile(
    r"\b("
    r"read|open|print|show|dump|cat|head|tail|less|copy|cp|scp|reveal|display|summari[sz]e|inspect|extract|"
    r"use|include|grab|"
    r"contain(?:s)?|contents?\s+of|what(?:'s| is)\s+in"
    r")\b",
    re.IGNORECASE,
)

_NEGATED_SECRET_READ_PATTERN = re.compile(
    r"\b(?:never|do\s+not|don't|dont|must\s+not|should\s+not|cannot|can't)\b[^.!?;\n]{0,80}"
    r"\b(?:read|open|print|show|dump|cat|head|tail|less|copy|cp|scp|reveal|display|summari[sz]e|inspect|extract|"
    r"use|include|grab)\b",
    re.IGNORECASE,
)

_FOLLOWING_SECRET_REFERENCE_PATTERN = re.compile(
    r"\b(?:it|them|these|those|file|files|secret|secrets|contents?|credentials?|tokens?|key|keys)\b",
    re.IGNORECASE,
)

_EXFIL_ACTIONS = r"(?:send|post|upload|transfer|paste|sync)"

_EXFIL_ARTIFACTS = r"(?:contents?|data|payload|file|secret|token|key|credential|credentials|config|output)"

_EXFIL_DESTINATIONS = r"(?:to|into|onto|via|through|over|at)"

_EXFIL_NAMED_REMOTE_TARGETS = r"(?:webhook|gist|pastebin|slack|discord|telegram|server|endpoint|url)"

_EXFIL_REMOTE_TARGETS = (
    r"(?:(?:[a-z][a-z0-9+.-]*://)|(?:[a-z0-9-]+\.)+[a-z]{2,}|(?:\d{1,3}\.){3}\d{1,3}|"
    rf"{_EXFIL_NAMED_REMOTE_TARGETS})"
)

_SAME_SENTENCE_80 = r"[^.!?;\n]{0,80}"

_SAME_SENTENCE_40 = r"[^.!?;\n]{0,40}"

_EXFIL_PROMPT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        rf"\b(?:upload|exfiltrate|transfer|paste|gist|webhook)\b{_SAME_SENTENCE_80}\b"
        rf"{_EXFIL_ARTIFACTS}\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{_EXFIL_ACTIONS}\b{_SAME_SENTENCE_80}\b"
        rf"{_EXFIL_ARTIFACTS}\b"
        rf"{_SAME_SENTENCE_40}\b{_EXFIL_DESTINATIONS}\b{_SAME_SENTENCE_40}\b"
        rf"{_EXFIL_REMOTE_TARGETS}\b",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\b{_EXFIL_ACTIONS}\b{_SAME_SENTENCE_80}\b"
        rf"{_EXFIL_DESTINATIONS}\b{_SAME_SENTENCE_40}\b"
        rf"{_EXFIL_NAMED_REMOTE_TARGETS}\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:send|post|upload|transfer|paste|sync)\b.{0,120}"
        r"(?:"
        r"(?<![\w-])\.env(?:\.[\w.-]+)?\b|"
        r"(?:^|[\s'\"`])~?/.ssh(?:/|\b)|"
        r"(?:^|[\s'\"`])~?/.aws/(?:credentials|config)\b|"
        r"(?:^|[\s'\"`])~?/.kube/config\b|"
        r"(?:^|[\s'\"`])~?/.docker/config\.json\b|"
        r"(?<![\w-])\.npmrc\b|"
        r"(?<![\w-])\.pypirc\b|"
        r"(?<![\w-])\.git-credentials\b|"
        r"/.ssh/|"
        r"/.aws/credentials|"
        r"/.aws/config|"
        r"/.kube/config|"
        r"/.docker/config\.json"
        r")"
        r".{0,80}\b(?:to|into|onto|via|through)\b.{0,80}"
        r"(?:[a-z][a-z0-9+.-]*://|webhook|gist|pastebin|slack|discord|telegram|server|endpoint|url)\b",
        re.IGNORECASE,
    ),
)

_DESTRUCTIVE_PROMPT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(?:run|execute|use|call|invoke)\b.{0,40}\b(?:rm\s+-rf|rm\s+|del\s+|truncate\s+|chmod\s+|chown\s+|mv\s+)",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:^|[\s'\"`(])(?:rm\s+-rf|rm\s+\S|del\s+\S|truncate\s+\S|chmod\s+\S|chown\s+\S|mv\s+\S)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:delete|remove|overwrite|truncate)\b.{0,60}\b(?:file|directory|repo|workspace|contents?)\b",
        re.IGNORECASE,
    ),
)

_SUBPROCESS_PROMPT_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(
        r"\b(?:run|execute|use|call|invoke|launch|spawn)\b.{0,60}\b"
        r"(?:bash\s+-c|sh\s+-c|zsh\s+-c|powershell|cmd\s+/c|subprocess|exec\(|spawn\()",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:^|[\s'\"`(])(?:bash\s+-c\b|sh\s+-c\b|zsh\s+-c\b|powershell(?:\.exe)?(?:\s|$)|cmd\s+/c(?:\s|$)|subprocess\.(?:run|Popen|call|check_call|check_output)\b|exec\(|spawn\()",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:use|call|invoke)\b.{0,40}\bsubprocess\b",
        re.IGNORECASE,
    ),
)

_GUARD_BYPASS_PROMPT_PATTERN = re.compile(
    r"\b(hol-guard\s+(?:disable|off|uninstall)|disable\s+hol-guard|approval_policy\s*=\s*\"never\"|guard[_-]?bypass)\b",
    re.IGNORECASE,
)

_DOCUMENT_PROMPT_ACTION_PATTERN = re.compile(
    r"\b(?:create|draft|document|generate|outline|plan|update|write)\b",
    re.IGNORECASE,
)

_DOCUMENT_PROMPT_TARGET_PATTERN = re.compile(
    r"\b(?:checklist|docs?|documentation|file|files|guide|markdown|notes?|plan(?:ning)?|prd|prompt|report|runbook|spec|todo)\b",
    re.IGNORECASE,
)

_DOCUMENT_PROMPT_CONTEXT_PATTERN = re.compile(
    r"\b(?:checklist|command|commands|document|documentation|example|examples|regression|test|tests|validate|verify)\b",
    re.IGNORECASE,
)

_DOCUMENT_PROMPT_GUARDRAIL_PATTERN = re.compile(
    r"\b(?:approval|block(?:ed)?|guard|guardrail|policy|protection|require(?:s|d)?\s+approval)\b",
    re.IGNORECASE,
)

_DOCUMENT_PROMPT_STRONG_GUARDRAIL_PATTERN = re.compile(
    r"(?:do\s+not|must\s+not|must\s+stay\s+blocked|must\s+remain\s+blocked|never|"
    r"require(?:s|d)?\s+approval|should\s+stay\s+blocked|should\s+remain\s+blocked|stay\s+blocked)",
    re.IGNORECASE,
)

_PROMPT_SENTENCE_BOUNDARY_PATTERN = re.compile(r"[!?;]|[.](?=\s|$)")

_GUARD_SYNC_USER_AGENT = f"hol-guard/{__version__}"

_SYNC_HTTP_TIMEOUT_SECONDS = 20

_SYNC_HTTP_RETRY_TIMEOUT_SECONDS = 120

_SYNC_RETRYABLE_GATEWAY_STATUS_CODES = frozenset({502, 503, 504, 522, 524})

_SYNC_RETRYABLE_GATEWAY_MAX_ATTEMPTS = 2

_RUNTIME_SYNC_TIMEOUT_SECONDS = 10

_RUNTIME_SYNC_RETRY_TIMEOUT_SECONDS = 90

_RECEIPT_SYNC_BATCH_SIZE = 50

_RECEIPT_SYNC_CURSOR_PAGE_SIZE = 200

_RECEIPT_SYNC_CURSOR_BACKFILL_ROWS = 200

_RECEIPT_COMMAND_DETAIL_BACKFILL_DAYS = 30

_RECEIPT_COMMAND_DETAIL_BACKFILL_LIMIT = 200

_PAIN_SIGNAL_TIMEOUT_SECONDS = 10

_PAIN_SIGNAL_RETRY_TIMEOUT_SECONDS = 90

_GUARD_EVENTS_ENDPOINT_UNAVAILABLE_RETRY_MINUTES = 5  # single 404 shouldn't disable sync for a full day

_RUNTIME_DETECTOR_RESULT_KEYS = (
    "runtime_detector_signals_v2",
    "runtime_detector_telemetry",
    "runtime_detector_composition",
    "runtime_detector_trace_error",
)

_GUARD_DPOP_REQUEST_CONTEXT_LIMIT = 1000

_OAUTH_ACCESS_TOKEN_REFRESH_SKEW_SECONDS = 60

_OAUTH_INVALID_GRANT_MAX_ATTEMPTS = 2

_OAUTH_INVALID_GRANT_RETRY_DELAY_SECONDS = 0.75

_PLAN_403_KEYWORDS: frozenset[str] = frozenset(
    {
        "sync_not_available",
        "plan_restriction",
        "requires a pro",
        "requires a team",
        "upgrade your plan",
        "upgrade to",
        "subscription required",
        "not included in your plan",
        "guard sync requires",
    }
)

_RECEIPT_REDACTION_LEVEL_RANK: dict[str, int] = {
    "full": 0,
    "partial": 1,
    "none": 2,
}

_RELAXED_RECEIPT_REDACTION_RESYNC_MARKER = "cloud_receipt_redaction_relaxed_resync_v1"

_CLOUD_REVIEW_PRIVACY_PROJECTION_MARKER = "cloud_review_privacy_projection_v2"

_RECEIPT_COMMAND_DETAIL_BACKFILL_MARKER = "cloud_receipt_command_detail_backfill_v2"

_RECEIPT_COMMAND_DETAIL_BACKFILL_FLAG = "__command_detail_backfill"
