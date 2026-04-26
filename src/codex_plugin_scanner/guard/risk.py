"""Risk heuristics and structured signal generation for local Guard artifacts."""

from __future__ import annotations

import re
from collections.abc import Sequence
from pathlib import PurePath
from urllib.parse import urlsplit

from .models import GuardArtifact
from .types import GuardSignal

_RULE_VERSION = "guard-risk-v2"
_URL_PATTERN = re.compile(r"https?://[^\s'\"`]+", re.IGNORECASE)
_HOST_PATTERN = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
_NON_NETWORK_SUFFIXES = {
    "md",
    "json",
    "toml",
    "yaml",
    "yml",
    "txt",
    "py",
    "js",
    "ts",
    "sh",
    "cfg",
    "conf",
    "log",
    "tmp",
    "bak",
    "bin",
}
_ENCODED_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\bbase64(?:\s+--decode|\s+-d)\b", "base64 decode invocation"),
    (r"\bb64decode\b", "runtime base64 decode invocation"),
    (r"xxd\s+-r\s+-p", "hex decode and reverse invocation"),
    (r"frombase64string", "powershell base64 decode invocation"),
)
_STAGED_DOWNLOAD_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"curl\b[^\n|]*\|\s*(?:bash|sh|zsh)", "curl piped directly to shell"),
    (r"wget\b[^\n|]*\|\s*(?:bash|sh|zsh)", "wget piped directly to shell"),
    (r"python(?:3)?\s+-c[^\n]*requests\.(?:get|post)", "python inline fetch and execute pattern"),
    (r"node\s+-e[^\n]*fetch\(", "node inline fetch and execute pattern"),
)
_GUARD_BYPASS_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"hol-guard\s+(?:disable|off|uninstall)", "explicit Guard disable command"),
    (r"approval_policy\s*=\s*\"never\"", "approval policy forced to never"),
    (r"\.codex/config\.toml", "direct Guard-managed configuration mutation"),
    (r"guard[_-]?bypass", "explicit Guard bypass marker"),
)
_EXFIL_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\b(upload|exfiltrate|send|post|sync)\b", "exfiltration verb"),
    (r"(gist\.github\.com|pastebin\.com|transfer\.sh|webhook)", "external sink destination"),
    (r"scp\s+", "scp transfer intent"),
)
_SECRET_PATH_LABELS: tuple[tuple[str, str], ...] = (
    (".env", "local .env file"),
    (".npmrc", "npm registry credentials"),
    (".pypirc", "python package credentials"),
    (".aws/credentials", "aws shared credentials"),
    (".ssh/", "ssh material"),
    (".gnupg/", "gpg material"),
    (".docker/config.json", "docker credentials"),
    (".kube/config", "kubeconfig"),
    (".git-credentials", "git credential store"),
)


def artifact_risk_signals_typed(artifact: GuardArtifact) -> tuple[GuardSignal, ...]:
    """Return structured risk signals for a Guard artifact."""

    signals: list[GuardSignal] = []
    signals.extend(_metadata_signals(artifact))
    combined = " ".join(_artifact_terms(artifact))
    lowered = combined.lower()
    command_name = PurePath(artifact.command or "").name.lower()
    env_keys = _env_keys(artifact)

    if artifact.url is not None and artifact.url.startswith(("http://", "https://")):
        signals.append(
            GuardSignal(
                signal_id="network:remote-server",
                family="network",
                severity=6,
                confidence=0.92,
                evidence_source="artifact",
                matched_text=artifact.url,
                explanation="connects to a remote server",
                remediation="Review remote host trust and scope before allowing.",
                rule_version=_RULE_VERSION,
            )
        )

    for host in sorted(extract_network_hosts(combined)):
        signals.append(
            GuardSignal(
                signal_id=f"network:host:{host}",
                family="network",
                severity=5,
                confidence=0.78,
                evidence_source="artifact",
                matched_text=host,
                explanation=f"references network host `{host}`",
                remediation="Confirm host ownership and allowed transport.",
                rule_version=_RULE_VERSION,
            )
        )

    if any(token in lowered for token in ("http://", "https://", "curl ", "wget ", "fetch(", "axios.", "requests.")):
        signals.append(
            GuardSignal(
                signal_id="network:traffic",
                family="network",
                severity=5,
                confidence=0.86,
                evidence_source="artifact",
                matched_text=None,
                explanation="can send or receive network traffic",
                remediation="Restrict network access to known destinations.",
                rule_version=_RULE_VERSION,
            )
        )

    if env_keys:
        signals.append(
            GuardSignal(
                signal_id="secret:env-keys",
                family="secret",
                severity=5,
                confidence=0.8,
                evidence_source="artifact",
                matched_text=", ".join(env_keys[:3]),
                explanation="receives environment variables that may contain secrets",
                remediation="Minimize env exposure and redact sensitive keys.",
                rule_version=_RULE_VERSION,
            )
        )
        if _has_sensitive_env_semantics(env_keys):
            signals.append(
                GuardSignal(
                    signal_id="secret:env-semantic",
                    family="secret",
                    severity=7,
                    confidence=0.84,
                    evidence_source="artifact",
                    matched_text=", ".join(env_keys[:3]),
                    explanation="uses environment key names that imply credentials or auth material",
                    remediation="Pass scoped tokens only when required.",
                    rule_version=_RULE_VERSION,
                )
            )

    if any(token in lowered for token in (".env", "dotenv", "printenv", "process.env", "os.environ", "getenv(")):
        signals.append(
            GuardSignal(
                signal_id="secret:env-read",
                family="secret",
                severity=7,
                confidence=0.9,
                evidence_source="artifact",
                matched_text=None,
                explanation="can read local environment secrets",
                remediation="Prefer explicit per-command secret injection over broad env reads.",
                rule_version=_RULE_VERSION,
            )
        )

    for secret_class in sorted(classify_secret_paths(combined)):
        signals.append(
            GuardSignal(
                signal_id=f"secret:path:{secret_class}",
                family="secret",
                severity=8,
                confidence=0.88,
                evidence_source="artifact",
                matched_text=secret_class,
                explanation=f"mentions sensitive local file family: {secret_class}",
                remediation="Confirm file-read necessity and scope before approval.",
                rule_version=_RULE_VERSION,
            )
        )
    if classify_secret_paths(combined):
        signals.append(
            GuardSignal(
                signal_id="secret:sensitive-local-files",
                family="secret",
                severity=7,
                confidence=0.82,
                evidence_source="artifact",
                matched_text=None,
                explanation="mentions sensitive local files",
                remediation="Verify file path access scope before allowing.",
                rule_version=_RULE_VERSION,
            )
        )

    if command_name in {"bash", "sh", "zsh", "powershell", "cmd"} or _has_shell_wrapper(artifact):
        signals.append(
            GuardSignal(
                signal_id="execution:shell-wrapper",
                family="execution",
                severity=6,
                confidence=0.83,
                evidence_source="artifact",
                matched_text=command_name if command_name else None,
                explanation="runs through a shell wrapper",
                remediation="Prefer direct executable invocation over shell wrappers.",
                rule_version=_RULE_VERSION,
            )
        )

    if _has_inline_code(artifact):
        signals.append(
            GuardSignal(
                signal_id="execution:inline-code",
                family="execution",
                severity=7,
                confidence=0.87,
                evidence_source="artifact",
                matched_text=command_name if command_name else None,
                explanation="executes inline code at launch",
                remediation="Pin script source and review inline code payload.",
                rule_version=_RULE_VERSION,
            )
        )

    signals.extend(detect_encoded_command(lowered))
    signals.extend(detect_staged_download(lowered))
    signals.extend(detect_guard_bypass(lowered))
    signals.extend(detect_exfil_intent(lowered))

    return tuple(_dedupe_signals(signals))


def artifact_risk_signals(artifact: GuardArtifact) -> tuple[str, ...]:
    """Backward-compatible string signals derived from structured signals."""

    return tuple(signal.explanation for signal in artifact_risk_signals_typed(artifact))


def artifact_risk_summary(artifact: GuardArtifact) -> str:
    """Human-readable summary of the highest-impact artifact signals."""

    metadata_summary = _metadata_summary(artifact)
    if metadata_summary is not None:
        return metadata_summary
    return summarize_signals(artifact_risk_signals_typed(artifact))


def summarize_signals(signals: Sequence[GuardSignal]) -> str:
    """Summarize top signals by severity for CLI and approval UX."""

    if not signals:
        return "No obvious secret-access or network signal was detected in the launch definition."
    network_candidate = next(
        (signal for signal in signals if signal.family == "network" and "network" in signal.explanation.lower()),
        None,
    )
    if network_candidate is None:
        network_candidate = next((signal for signal in signals if signal.family == "network"), None)
    secret_candidate = next(
        (signal for signal in signals if signal.family == "secret" and "secret" in signal.explanation.lower()),
        None,
    )
    if secret_candidate is None:
        secret_candidate = next((signal for signal in signals if signal.family == "secret"), None)
    if network_candidate is not None and secret_candidate is not None:
        return f"{network_candidate.explanation.capitalize()}, and it also {secret_candidate.explanation}."
    ranked = sorted(signals, key=lambda item: (item.severity, item.confidence), reverse=True)
    if len(ranked) == 1:
        return ranked[0].explanation.capitalize() + "."
    return f"{ranked[0].explanation.capitalize()}, and it also {ranked[1].explanation}."


def extract_network_hosts(text: str) -> set[str]:
    """Extract host-like network references from text."""

    hosts: set[str] = set()
    for value in _URL_PATTERN.findall(text):
        parsed = urlsplit(value)
        if parsed.hostname:
            hosts.add(parsed.hostname.lower())
    for match in _HOST_PATTERN.finditer(text):
        value = match.group(0)
        if value.count(".") < 1:
            continue
        if text[match.end() : match.end() + 1] == "(":
            continue
        lowered = value.lower()
        suffix = lowered.rsplit(".", 1)[-1]
        if suffix in _NON_NETWORK_SUFFIXES:
            continue
        hosts.add(lowered)
    return hosts


def classify_secret_paths(text: str) -> set[str]:
    """Classify secret-bearing file families referenced in text."""

    lowered = text.lower()
    classes: set[str] = set()
    for pattern, label in _SECRET_PATH_LABELS:
        if pattern in lowered:
            classes.add(label)
    return classes


def detect_encoded_command(text: str) -> list[GuardSignal]:
    """Detect encoded command decode-and-execute patterns."""

    signals: list[GuardSignal] = []
    for pattern, reason in _ENCODED_PATTERNS:
        if re.search(pattern, text):
            signals.append(
                GuardSignal(
                    signal_id=f"execution:encoded:{reason.replace(' ', '-')}",
                    family="execution",
                    severity=8,
                    confidence=0.82,
                    evidence_source="artifact",
                    matched_text=reason,
                    explanation="includes encoded command decode patterns",
                    remediation="Decode and review payload before execution.",
                    rule_version=_RULE_VERSION,
                )
            )
    return signals


def detect_staged_download(text: str) -> list[GuardSignal]:
    """Detect staged downloader and fetch-and-exec patterns."""

    signals: list[GuardSignal] = []
    for pattern, reason in _STAGED_DOWNLOAD_PATTERNS:
        if re.search(pattern, text):
            signals.append(
                GuardSignal(
                    signal_id=f"network:staged:{reason.replace(' ', '-')}",
                    family="network",
                    severity=9,
                    confidence=0.88,
                    evidence_source="artifact",
                    matched_text=reason,
                    explanation="shows staged downloader behavior",
                    remediation="Pin source artifact and avoid direct shell piping.",
                    rule_version=_RULE_VERSION,
                )
            )
    return signals


def detect_guard_bypass(text: str) -> list[GuardSignal]:
    """Detect explicit attempts to bypass Guard-managed controls."""

    signals: list[GuardSignal] = []
    for pattern, reason in _GUARD_BYPASS_PATTERNS:
        if re.search(pattern, text):
            signals.append(
                GuardSignal(
                    signal_id=f"policy:bypass:{reason.replace(' ', '-')}",
                    family="policy",
                    severity=9,
                    confidence=0.9,
                    evidence_source="artifact",
                    matched_text=reason,
                    explanation="contains guard bypass intent",
                    remediation="Block and require manual investigation.",
                    rule_version=_RULE_VERSION,
                )
            )
    return signals


def detect_exfil_intent(text: str) -> list[GuardSignal]:
    """Detect exfiltration-oriented phrasing and destinations."""

    signals: list[GuardSignal] = []
    for pattern, reason in _EXFIL_PATTERNS:
        if re.search(pattern, text):
            signals.append(
                GuardSignal(
                    signal_id=f"network:exfil:{reason.replace(' ', '-')}",
                    family="network",
                    severity=8,
                    confidence=0.79,
                    evidence_source="artifact",
                    matched_text=reason,
                    explanation="includes exfiltration-oriented intent",
                    remediation="Confirm destination and data class before allowing transfer.",
                    rule_version=_RULE_VERSION,
                )
            )
    return signals


def _artifact_terms(artifact: GuardArtifact) -> list[str]:
    parts = [artifact.name, artifact.command or "", artifact.url or "", *artifact.args]
    parts.extend(_env_keys(artifact))
    request_summary = artifact.metadata.get("request_summary")
    if isinstance(request_summary, str) and request_summary:
        parts.append(request_summary)
    runtime_reason = artifact.metadata.get("runtime_request_reason")
    if isinstance(runtime_reason, str) and runtime_reason:
        parts.append(runtime_reason)
    return [part for part in parts if part]


def _env_keys(artifact: GuardArtifact) -> list[str]:
    env_keys = artifact.metadata.get("env_keys")
    if not isinstance(env_keys, list):
        return []
    return [str(value) for value in env_keys if isinstance(value, str) and value]


def _metadata_signals(artifact: GuardArtifact) -> list[GuardSignal]:
    signals: list[GuardSignal] = []
    for key in ("runtime_request_signals", "prompt_signals"):
        value = artifact.metadata.get(key)
        if not isinstance(value, list):
            continue
        for item in value:
            if not isinstance(item, str) or not item:
                continue
            signals.append(
                GuardSignal(
                    signal_id=f"metadata:{key}:{item[:32].lower().replace(' ', '-')}",
                    family="prompt" if key == "prompt_signals" else "execution",
                    severity=7 if key == "prompt_signals" else 6,
                    confidence=0.85,
                    evidence_source="prompt" if key == "prompt_signals" else "artifact",
                    matched_text=item,
                    explanation=item,
                    remediation="Review request intent before approving.",
                    rule_version=_RULE_VERSION,
                )
            )
    return signals


def _metadata_summary(artifact: GuardArtifact) -> str | None:
    for key in ("runtime_request_summary", "prompt_summary"):
        value = artifact.metadata.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _has_shell_wrapper(artifact: GuardArtifact) -> bool:
    return any(value in {"-c", "-lc", "/c"} for value in artifact.args)


def _has_inline_code(artifact: GuardArtifact) -> bool:
    if artifact.command is None:
        return False
    command_name = PurePath(artifact.command).name.lower()
    if command_name in {"python", "python3", "node", "ruby", "perl"}:
        return any(value in {"-c", "-e"} for value in artifact.args)
    return False


def _has_sensitive_env_semantics(env_keys: list[str]) -> bool:
    for env_key in env_keys:
        lowered = env_key.lower()
        if any(token in lowered for token in ("token", "secret", "password", "key", "credential", "auth")):
            return True
    return False


def _dedupe_signals(values: list[GuardSignal]) -> list[GuardSignal]:
    seen: set[str] = set()
    ordered: list[GuardSignal] = []
    for value in values:
        token = f"{value.signal_id}:{value.explanation}"
        if token in seen:
            continue
        seen.add(token)
        ordered.append(value)
    return ordered
