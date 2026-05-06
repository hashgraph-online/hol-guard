"""Shared secret path family classification for Guard runtime surfaces."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

SecretSensitivity = Literal["high", "critical"]
SecretContentSensitivity = Literal["medium", "high", "critical"]

_AWS_CREDENTIALS_MARKER = "/".join((".aws", "credentials"))
_DOCKER_CONFIG_MARKER = "/".join((".docker", "config.json"))
_KUBE_CONFIG_MARKER = "/".join((".kube", "config"))

SECRET_PATH_TEXT_MARKERS: tuple[tuple[str, str], ...] = (
    (".env", "local .env file"),
    (".npmrc", "npm registry credentials"),
    (".pypirc", "Python package credentials"),
    (_AWS_CREDENTIALS_MARKER, "AWS shared credentials file"),
    (".ssh/", "SSH private key"),
    (".gnupg/", "GnuPG key material"),
    (_DOCKER_CONFIG_MARKER, "Docker client config"),
    (_KUBE_CONFIG_MARKER, "Kubernetes config"),
    ("terraform.tfvars", "Terraform variable secrets"),
    (".git-credentials", "Git credential store"),
)
LEGACY_SECRET_PATH_TEXT_MARKERS: tuple[tuple[str, str], ...] = (
    (".env", "local .env file"),
    (".npmrc", "npm registry credentials"),
    (".pypirc", "python package credentials"),
    (".aws/" + "credentials", "aws shared credentials"),
    (".ssh/", "ssh material"),
    (".gnupg/", "gpg material"),
    (".docker/" + "config.json", "docker credentials"),
    (".kube/config", "kubeconfig"),
    (".git-credentials", "git credential store"),
)
_SENSITIVE_BASENAME_LABELS = {
    ".npmrc": "npm registry credentials",
    ".pypirc": "Python package credentials",
    ".netrc": "netrc credentials",
    ".git-credentials": "Git credential store",
    ".terraform.tfvars": "Terraform variable secrets",
    "private-key.pem": "wallet/private-key file",
    "private.key": "wallet/private-key file",
    "wallet.key": "wallet/private-key file",
    "terraform.tfvars": "Terraform variable secrets",
}
_SENSITIVE_BASENAME_KEYWORDS = ("private-key", "private_key", "wallet-key", "wallet_key")
_REDACTED_BASENAME_LABELS = {
    "id_rsa": "SSH private key",
    "id_ed25519": "SSH private key",
    "id_ecdsa": "SSH private key",
}
_SENSITIVE_SUFFIX_LABELS = {
    (".aws", "credentials"): "AWS shared credentials file",
    (".aws", "config"): "AWS shared config file",
    (".docker", "config.json"): "Docker client config",
    (".kube", "config"): "Kubernetes config",
    (".ssh", "id_rsa"): "SSH private key",
    (".ssh", "id_ed25519"): "SSH private key",
    (".ssh", "id_ecdsa"): "SSH private key",
    (".ssh", "config"): "SSH client config",
}
_SENSITIVE_DIRECTORY_LABELS = {
    ".gnupg": "GnuPG key material",
}
_SENSITIVE_PATH_REASONS = {
    "local .env file": "Guard treats .env files as sensitive because they commonly store local secrets.",
    "npm registry credentials": "Guard treats .npmrc as sensitive because it may contain registry tokens.",
    "Python package credentials": "Guard treats .pypirc as sensitive because it may contain package credentials.",
    "netrc credentials": "Guard treats .netrc as sensitive because it may contain login secrets.",
    "Git credential store": "Guard treats .git-credentials as sensitive because it may contain repository credentials.",
    "AWS shared credentials file": (
        "Guard treats AWS shared credentials as sensitive because they contain cloud access keys."
    ),
    "AWS shared config file": "Guard treats AWS shared config as sensitive because it may contain credential profiles.",
    "Docker client config": "Guard treats Docker client config as sensitive because it may contain registry auth.",
    "Kubernetes config": "Guard treats Kubernetes config as sensitive because it may include cluster credentials.",
    "SSH private key": "Guard treats SSH private keys as sensitive because they provide direct host access.",
    "SSH client config": "Guard treats SSH config as sensitive because it may reveal or shape host credentials.",
    "GnuPG key material": "Guard treats GnuPG key material as sensitive because it can unlock encrypted assets.",
    "Terraform variable secrets": (
        "Guard treats Terraform variable files as sensitive because they often contain secrets."
    ),
    "wallet/private-key file": (
        "Guard treats wallet and private-key files as sensitive because they can authorize account control."
    ),
}
_SECRET_ASSIGNMENT_VALUE_PATTERN = r"(?:\"[^\"\r\n]+\"|'[^'\r\n]+'|[^ \t\r\n\"',}]+)"
_HEDERA_PRIVATE_KEY_VALUE_PATTERN = r"(?:\"(?:0x)?[0-9a-f]{64,96}\"|'(?:0x)?[0-9a-f]{64,96}'|(?:0x)?[0-9a-f]{64,96}\b)"
_SAMPLE_SECRET_VALUE_PATTERN = re.compile(r"(?i)\b(?:example|fake|dummy|invalid|test|canary)\b")
_SAMPLE_SUPPRESSIBLE_CONTENT_CLASSIFIERS = frozenset({"credential-assignment", "generic-bearer-token"})
_SECRET_CONTENT_PATTERNS: tuple[tuple[str, str, SecretContentSensitivity, re.Pattern[str], str], ...] = (
    (
        "npm-auth-token",
        "npm auth token",
        "high",
        re.compile(
            r"(?im)[\"']?\b[A-Za-z0-9_-]*(?:_authToken|npm[_-]?token)\b[\"']?\s*[:=]\s*"
            + _SECRET_ASSIGNMENT_VALUE_PATTERN
        ),
        "Guard found an npm registry token pattern.",
    ),
    (
        "github-token",
        "GitHub token",
        "high",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}_[A-Za-z0-9_]{20,})\b"),
        "Guard found a GitHub token pattern.",
    ),
    (
        "aws-access-key",
        "AWS access key",
        "high",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "Guard found an AWS access key pattern.",
    ),
    (
        "openai-api-key",
        "OpenAI API key",
        "high",
        re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"),
        "Guard found an OpenAI API key pattern.",
    ),
    (
        "anthropic-api-key",
        "Anthropic API key",
        "high",
        re.compile(r"\bsk-ant-api03-[A-Za-z0-9_-]{20,}\b"),
        "Guard found an Anthropic API key pattern.",
    ),
    (
        "hedera-private-key",
        "Hedera private key",
        "critical",
        re.compile(
            r"(?im)[\"']?\b[A-Za-z0-9_-]*(?:hedera[_-]?)?(?:operator[_-]?)?private[_-]?key\b[\"']?\s*[:=]\s*"
            + _HEDERA_PRIVATE_KEY_VALUE_PATTERN
        ),
        "Guard found a Hedera private-key-like value.",
    ),
    (
        "pem-private-key",
        "PEM private key",
        "critical",
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.MULTILINE),
        "Guard found a PEM private key header.",
    ),
    (
        "generic-bearer-token",
        "generic bearer token",
        "medium",
        re.compile(r"(?im)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}\b"),
        "Guard found a bearer token pattern.",
    ),
    (
        "credential-marker",
        "credential assignment",
        "medium",
        re.compile(r"(?i)(?:^|[^a-z0-9])fake[_-]?(?:credential|secret)\b"),
        "Guard found credential-looking marker text.",
    ),
    (
        "credential-assignment",
        "credential assignment",
        "medium",
        re.compile(
            r"(?im)[\"']?\b[A-Za-z0-9_-]*(?:api[_-]?key|auth[_-]?token|credential|credentials|npm[_-]?token|"
            r"private[_-]?key|secret|token|password)\b[\"']?\s*[:=]\s*" + _SECRET_ASSIGNMENT_VALUE_PATTERN
        ),
        "Guard found credential-looking assignment text.",
    ),
)


@dataclass(frozen=True, slots=True)
class SecretPathMatch:
    family: str
    path: str
    sensitivity: SecretSensitivity
    reason: str
    requested_path: str = ""

    @property
    def normalized_path(self) -> str:
        return self.path

    @property
    def path_class(self) -> str:
        return self.family


@dataclass(frozen=True, slots=True)
class SecretContentMatch:
    classifier: str
    family: str
    sensitivity: SecretContentSensitivity
    reason: str


def classify_secret_path(
    path: str | None,
    *,
    cwd: Path | None = None,
    home_dir: Path | None = None,
) -> SecretPathMatch | None:
    if not isinstance(path, str):
        return None
    requested_path = path.strip().strip("'").strip('"')
    if not requested_path:
        return None
    expanded_home = _expand_home(requested_path, home_dir)
    normalized_path = _normalize_path(expanded_home, cwd)
    lowered_segments = tuple(segment for segment in normalized_path.replace("\\", "/").lower().split("/") if segment)
    if not lowered_segments:
        return None
    basename = lowered_segments[-1]
    if basename == ".env" or basename.startswith(".env."):
        return _match(
            requested_path=requested_path,
            normalized_path=normalized_path,
            family="local .env file",
            sensitivity="critical",
        )
    if basename in _SENSITIVE_BASENAME_LABELS:
        family = _SENSITIVE_BASENAME_LABELS[basename]
        sensitivity: SecretSensitivity = "critical" if family == "wallet/private-key file" else "high"
        return _match(
            requested_path=requested_path,
            normalized_path=normalized_path,
            family=family,
            sensitivity=sensitivity,
        )
    if any(keyword in basename for keyword in _SENSITIVE_BASENAME_KEYWORDS):
        return _match(
            requested_path=requested_path,
            normalized_path=normalized_path,
            family="wallet/private-key file",
            sensitivity="critical",
        )
    if "..." in lowered_segments and basename in _REDACTED_BASENAME_LABELS:
        family = _REDACTED_BASENAME_LABELS[basename]
        sensitivity: SecretSensitivity = "critical" if family == "SSH private key" else "high"
        return _match(
            requested_path=requested_path,
            normalized_path=normalized_path,
            family=family,
            sensitivity=sensitivity,
        )
    for directory, family in _SENSITIVE_DIRECTORY_LABELS.items():
        if directory in lowered_segments:
            return _match(
                requested_path=requested_path,
                normalized_path=normalized_path,
                family=family,
                sensitivity="high",
            )
    for suffix, family in _SENSITIVE_SUFFIX_LABELS.items():
        if lowered_segments[-len(suffix) :] == suffix:
            sensitivity: SecretSensitivity = "critical" if family == "SSH private key" else "high"
            return _match(
                requested_path=requested_path,
                normalized_path=normalized_path,
                family=family,
                sensitivity=sensitivity,
            )
    return None


def classify_secret_path_families(text: str) -> set[str]:
    lowered = text.lower()
    return {family for marker, family in SECRET_PATH_TEXT_MARKERS if marker in lowered}


def classify_legacy_secret_path_families(text: str) -> set[str]:
    lowered = text.lower()
    return {family for marker, family in LEGACY_SECRET_PATH_TEXT_MARKERS if marker in lowered}


def classify_secret_content(text: str | None, *, suppress_samples: bool = True) -> tuple[SecretContentMatch, ...]:
    if not isinstance(text, str) or not text.strip():
        return ()
    matches: list[SecretContentMatch] = []
    seen: set[str] = set()
    for classifier, family, sensitivity, pattern, reason in _SECRET_CONTENT_PATTERNS:
        if classifier in seen:
            continue
        if not any(
            not _secret_content_match_is_sample(classifier=classifier, text=match.group(0), enabled=suppress_samples)
            for match in pattern.finditer(text)
        ):
            continue
        seen.add(classifier)
        matches.append(
            SecretContentMatch(
                classifier=classifier,
                family=family,
                sensitivity=sensitivity,
                reason=reason,
            )
        )
    return tuple(matches)


def _secret_content_match_is_sample(*, classifier: str, text: str, enabled: bool) -> bool:
    if not enabled or classifier not in _SAMPLE_SUPPRESSIBLE_CONTENT_CLASSIFIERS:
        return False
    if classifier == "generic-bearer-token":
        token = text.rsplit(None, 1)[-1]
        return _SAMPLE_SECRET_VALUE_PATTERN.search(token) is not None and re.search(r"[A-Za-z0-9]{20,}", token) is None
    return _SAMPLE_SECRET_VALUE_PATTERN.search(text) is not None


def redacted_secret_path_context(path: str) -> str | None:
    segments = tuple(segment for segment in path.replace("\\", "/").split("/") if segment)
    lowered_segments = tuple(segment.lower() for segment in segments)
    if not lowered_segments:
        return None
    for suffix in _SENSITIVE_SUFFIX_LABELS:
        if lowered_segments[-len(suffix) :] == suffix:
            return ".../" + "/".join(suffix)
    for directory in _SENSITIVE_DIRECTORY_LABELS:
        if directory in lowered_segments and len(segments) > 1:
            return f".../{directory}/{segments[-1]}"
    return None


def _match(
    *,
    requested_path: str,
    normalized_path: str,
    family: str,
    sensitivity: SecretSensitivity,
) -> SecretPathMatch:
    return SecretPathMatch(
        family=family,
        path=normalized_path,
        sensitivity=sensitivity,
        reason=_SENSITIVE_PATH_REASONS[family],
        requested_path=requested_path,
    )


def _expand_home(value: str, home_dir: Path | None) -> str:
    if value == "~":
        return str(home_dir or Path.home())
    if value.startswith("~/") or value.startswith("~\\"):
        base = home_dir or Path.home()
        return str(base / value[2:])
    return value


def _normalize_path(value: str, cwd: Path | None) -> str:
    if os.path.isabs(value):
        return os.path.normpath(value)
    if cwd is not None:
        return os.path.normpath(os.path.join(str(cwd), value))
    return os.path.normpath(value)
