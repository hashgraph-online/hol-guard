"""HOL Guard leaked-secret detection primitives."""

from .secret_detection import (
    SECRET_RULES,
    SecretFinding,
    SecretScanSummary,
    detector_version,
    scan_secret_text,
    secret_rule_catalog,
    shannon_entropy,
)
from .secret_repository_scanner import RepositorySecretScanResult, scan_repository_secrets

__all__ = [
    "SECRET_RULES",
    "RepositorySecretScanResult",
    "SecretFinding",
    "SecretScanSummary",
    "detector_version",
    "scan_repository_secrets",
    "scan_secret_text",
    "secret_rule_catalog",
    "shannon_entropy",
]
