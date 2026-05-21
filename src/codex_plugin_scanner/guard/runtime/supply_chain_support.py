"""Shared ecosystem support labels for Guard local supply-chain coverage."""

from __future__ import annotations

_SUPPORT_LEVELS: dict[str, tuple[str, str, str]] = {
    "npm": ("npm", "protected", "Protected"),
    "pypi": ("PyPI", "protected", "Protected"),
    "cargo": ("Cargo", "beta", "Beta"),
    "go": ("Go modules", "beta", "Beta"),
    "maven": ("Maven/Gradle", "beta", "Beta"),
    "packagist": ("Composer", "beta", "Beta"),
    "rubygems": ("RubyGems", "beta", "Beta"),
    "docker": ("Docker base images", "monitor-only", "Monitor-only"),
    "github-actions": ("GitHub Actions", "monitor-only", "Monitor-only"),
    "system": ("System packages", "monitor-only", "Monitor-only"),
    "unsupported": ("Unsupported managers", "monitor-only", "Monitor-only"),
}

_SUPPORT_ORDER = (
    "npm",
    "pypi",
    "cargo",
    "go",
    "maven",
    "packagist",
    "rubygems",
    "docker",
    "github-actions",
    "system",
    "unsupported",
)


def ecosystem_support_metadata(ecosystem: str) -> dict[str, str]:
    display_name, support_level, support_label = _SUPPORT_LEVELS.get(
        ecosystem,
        (ecosystem.replace("-", " ").title(), "monitor-only", "Monitor-only"),
    )
    return {
        "display_name": display_name,
        "support_level": support_level,
        "support_label": support_label,
    }


def ecosystem_support_matrix() -> tuple[dict[str, str], ...]:
    return tuple(
        {
            "ecosystem": ecosystem,
            **ecosystem_support_metadata(ecosystem),
        }
        for ecosystem in _SUPPORT_ORDER
    )
