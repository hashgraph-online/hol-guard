"""Materialize inert skill test data for static scanning, never execution."""

from pathlib import Path, PurePath
from shutil import copytree

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MALICIOUS_SKILL_FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "malicious-skill-plugin"
MALICIOUS_SKILL_DOCUMENT = PurePath("skills/leaky-skill/SKILL.md")


def materialize_malicious_skill_plugin(destination: Path) -> Path:
    """Restore the standard filename only in a caller-owned temporary tree.

    The scanner needs the genuine skill layout to exercise its security checks.
    Reject repository destinations so test setup cannot recreate a public skill.
    """
    if destination.resolve().is_relative_to(PROJECT_ROOT):
        raise ValueError("Skill fixtures must be materialized outside the repository")
    copytree(MALICIOUS_SKILL_FIXTURE, destination)
    document = destination / MALICIOUS_SKILL_DOCUMENT
    document.with_name("SKILL.md.fixture").rename(document)
    return destination
