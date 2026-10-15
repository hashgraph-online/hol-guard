"""Compatibility import for native non-reusable skill-directory identities."""

from .native_skill_directory_identity import (
    native_incomplete_skill_directory_identity as incomplete_skill_directory_identity,
)
from .skill_directory_identity_contract import (
    SKILL_DIRECTORY_IDENTITY_SCHEMA,
    SkillDirectoryIdentity,
    SkillDirectoryIdentityFailure,
)

__all__ = [
    "SKILL_DIRECTORY_IDENTITY_SCHEMA",
    "SkillDirectoryIdentity",
    "SkillDirectoryIdentityFailure",
    "incomplete_skill_directory_identity",
]
