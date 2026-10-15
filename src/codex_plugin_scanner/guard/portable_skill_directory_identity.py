"""Compatibility import for native skill-directory identity on every platform."""

from .skill_directory_identity import inspect_skill_directory as inspect_skill_directory
from .skill_directory_identity_contract import (
    DEFAULT_SKILL_DIRECTORY_LIMITS as DEFAULT_SKILL_DIRECTORY_LIMITS,
)
from .skill_directory_identity_contract import SKILL_DIRECTORY_IDENTITY_SCHEMA as SKILL_DIRECTORY_IDENTITY_SCHEMA
from .skill_directory_identity_contract import (
    SkillDirectoryIdentity as SkillDirectoryIdentity,
)
from .skill_directory_identity_contract import SkillDirectoryIdentityFailure as SkillDirectoryIdentityFailure
from .skill_directory_identity_contract import (
    SkillDirectoryIdentityLimits as SkillDirectoryIdentityLimits,
)
