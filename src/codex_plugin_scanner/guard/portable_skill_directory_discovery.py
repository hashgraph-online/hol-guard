"""Compatibility import for native skill-document discovery on every platform."""

from .skill_directory_discovery import discover_skill_documents as discover_skill_documents
from .skill_directory_identity_contract import (
    DEFAULT_SKILL_DIRECTORY_LIMITS as DEFAULT_SKILL_DIRECTORY_LIMITS,
)
from .skill_directory_identity_contract import SkillDirectoryIdentityFailure as SkillDirectoryIdentityFailure
from .skill_directory_identity_contract import (
    SkillDirectoryIdentityLimits as SkillDirectoryIdentityLimits,
)
from .skill_directory_identity_contract import (
    SkillDocumentDiscovery as SkillDocumentDiscovery,
)
from .skill_directory_identity_contract import (
    SkillDocumentDiscoveryIssue as SkillDocumentDiscoveryIssue,
)
