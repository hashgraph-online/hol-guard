"""Directly enforced built-in command extension constructor values."""

from __future__ import annotations

from .command_backup_extensions import BACKUP_COMMAND_EXTENSION_SPECS, BACKUP_COMMAND_RULES
from .command_cicd_extensions import CICD_COMMAND_EXTENSION_SPECS, CICD_COMMAND_RULES
from .command_cloud_extensions import CLOUD_COMMAND_EXTENSION_SPECS, CLOUD_COMMAND_RULES
from .command_common_cli_extensions import COMMON_CLI_COMMAND_EXTENSION_SPECS, COMMON_CLI_COMMAND_RULES
from .command_database_extensions import DATABASE_COMMAND_EXTENSION_SPECS, DATABASE_COMMAND_RULES
from .command_domain_extensions import DOMAIN_COMMAND_EXTENSION_SPECS, DOMAIN_COMMAND_RULES
from .command_extension_specs import CommandExtensionValues, command_extension_values
from .command_github_rules import GITHUB_COMMAND_EXTENSION_SPECS, GITHUB_COMMAND_RULES
from .command_managed_service_extensions import MANAGED_SERVICE_COMMAND_EXTENSION_SPECS, MANAGED_SERVICE_COMMAND_RULES
from .command_noodle_extensions import NOODLE_COMMAND_EXTENSION_SPECS, NOODLE_COMMAND_RULES
from .command_platform_extensions import PLATFORM_COMMAND_EXTENSION_SPECS, PLATFORM_COMMAND_RULES
from .command_remote_extensions import REMOTE_COMMAND_EXTENSION_SPECS, REMOTE_COMMAND_RULES
from .command_search_messaging_extensions import (
    SEARCH_MESSAGING_COMMAND_EXTENSION_SPECS,
    SEARCH_MESSAGING_COMMAND_RULES,
)
from .command_skill_sunset_extensions import (
    SKILL_SUNSET_COMMAND_EXTENSION_SPECS,
    SKILL_SUNSET_COMMAND_RULES,
)
from .command_storage_extensions import STORAGE_COMMAND_EXTENSION_SPECS, STORAGE_COMMAND_RULES

_DIRECT_EXTENSION_CATALOGS = (
    (DOMAIN_COMMAND_EXTENSION_SPECS, DOMAIN_COMMAND_RULES),
    (CLOUD_COMMAND_EXTENSION_SPECS, CLOUD_COMMAND_RULES),
    (DATABASE_COMMAND_EXTENSION_SPECS, DATABASE_COMMAND_RULES),
    (STORAGE_COMMAND_EXTENSION_SPECS, STORAGE_COMMAND_RULES),
    (BACKUP_COMMAND_EXTENSION_SPECS, BACKUP_COMMAND_RULES),
    (REMOTE_COMMAND_EXTENSION_SPECS, REMOTE_COMMAND_RULES),
    (CICD_COMMAND_EXTENSION_SPECS, CICD_COMMAND_RULES),
    (PLATFORM_COMMAND_EXTENSION_SPECS, PLATFORM_COMMAND_RULES),
    (MANAGED_SERVICE_COMMAND_EXTENSION_SPECS, MANAGED_SERVICE_COMMAND_RULES),
    (SEARCH_MESSAGING_COMMAND_EXTENSION_SPECS, SEARCH_MESSAGING_COMMAND_RULES),
    (NOODLE_COMMAND_EXTENSION_SPECS, NOODLE_COMMAND_RULES),
    (SKILL_SUNSET_COMMAND_EXTENSION_SPECS, SKILL_SUNSET_COMMAND_RULES),
    (GITHUB_COMMAND_EXTENSION_SPECS, GITHUB_COMMAND_RULES),
    (COMMON_CLI_COMMAND_EXTENSION_SPECS, COMMON_CLI_COMMAND_RULES),
)

# Later catalogs may deliberately replace metadata for an existing stable ID while
# all rule tuples remain additive. This lets a release expand one capability
# boundary without creating a duplicate registry identity.
_DIRECT_EXTENSION_SPEC_BY_ID = {
    spec.extension_id: spec for specs, _rules in _DIRECT_EXTENSION_CATALOGS for spec in specs
}
_DIRECT_COMMAND_RULES = tuple(rule for _specs, rules in _DIRECT_EXTENSION_CATALOGS for rule in rules)

DIRECT_COMMAND_EXTENSION_VALUES: tuple[CommandExtensionValues, ...] = tuple(
    command_extension_values(_DIRECT_EXTENSION_SPEC_BY_ID[extension_id], _DIRECT_COMMAND_RULES)
    for extension_id in sorted(_DIRECT_EXTENSION_SPEC_BY_ID)
)
