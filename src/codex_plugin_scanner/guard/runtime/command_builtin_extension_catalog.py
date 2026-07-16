"""Directly enforced built-in command extension constructor values."""

from __future__ import annotations

from .command_backup_extensions import BACKUP_COMMAND_EXTENSION_SPECS, BACKUP_COMMAND_RULES
from .command_cloud_extensions import CLOUD_COMMAND_EXTENSION_SPECS, CLOUD_COMMAND_RULES
from .command_database_extensions import DATABASE_COMMAND_EXTENSION_SPECS, DATABASE_COMMAND_RULES
from .command_domain_extensions import DOMAIN_COMMAND_EXTENSION_SPECS, DOMAIN_COMMAND_RULES
from .command_extension_specs import CommandExtensionValues, command_extension_values
from .command_remote_extensions import REMOTE_COMMAND_EXTENSION_SPECS, REMOTE_COMMAND_RULES
from .command_storage_extensions import STORAGE_COMMAND_EXTENSION_SPECS, STORAGE_COMMAND_RULES

_DIRECT_EXTENSION_CATALOGS = (
    (DOMAIN_COMMAND_EXTENSION_SPECS, DOMAIN_COMMAND_RULES),
    (CLOUD_COMMAND_EXTENSION_SPECS, CLOUD_COMMAND_RULES),
    (DATABASE_COMMAND_EXTENSION_SPECS, DATABASE_COMMAND_RULES),
    (STORAGE_COMMAND_EXTENSION_SPECS, STORAGE_COMMAND_RULES),
    (BACKUP_COMMAND_EXTENSION_SPECS, BACKUP_COMMAND_RULES),
    (REMOTE_COMMAND_EXTENSION_SPECS, REMOTE_COMMAND_RULES),
)

DIRECT_COMMAND_EXTENSION_VALUES: tuple[CommandExtensionValues, ...] = tuple(
    command_extension_values(spec, rules) for specs, rules in _DIRECT_EXTENSION_CATALOGS for spec in specs
)
