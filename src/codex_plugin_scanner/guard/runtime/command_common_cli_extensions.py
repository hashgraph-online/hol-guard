"""First-class coverage for common production, secrets, GitOps, and package CLIs."""

from __future__ import annotations

from .command_common_cli_rules_1 import COMMON_CLI_COMMAND_RULES_1
from .command_common_cli_rules_2 import COMMON_CLI_COMMAND_RULES_2
from .command_common_cli_rules_3 import COMMON_CLI_COMMAND_RULES_3
from .command_common_cli_rules_4 import COMMON_CLI_COMMAND_RULES_4
from .command_common_cli_specs import COMMON_CLI_COMMAND_EXTENSION_SPECS

COMMON_CLI_COMMAND_RULES = (
    *COMMON_CLI_COMMAND_RULES_1,
    *COMMON_CLI_COMMAND_RULES_2,
    *COMMON_CLI_COMMAND_RULES_3,
    *COMMON_CLI_COMMAND_RULES_4,
)

__all__ = ("COMMON_CLI_COMMAND_EXTENSION_SPECS", "COMMON_CLI_COMMAND_RULES")
