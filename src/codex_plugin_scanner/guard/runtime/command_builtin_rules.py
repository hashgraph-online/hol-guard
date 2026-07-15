"""Built-in compatibility rules for existing Guard command action classes."""

from __future__ import annotations

from .command_rules import CommandSafetyRule

COMMAND_ACTION_RISK_CLASSES: dict[str, tuple[str, ...]] = {
    "credential exfiltration shell command": (
        "data_flow_exfiltration",
        "credential_exfiltration",
        "network_egress",
    ),
    "guard-managed config write": ("destructive_shell",),
    "docker-sensitive command": ("network_egress", "destructive_shell"),
    "docker client config access": ("local_secret_read",),
    "encoded or encrypted shell command": ("encoded_execution",),
    "kubernetes secret read command": ("local_secret_read",),
    "shell file upload command": ("credential_exfiltration", "network_egress"),
    "sensitive local file write": ("destructive_shell", "local_secret_read"),
    "destructive shell command": ("destructive_shell",),
    "guard approval self-authorization command": ("policy_bypass",),
    "github pr body shell substitution": ("execution",),
}


def _compatibility_rule(
    *,
    rule_id: str,
    title: str,
    description: str,
    action_class: str,
    safer_alternative: str,
) -> CommandSafetyRule:
    return CommandSafetyRule(
        rule_id=rule_id,
        title=title,
        description=description,
        severity="high",
        risk_classes=COMMAND_ACTION_RISK_CLASSES[action_class.lower()],
        action_classes=(action_class,),
        safer_alternatives=(safer_alternative,),
    )


BUILT_IN_COMMAND_RULES = (
    _compatibility_rule(
        rule_id="command.container-runtime.docker-sensitive",
        title="Sensitive container operation",
        description="Identifies container operations that can expose credentials or mutate protected state.",
        action_class="docker-sensitive command",
        safer_alternative="Use a pinned image, minimal privileges, and a preview where the command supports one.",
    ),
    _compatibility_rule(
        rule_id="command.container-runtime.docker-config-access",
        title="Container credential access",
        description="Identifies reads of local container client authentication configuration.",
        action_class="Docker client config access",
        safer_alternative="Pass only the specific credential material required by the operation.",
    ),
    _compatibility_rule(
        rule_id="command.data-protection.credential-exfiltration",
        title="Credential data transfer",
        description="Identifies shell flows that can send credential material to a network destination.",
        action_class="credential exfiltration shell command",
        safer_alternative="Send an explicit non-secret value and review the exact destination and payload.",
    ),
    _compatibility_rule(
        rule_id="command.data-protection.file-upload",
        title="Local file upload",
        description="Identifies shell upload flows that read local files or standard input.",
        action_class="shell file upload command",
        safer_alternative="Upload a reviewed non-secret artifact through an allowlisted destination.",
    ),
    _compatibility_rule(
        rule_id="command.encoded-execution.decode-and-execute",
        title="Encoded execution",
        description="Identifies decode or decrypt chains that immediately execute their output.",
        action_class="encoded or encrypted shell command",
        safer_alternative="Decode to a file, inspect the result, then invoke the reviewed file directly.",
    ),
    _compatibility_rule(
        rule_id="command.guard-self-protection.self-authorization",
        title="Guard self-authorization",
        description="Identifies commands that attempt to approve or weaken their own Guard decision.",
        action_class="Guard approval self-authorization command",
        safer_alternative="Approve the request through Guard's authenticated approval surface.",
    ),
    _compatibility_rule(
        rule_id="command.kubernetes-secrets.secret-read",
        title="Cluster secret read",
        description="Identifies cluster CLI operations that can reveal Secret payloads.",
        action_class="Kubernetes secret read command",
        safer_alternative="Request non-secret metadata or only the specific field required.",
    ),
    _compatibility_rule(
        rule_id="command.shell-mutations.destructive-shell",
        title="Destructive shell mutation",
        description="Identifies destructive shell, filesystem, and version-control mutations.",
        action_class="destructive shell command",
        safer_alternative="Use a dry run or narrow preview before applying the mutation.",
    ),
    _compatibility_rule(
        rule_id="command.shell-mutations.managed-config-write",
        title="Guard-managed configuration write",
        description="Identifies direct writes to configuration managed by Guard.",
        action_class="guard-managed config write",
        safer_alternative="Use Guard's setup or repair command to update managed configuration.",
    ),
    _compatibility_rule(
        rule_id="command.shell-mutations.sensitive-file-write",
        title="Sensitive local file write",
        description="Identifies writes that can replace or expose sensitive local state.",
        action_class="sensitive local file write",
        safer_alternative="Write to a scoped temporary path and review the final destination.",
    ),
    _compatibility_rule(
        rule_id="command.shell-mutations.github-body-substitution",
        title="Command substitution in remote body",
        description="Identifies shell substitution used to construct a remote request body.",
        action_class="GitHub PR body shell substitution",
        safer_alternative="Use a literal body file whose contents can be reviewed before submission.",
    ),
)

_RULES_BY_EXTENSION: dict[str, tuple[CommandSafetyRule, ...]] = {}
for _rule_definition in BUILT_IN_COMMAND_RULES:
    _extension_id, _separator, _rule_name = _rule_definition.rule_id.rpartition(".")
    _RULES_BY_EXTENSION[_extension_id] = (*_RULES_BY_EXTENSION.get(_extension_id, ()), _rule_definition)


def rules_for_extension(extension_id: str) -> tuple[CommandSafetyRule, ...]:
    """Return deterministic built-in rules owned by one extension."""

    return _RULES_BY_EXTENSION.get(extension_id, ())
