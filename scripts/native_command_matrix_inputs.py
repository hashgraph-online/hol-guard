"""Reviewed catalog subsets and control cases for component diagnostics only."""

from __future__ import annotations

from collections.abc import Iterator

from codex_plugin_scanner.guard.runtime.command_extensions import (
    BUILT_IN_COMMAND_EXTENSION_REGISTRY as REGISTRY,
)
from codex_plugin_scanner.guard.runtime.command_extensions import (
    CommandSafetyExtensionRegistry,
)
from codex_plugin_scanner.guard.runtime.extension_control_contract import (
    ControlLayerKind,
    ControlState,
    ControlTarget,
    ControlTargetKind,
    ExtensionControl,
    ExtensionControlLayer,
)

# Intent labels are independent of both implementations. A review of benign
# input is counted even where an existing conservative policy explains it.
COMMANDS = (
    ("benign", "pwd"),
    ("benign", "printf café"),
    ("benign", "git status"),
    ("benign", "git diff --stat"),
    ("benign", "gh issue view 123"),
    ("benign", "ollama push --help"),
    ("benign", "aws s3 rm --help"),
    ("benign", "sqlite3 fixture.db 'SELECT 1'"),
    ("benign", "psql -c 'SELECT 1'"),
    ("benign", "terraform plan"),
    ("benign", "kubectl get pods"),
    ("benign", "docker ps"),
    ("destructive", "ollama push fixture-model"),
    ("destructive", "ollama rm first && ollama push second"),
    ("destructive", "aws s3 rm s3://fixture-bucket/key"),
    ("destructive", "sqlite3 fixture.db 'DROP TABLE fixture'"),
    ("destructive", "rm -rf /"),
    ("destructive", "ollama push fixture-model && rm -rf /"),
    ("ambiguous", "git fixture-alias"),
    ("ambiguous", "gh api graphql -f query='query { viewer { login } }'"),
    ("ambiguous", "python -m json.tool café"),
    ("benign", "pwd && git status && gh issue view 123 && printf café"),
)


def catalogs() -> Iterator[tuple[str, CommandSafetyExtensionRegistry]]:
    by_id = {extension.extension_id: extension for extension in REGISTRY.extensions}
    permission_owner = {
        permission.permission_id: extension.extension_id
        for extension in REGISTRY.extensions
        for permission in extension.permissions
    }
    selected = {
        extension.extension_id
        for extension in REGISTRY.extensions
        if any(rule.matcher is None for rule in extension.rules)
    }
    selected.add("command.ollama")

    def close_dependencies() -> None:
        while True:
            previous = len(selected)
            for identity in tuple(selected):
                extension = by_id[identity]
                selected.update(extension.dependencies)
                for permission in extension.permissions:
                    selected.update(
                        permission_owner[target]
                        for target in (*permission.dependencies, *permission.implied_permissions)
                    )
            if len(selected) == previous:
                return

    close_dependencies()
    for name, minimum in (("compatibility-plus-ollama", 0), ("medium", 48), ("full", len(by_id))):
        for identity in sorted(by_id):
            if len(selected) >= minimum:
                break
            selected.add(identity)
        close_dependencies()
        yield name, CommandSafetyExtensionRegistry(tuple(by_id[identity] for identity in selected))


def control_cases(registry: CommandSafetyExtensionRegistry) -> Iterator[tuple[str, tuple[ExtensionControlLayer, ...]]]:
    targets = [("extension", "command.ollama")]
    targets.extend(
        sorted(
            {
                ("extension", extension.extension_id)
                for extension in registry.extensions
                if extension.extension_id != "command.ollama"
            }
            | {
                ("permission", permission.permission_id)
                for extension in registry.extensions
                for permission in extension.permissions
            }
        )
    )

    def layer(kind: str, rows: list[tuple[str, str]], state: str = "enabled") -> ExtensionControlLayer:
        return ExtensionControlLayer(
            "1.0.0",
            ControlLayerKind(kind),
            registry.catalog_digest,
            False,
            tuple(
                ExtensionControl(ControlTarget(ControlTargetKind(key), identity), ControlState(state))
                for key, identity in sorted(rows)
            ),
        )

    yield "defaults", ()
    yield "local-opt-in", (layer("local-admin", targets[:1]),)
    yield "managed-only", (layer("signed-cloud", targets[:1]),)
    for size in sorted({min(32, len(targets)), min(128, len(targets)), len(targets)}):
        yield f"local-{size}", (layer("local-admin", targets[:size]),)
    yield "both-layers-all", (layer("local-admin", targets), layer("signed-cloud", targets))
    yield "disable-dominates", (layer("local-admin", targets), layer("signed-cloud", targets, "disabled"))
    yield "external-disabled", (layer("local-admin", targets[:1], "disabled"),)
    restricted = [
        (kind, identity)
        for kind, identity in targets
        if identity
        in {
            "command.git.permission.status",
            "command.github.permission.read-remote",
            "command.ollama.permission.push",
        }
    ]
    yield "permission-disabled", (layer("local-admin", targets[:1]), layer("signed-cloud", restricted, "disabled"))
