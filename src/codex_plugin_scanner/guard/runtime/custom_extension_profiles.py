"""Curated command trees for popular CLIs offered as custom extensions.

A profile only describes commands and suggests a starting rule for each one.
Suggestions pre-fill the custom extension editor; nothing is enforced until the
user saves the extension through the normal trust-gated apply flow.

``root`` is never suggested as allowed: command matching stops at the first
flag, so ``wrangler --env prod deploy`` resolves to ``root`` as well.

Commands that change remote state are left on ``inherit``: CLI commands cannot
carry an explicit review rule, and Guard's command authority already asks
before running anything it cannot prove read-only. Legacy colon forms such as
``kv:key`` do not match a command id, so allow rules never reach them.
"""

from __future__ import annotations

from dataclasses import dataclass

from .local_cli_commands import LocalCliCommand, LocalCliCommandState


@dataclass(frozen=True, slots=True)
class ProfileCommand:
    command: LocalCliCommand
    suggested_state: LocalCliCommandState = "inherit"


@dataclass(frozen=True, slots=True)
class KnownCliProfile:
    profile_id: str
    display_name: str
    brand: str
    homepage: str
    executables: frozenset[str]
    commands: tuple[ProfileCommand, ...]

    def suggested_states(self) -> dict[str, LocalCliCommandState]:
        return {entry.command.command_id: entry.suggested_state for entry in self.commands}

    def local_cli_commands(self) -> tuple[LocalCliCommand, ...]:
        return tuple(entry.command for entry in self.commands)


def _commands(
    executable: str,
    rows: tuple[tuple[str, LocalCliCommandState, str], ...],
) -> tuple[ProfileCommand, ...]:
    entries: list[ProfileCommand] = []
    for command_id, state, description in rows:
        parts = command_id.split(".")
        entries.append(
            ProfileCommand(
                LocalCliCommand(
                    command_id=command_id,
                    name=parts[-1],
                    usage=" ".join((executable, *parts)),
                    description=description,
                    parent_id=".".join(parts[:-1]) or None,
                ),
                state,
            )
        )
    return tuple(entries)


_WRANGLER_COMMANDS: tuple[tuple[str, LocalCliCommandState, str], ...] = (
    ("whoami", "allow", "Show the signed-in Cloudflare account."),
    ("login", "inherit", "Sign in to Cloudflare and store an OAuth token."),
    ("logout", "inherit", "Remove the stored Cloudflare token."),
    ("init", "inherit", "Create a new Worker project."),
    ("dev", "inherit", "Run the Worker locally."),
    ("types", "allow", "Generate TypeScript types for bindings."),
    ("tail", "allow", "Stream live logs from a deployed Worker."),
    ("deploy", "inherit", "Deploy the Worker to Cloudflare."),
    ("publish", "inherit", "Deploy the Worker (legacy command)."),
    ("delete", "inherit", "Delete a deployed Worker."),
    ("rollback", "inherit", "Roll back to an earlier Worker version."),
    ("preview", "inherit", "Create a preview deployment."),
    ("preview.delete", "inherit", "Delete a preview deployment."),
    ("deployments", "inherit", "Inspect Worker deployments."),
    ("deployments.list", "allow", "List recent deployments."),
    ("deployments.status", "allow", "Show the active deployment."),
    ("versions", "inherit", "Manage Worker versions."),
    ("versions.list", "allow", "List Worker versions."),
    ("versions.view", "allow", "Show one Worker version."),
    ("versions.upload", "inherit", "Upload a new Worker version."),
    ("versions.deploy", "inherit", "Shift traffic to Worker versions."),
    ("versions.secret", "inherit", "Manage secrets on a Worker version."),
    ("versions.secret.put", "inherit", "Create or replace a version secret."),
    ("versions.secret.delete", "inherit", "Delete a version secret."),
    ("versions.secret.bulk", "inherit", "Upload many version secrets."),
    ("triggers", "inherit", "Manage Worker triggers."),
    ("triggers.deploy", "inherit", "Apply trigger changes."),
    ("secret", "inherit", "Manage Worker secrets."),
    ("secret.list", "inherit", "List secret names."),
    ("secret.put", "inherit", "Create or replace a secret."),
    ("secret.delete", "inherit", "Delete a secret."),
    ("secret.bulk", "inherit", "Upload many secrets."),
    ("d1", "inherit", "Manage D1 databases."),
    ("d1.list", "allow", "List D1 databases."),
    ("d1.info", "allow", "Show D1 database details."),
    ("d1.execute", "inherit", "Run SQL against a D1 database."),
    ("d1.delete", "inherit", "Delete a D1 database."),
    ("d1.migrations", "inherit", "Manage D1 migrations."),
    ("d1.migrations.apply", "inherit", "Apply pending D1 migrations."),
    ("kv", "inherit", "Manage Workers KV."),
    ("kv.namespace", "inherit", "Manage KV namespaces."),
    ("kv.namespace.list", "allow", "List KV namespaces."),
    ("kv.namespace.delete", "inherit", "Delete a KV namespace."),
    ("kv.key", "inherit", "Manage KV keys."),
    ("kv.key.list", "allow", "List keys in a namespace."),
    ("kv.key.put", "inherit", "Write a KV value."),
    ("kv.key.delete", "inherit", "Delete a KV key."),
    ("kv.bulk", "inherit", "Bulk KV operations."),
    ("kv.bulk.put", "inherit", "Write many KV values."),
    ("kv.bulk.delete", "inherit", "Delete many KV keys."),
    ("r2", "inherit", "Manage R2 storage."),
    ("r2.bucket", "inherit", "Manage R2 buckets."),
    ("r2.bucket.list", "allow", "List R2 buckets."),
    ("r2.bucket.delete", "inherit", "Delete an R2 bucket."),
    ("r2.object", "inherit", "Manage R2 objects."),
    ("r2.object.put", "inherit", "Upload an R2 object."),
    ("r2.object.delete", "inherit", "Delete an R2 object."),
    ("queues", "inherit", "Manage Queues."),
    ("queues.delete", "inherit", "Delete a queue."),
    ("pages", "inherit", "Manage Pages projects."),
    ("pages.deploy", "inherit", "Deploy a Pages site."),
    ("pages.project", "inherit", "Manage Pages projects."),
    ("pages.project.delete", "inherit", "Delete a Pages project."),
    ("pages.deployment", "inherit", "Manage Pages deployments."),
    ("pages.deployment.delete", "inherit", "Delete a Pages deployment."),
)

WRANGLER_PROFILE = KnownCliProfile(
    profile_id="wrangler",
    display_name="Cloudflare Wrangler",
    brand="cloudflare",
    homepage="https://developers.cloudflare.com/workers/wrangler/",
    executables=frozenset({"wrangler"}),
    commands=_commands("wrangler", _WRANGLER_COMMANDS),
)

KNOWN_CLI_PROFILES: tuple[KnownCliProfile, ...] = (WRANGLER_PROFILE,)


def profile_for_executable(name: object) -> KnownCliProfile | None:
    if not isinstance(name, str):
        return None
    normalized = name.strip().lower()
    for suffix in (".cmd", ".exe"):
        normalized = normalized.removesuffix(suffix)
    for profile in KNOWN_CLI_PROFILES:
        if normalized in profile.executables:
            return profile
    return None


__all__ = [
    "KNOWN_CLI_PROFILES",
    "WRANGLER_PROFILE",
    "KnownCliProfile",
    "ProfileCommand",
    "profile_for_executable",
]
