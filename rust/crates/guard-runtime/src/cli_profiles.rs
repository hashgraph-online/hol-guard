//! `cli_profiles` runner-authority kind: curated command trees for popular
//! CLIs offered as custom extensions.
//!
//! A profile only describes commands and suggests a starting rule for each
//! one. Suggestions pre-fill the custom extension editor; nothing is enforced
//! until the user saves the extension through the normal trust-gated apply
//! flow.
//!
//! `root` is never suggested as allowed: command matching stops at the first
//! flag, so `wrangler --env prod deploy` resolves to `root` as well. Commands
//! that change remote state are left on `inherit`: CLI commands cannot carry
//! an explicit review rule, and Guard's command authority already asks before
//! running anything it cannot prove read-only. Legacy colon forms such as
//! `kv:key` do not match a command id, so allow rules never reach them.
//!
//! `{}` answers `{"profiles": [profile, ...]}`; `{"executable": name}`
//! answers `{"profile_id": id | null}` for the profile whose executable the
//! name is, ignoring case, surrounding whitespace and a `.cmd`/`.exe` suffix.

use guard_contracts::python_strip;
use serde_json::{json, Value};

use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

struct Profile {
    id: &'static str,
    display_name: &'static str,
    brand: &'static str,
    homepage: &'static str,
    executables: &'static [&'static str],
    /// `(command id, suggested state, description)`, parents before children.
    commands: &'static [(&'static str, &'static str, &'static str)],
}

const PROFILES: &[Profile] = &[Profile {
    id: "wrangler",
    display_name: "Cloudflare Wrangler",
    brand: "cloudflare",
    homepage: "https://developers.cloudflare.com/workers/wrangler/",
    executables: &["wrangler"],
    commands: WRANGLER_COMMANDS,
}];

const WRANGLER_COMMANDS: &[(&str, &str, &str)] = &[
    ("whoami", "allow", "Show the signed-in Cloudflare account."),
    (
        "login",
        "inherit",
        "Sign in to Cloudflare and store an OAuth token.",
    ),
    ("logout", "inherit", "Remove the stored Cloudflare token."),
    ("init", "inherit", "Create a new Worker project."),
    ("dev", "inherit", "Run the Worker locally."),
    ("types", "allow", "Generate TypeScript types for bindings."),
    ("tail", "allow", "Stream live logs from a deployed Worker."),
    ("deploy", "inherit", "Deploy the Worker to Cloudflare."),
    ("publish", "inherit", "Deploy the Worker (legacy command)."),
    ("delete", "inherit", "Delete a deployed Worker."),
    (
        "rollback",
        "inherit",
        "Roll back to an earlier Worker version.",
    ),
    ("preview", "inherit", "Create a preview deployment."),
    ("preview.delete", "inherit", "Delete a preview deployment."),
    ("deployments", "inherit", "Inspect Worker deployments."),
    ("deployments.list", "allow", "List recent deployments."),
    ("deployments.status", "allow", "Show the active deployment."),
    ("versions", "inherit", "Manage Worker versions."),
    ("versions.list", "allow", "List Worker versions."),
    ("versions.view", "allow", "Show one Worker version."),
    ("versions.upload", "inherit", "Upload a new Worker version."),
    (
        "versions.deploy",
        "inherit",
        "Shift traffic to Worker versions.",
    ),
    (
        "versions.secret",
        "inherit",
        "Manage secrets on a Worker version.",
    ),
    (
        "versions.secret.put",
        "inherit",
        "Create or replace a version secret.",
    ),
    (
        "versions.secret.delete",
        "inherit",
        "Delete a version secret.",
    ),
    (
        "versions.secret.bulk",
        "inherit",
        "Upload many version secrets.",
    ),
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
    (
        "d1.migrations.apply",
        "inherit",
        "Apply pending D1 migrations.",
    ),
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
    (
        "pages.deployment.delete",
        "inherit",
        "Delete a Pages deployment.",
    ),
];

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let args = args_object(args)?;
    match args.get("executable") {
        None if args.is_empty() => Ok(json!({
            "profiles": PROFILES.iter().map(profile_value).collect::<Vec<_>>()
        })),
        Some(Value::String(name)) if args.len() == 1 => Ok(json!({
            "profile_id": profile_for_executable(name).map(|profile| profile.id)
        })),
        _ => Err(ERR_INVALID),
    }
}

fn profile_for_executable(name: &str) -> Option<&'static Profile> {
    let lowered = python_strip(name).to_lowercase();
    let mut normalized = lowered.as_str();
    for suffix in [".cmd", ".exe"] {
        normalized = normalized.strip_suffix(suffix).unwrap_or(normalized);
    }
    PROFILES.iter().find(|profile| {
        profile
            .executables
            .iter()
            .any(|executable| *executable == normalized)
    })
}

fn profile_value(profile: &Profile) -> Value {
    // The first executable names the commands' usage, as the seeded row does.
    let executable = profile.executables.first().copied().unwrap_or(profile.id);
    let commands: Vec<Value> = profile
        .commands
        .iter()
        .map(|(command_id, state, description)| {
            let (parent, name) = match command_id.rsplit_once('.') {
                Some((parent, name)) => (Some(parent), name),
                None => (None, *command_id),
            };
            json!({
                "command_id": command_id,
                "name": name,
                "usage": format!("{executable} {}", command_id.replace('.', " ")),
                "description": description,
                "parent_id": parent,
                "suggested_state": state,
            })
        })
        .collect();
    json!({
        "profile_id": profile.id,
        "display_name": profile.display_name,
        "brand": profile.brand,
        "homepage": profile.homepage,
        "executables": profile.executables,
        "commands": commands,
    })
}

#[cfg(test)]
#[path = "cli_profiles_tests.rs"]
mod tests;
