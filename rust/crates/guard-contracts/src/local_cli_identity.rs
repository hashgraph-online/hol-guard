//! Local CLI identity contract.
//!
//! A local CLI grant is matched by the identity hash and CLI id derived from a
//! verified launch identity. The derivation is authority-bearing, so Python
//! sends the verified material and receives the identity back instead of
//! hashing it itself.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Verified material for one unlisted CLI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum LocalCliIdentitySourceV1 {
    /// A script entrypoint from the native launch identity.
    Script { entrypoint: Value },
    /// A verified executable from the native launch identity.
    Executable { executable: Value, name: String },
    /// A package runner target resolved to a local `node_modules/.bin` file.
    RunnerLocalBin {
        name: String,
        package_name: String,
        local_bin: Value,
    },
    /// A package runner target fetched from a registry.
    RegistryPackage { name: String, package_name: String },
    /// A `package.json` script manifest.
    PackageJson {
        manifest_path: String,
        content_sha256: String,
        package_name: String,
    },
}

/// Derived identity. Grants bind to `cli_id` and `identity_hash`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalCliIdentityV1 {
    pub cli_id: String,
    pub name: String,
    /// `script` or `executable`.
    pub kind: String,
    pub identity_hash: String,
}

/// One unlisted CLI a command launches, with the verified material its grant
/// binds. `identity_source` is what grant decisions re-derive the identity from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct UnlistedCliV1 {
    pub cli_id: String,
    pub name: String,
    /// `script` or `executable`.
    pub kind: String,
    pub identity_hash: String,
    pub example_label: String,
    pub interpreter_name: Option<String>,
    pub source_path: Option<String>,
    /// Stored observation class; only set for package-runner identities.
    pub path_class: Option<String>,
    /// Package runner (`npx`) that launched the CLI, if any.
    pub runner: Option<String>,
    pub identity_source: LocalCliIdentitySourceV1,
}

/// One `package.json` script as a local CLI subcommand, before Python merges
/// the catalog with its root and "other" entries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PackageScriptCommandV1 {
    pub command_id: String,
    pub name: String,
    pub usage: String,
    pub description: String,
    pub parent_id: Option<String>,
}

/// A recognized `npm`/`pnpm`/`yarn`/`bun` script run, or a pasted path to a
/// `package.json` project.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PackageJsonScriptsV1 {
    /// The manifest as found, before symlinks are resolved.
    pub manifest_path: String,
    pub runner: String,
    pub focused_script: Option<String>,
    /// Whether `focused_script` names one of the listed scripts.
    pub focused_listed: bool,
    /// Always the `package_json` variant.
    pub source: LocalCliIdentitySourceV1,
    pub identity: Option<LocalCliIdentityV1>,
    /// Listed scripts, focused script first. Empty when the manifest lists none.
    pub commands: Vec<PackageScriptCommandV1>,
    /// Colon-nested tokens of the focused script; empty when there is none.
    pub command_tokens: Vec<String>,
}

/// One observed CLI to rank for a custom-extension suggestion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SuggestionToolV1 {
    pub name: String,
    /// `script` or `executable`; only `script` changes the score.
    pub kind: String,
    /// A raw path or an already-stored path class token.
    pub source_path: Option<String>,
    pub observed_count: i64,
    pub help_status: Option<String>,
    pub surface: String,
}

/// How one observed CLI ranks, and whether its name is a common utility.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SuggestionVerdictV1 {
    /// Zero hides the suggestion.
    pub score: i64,
    pub suggestable: bool,
    /// Path class token safe to store without the raw path.
    pub path_class: String,
    pub common_utility: bool,
    /// Operator copy for refusing a common utility.
    pub reject_message: String,
}
