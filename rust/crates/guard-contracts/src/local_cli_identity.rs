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
