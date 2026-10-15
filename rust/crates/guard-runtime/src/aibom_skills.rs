//! Skill artifacts for AIBOM inventory. The native walk composes discovery and
//! directory identity in-process; a caller that cannot use it (no native skill
//! walk on this platform, or a root that cannot be carried as UTF-8) supplies
//! the finished artifacts instead.

use std::path::Path;

use guard_contracts::{SkillDirectoryIdentityV1, SkillDirectoryLimitsV1};
use serde_json::{json, Map, Value};

pub(crate) const ERR_IDENTITY: &str = "native_runner_authority_aibom_skill_identity_invalid";

/// Finished skill artifacts for one scope, or `None` to walk natively.
pub(crate) type SkillSource = Option<Vec<Value>>;

pub(crate) const WORKSPACE_SKILL_ROOTS: [&str; 1] = [".agents/skills"];
pub(crate) const HOME_SKILL_ROOTS: [&str; 2] = [".codex/skills", ".agents/skills"];

/// Project skills below a workspace.
pub(crate) fn project_skill_artifacts(
    harness: &str,
    workspace: &Path,
    source: &SkillSource,
) -> Result<Vec<Value>, &'static str> {
    scope_skill_artifacts(
        harness,
        workspace,
        &WORKSPACE_SKILL_ROOTS,
        "project",
        source,
    )
}

/// Skills below `scope_dir` for the given grouping roots.
pub(crate) fn scope_skill_artifacts(
    harness: &str,
    scope_dir: &Path,
    roots: &[&str],
    scope: &str,
    source: &SkillSource,
) -> Result<Vec<Value>, &'static str> {
    if let Some(finished) = source {
        return Ok(finished.clone());
    }
    native::skills(harness, scope_dir, roots, scope)
}

/// A skill directory identity and the facts a caller reports about it.
pub(crate) struct DirectoryIdentity {
    pub(crate) metadata: serde_json::Map<String, Value>,
    pub(crate) complete: bool,
    pub(crate) failure_reason: Option<String>,
}

/// `inspect_skill_directory` plus `skill_directory_identity_metadata`, walked
/// natively. Platforms without a native walk refuse; the caller supplies the
/// finished identity instead.
pub(crate) fn directory_identity(
    skill_md: &Path,
    scope_root: &Path,
    version_label: &str,
) -> Result<DirectoryIdentity, &'static str> {
    native::directory_identity(skill_md, scope_root, version_label)
}

pub(crate) const LIMITS: SkillDirectoryLimitsV1 = SkillDirectoryLimitsV1 {
    max_depth: 32,
    max_entries: 4_096,
    max_file_bytes: 128 * 1024 * 1024,
    max_total_bytes: 256 * 1024 * 1024,
};

/// `skill_directory_identity_metadata`.
pub(crate) fn identity_metadata(
    identity: &SkillDirectoryIdentityV1,
    version_label: &str,
) -> Result<Map<String, Value>, &'static str> {
    let complete = identity.status == "complete";
    let mut envelope = Map::new();
    envelope.insert("schemaVersion".to_owned(), json!(identity.schema_version));
    envelope.insert("status".to_owned(), json!(identity.status));
    envelope.insert("entryCount".to_owned(), json!(identity.entry_count));
    envelope.insert("totalBytes".to_owned(), json!(identity.total_bytes));
    envelope.insert("reusable".to_owned(), json!(complete));
    let mut metadata = Map::new();
    if let Some(primary) = &identity.primary_content_hash {
        metadata.insert("content_hash".to_owned(), json!(primary));
    }
    let version_hash = match (&identity.directory_hash, complete) {
        (Some(directory), true) => {
            envelope.insert("contentHash".to_owned(), json!(directory));
            metadata.insert("directory_hash".to_owned(), json!(directory));
            directory.clone()
        }
        _ => {
            let state = identity.incomplete_state_hash.clone().ok_or(ERR_IDENTITY)?;
            if let Some(reason) = identity.failure_reason {
                envelope.insert(
                    "reason".to_owned(),
                    serde_json::to_value(reason).map_err(|_| ERR_IDENTITY)?,
                );
            }
            envelope.insert("incompleteStateHash".to_owned(), json!(state));
            state
        }
    };
    metadata.insert("skillDirectoryIdentity".to_owned(), Value::Object(envelope));
    metadata.insert(
        "versionInfo".to_owned(),
        json!({
            "versionLabel": version_label,
            "hashBasis": "skill-directory-v1",
            "contentHash": version_hash,
            "changedFields": [],
        }),
    );
    Ok(metadata)
}

#[cfg(unix)]
mod native {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    use guard_contracts::SkillDirectoryIdentityV1;
    use serde_json::{json, Map, Value};

    use super::{identity_metadata, ERR_IDENTITY, LIMITS};
    use crate::aibom_artifact::guard_artifact;
    use crate::aibom_paths::py_join;
    use crate::skill_identity_canon::Failure;
    use crate::skill_identity_discovery::{discover_skill_documents, issue_id};
    use crate::skill_identity_inspect::{incomplete_identity, inspect_skill_directory};

    /// The identity of one skill directory: its metadata and completeness.
    pub(super) fn directory_identity(
        skill_md: &Path,
        scope_root: &Path,
        version_label: &str,
    ) -> Result<super::DirectoryIdentity, &'static str> {
        let identity = inspect_skill_directory(skill_md, scope_root, &LIMITS);
        let failure_reason = match identity.failure_reason {
            Some(reason) => serde_json::to_value(reason)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned)),
            None => None,
        };
        Ok(super::DirectoryIdentity {
            metadata: identity_metadata(&identity, version_label)?,
            complete: identity.status == "complete",
            failure_reason,
        })
    }

    fn skill_metadata(
        relative_root: &str,
        identity: &SkillDirectoryIdentityV1,
        label: &str,
    ) -> Result<Map<String, Value>, &'static str> {
        let mut metadata = Map::new();
        metadata.insert("enabled".to_owned(), json!(true));
        metadata.insert("skill_root".to_owned(), json!(relative_root));
        metadata.extend(identity_metadata(identity, label)?);
        Ok(metadata)
    }

    fn issue_artifact(
        harness: &str,
        scope: &str,
        relative_root: &str,
        issue: &str,
        config_path: &Path,
        identity: &SkillDirectoryIdentityV1,
    ) -> Result<Value, &'static str> {
        let label = format!(".guard-discovery/{issue}");
        Ok(guard_artifact(
            format!("{harness}:{scope}:skill-discovery:{relative_root}:{issue}"),
            "Incomplete skill discovery".to_owned(),
            harness,
            "skill",
            scope,
            config_path,
            skill_metadata(relative_root, identity, &label)?,
        ))
    }

    pub(super) fn skills(
        harness: &str,
        scope_dir: &Path,
        roots: &[&str],
        scope: &str,
    ) -> Result<Vec<Value>, &'static str> {
        let mut artifacts = Vec::new();
        for relative_root in roots {
            let skill_root = py_join(scope_dir, relative_root);
            let discovery = discover_skill_documents(&skill_root, &LIMITS);
            for encoded in &discovery.documents_hex {
                let relative = hex::decode(encoded).map_err(|_| ERR_IDENTITY)?;
                let skill_md = skill_root.join(OsStr::from_bytes(&relative));
                let Ok(text) = std::str::from_utf8(&relative) else {
                    let reason = Failure::InvalidPathEncoding;
                    artifacts.push(issue_artifact(
                        harness,
                        scope,
                        relative_root,
                        &issue_id(&relative, reason),
                        &skill_md,
                        &incomplete_identity(reason, None, 0, 0),
                    )?);
                    continue;
                };
                let relative_id = text.rsplit_once('/').map_or(".", |(parent, _)| parent);
                let identity = inspect_skill_directory(&skill_md, scope_dir, &LIMITS);
                artifacts.push(guard_artifact(
                    format!("{harness}:{scope}:skill:{relative_root}:{relative_id}"),
                    relative_id.to_owned(),
                    harness,
                    "skill",
                    scope,
                    &skill_md,
                    skill_metadata(relative_root, &identity, relative_id)?,
                ));
            }
            for issue in &discovery.issues {
                let relative = hex::decode(&issue.relative_path_hex).map_err(|_| ERR_IDENTITY)?;
                let path = if relative == b"." {
                    skill_root.clone()
                } else {
                    skill_root.join(OsStr::from_bytes(&relative))
                };
                artifacts.push(issue_artifact(
                    harness,
                    scope,
                    relative_root,
                    &issue.issue_id,
                    &path,
                    &issue.identity,
                )?);
            }
        }
        Ok(artifacts)
    }
}

#[cfg(not(unix))]
mod native {
    use std::path::Path;

    use serde_json::Value;

    pub(super) fn directory_identity(
        _skill_md: &Path,
        _scope_root: &Path,
        _version_label: &str,
    ) -> Result<super::DirectoryIdentity, &'static str> {
        Err("native_runner_authority_aibom_skills_unsupported")
    }

    pub(super) fn skills(
        _harness: &str,
        _scope_dir: &Path,
        _roots: &[&str],
        _scope: &str,
    ) -> Result<Vec<Value>, &'static str> {
        Err("native_runner_authority_aibom_skills_unsupported")
    }
}
