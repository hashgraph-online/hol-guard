//! `ProjectIdentity` — resident op answering the portable Git project
//! identity of a workspace from `project_identity`.
//!
//! The answer separates the two ways a workspace can have no identity.
//! `Absent` is a workspace that names no conventional clone, and the op
//! answers it as no identity. `Unknown` is a workspace this resolver does not
//! settle, and the op answers it as an error, because a caller that read it
//! as `Absent` would drop the portable half of a most-restrictive
//! composition and let local authority alone decide.
//!
//! A workspace named relative to the asking process is read under the `cwd`
//! that process reports, which is the directory Python's retired
//! `Path(workspace).resolve(strict=False)` resolved it against.

use crate::package_authority_op::request_digest_with_limit;
use crate::project_identity::{portable_workspace, resolve_relative, PortableIdentity};
use guard_contracts::{
    ProjectIdentityPayloadV1, ProjectIdentityQueryV1, ProjectIdentityRequestV1,
    ProjectIdentityResultV1, PROJECT_IDENTITY_MAX_BYTES, PROJECT_IDENTITY_REQUEST_SCHEMA,
    PROJECT_IDENTITY_RESULT_SCHEMA,
};

pub(crate) fn evaluate_project_identity_request(
    request: &ProjectIdentityRequestV1,
) -> Result<Vec<u8>, String> {
    // Bound the complete canonical request before any filesystem read; an
    // oversized request has no digest to bind.
    let request_sha256 = request_digest_with_limit(request, PROJECT_IDENTITY_MAX_BYTES)
        .map_err(|_| "native_project_identity_too_large".to_owned())?;
    let (status, code, payload) = if request.schema == PROJECT_IDENTITY_REQUEST_SCHEMA {
        let ProjectIdentityQueryV1::Resolve { workspace, cwd } = &request.query;
        let resolved = match cwd.as_deref() {
            Some(cwd) if !cwd.is_empty() => resolve_relative(workspace, cwd),
            _ => portable_workspace(workspace),
        };
        match resolved {
            PortableIdentity::Identity(identity) => (
                "ok",
                "ok",
                Some(ProjectIdentityPayloadV1::Resolve {
                    identity: Some(identity),
                }),
            ),
            PortableIdentity::Absent => (
                "ok",
                "ok",
                Some(ProjectIdentityPayloadV1::Resolve { identity: None }),
            ),
            PortableIdentity::Unknown => ("error", "native_project_identity_unresolved", None),
        }
    } else {
        ("error", "native_project_identity_schema_mismatch", None)
    };
    crate::encode_response(&ProjectIdentityResultV1 {
        schema: PROJECT_IDENTITY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::fs;
    #[cfg(unix)]
    use std::path::{Path, PathBuf};
    #[cfg(unix)]
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn run(schema: &str, workspace: &str, cwd: Option<&str>) -> ProjectIdentityResultV1 {
        let request = ProjectIdentityRequestV1 {
            schema: schema.to_owned(),
            request_id: "project-identity-1".to_owned(),
            query: ProjectIdentityQueryV1::Resolve {
                workspace: workspace.to_owned(),
                cwd: cwd.map(str::to_owned),
            },
        };
        serde_json::from_slice(&evaluate_project_identity_request(&request).unwrap()).unwrap()
    }

    fn identity(result: &ProjectIdentityResultV1) -> Option<String> {
        match &result.payload {
            Some(ProjectIdentityPayloadV1::Resolve { identity }) => identity.clone(),
            None => panic!("no payload: {result:?}"),
        }
    }

    #[cfg(unix)]
    fn scratch(label: &str) -> PathBuf {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "guard-project-identity-op-{}-{}-{label}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).expect("scratch dir");
        fs::canonicalize(&path).expect("canonical scratch dir")
    }

    /// The `.git` metadata of a conventional clone (`project_identity_tests`).
    #[cfg(unix)]
    fn repository(root: &Path) {
        let remote = "https://github.com/example/op.git";
        fs::create_dir_all(root.join(".git/logs")).expect("git dir");
        fs::write(
            root.join(".git/config"),
            format!("[remote \"origin\"]\n\turl = {remote}\n"),
        )
        .expect("config");
        fs::write(
            root.join(".git/logs/HEAD"),
            format!(
                "{} {} G <g@example.invalid> 1 +0000\tclone: from {remote}\n",
                "0".repeat(40),
                "1".repeat(40)
            ),
        )
        .expect("reflog");
    }

    #[test]
    fn a_portable_identity_answers_itself() {
        let value = format!("git-project:v1:{}", "a".repeat(64));
        let result = run(
            PROJECT_IDENTITY_REQUEST_SCHEMA,
            &format!("  {value} "),
            None,
        );
        assert_eq!((result.status.as_str(), result.code.as_str()), ("ok", "ok"));
        assert_eq!(result.request_id, "project-identity-1");
        assert!(result.request_sha256.starts_with("sha256:"));
        assert_eq!(identity(&result), Some(value));
    }

    #[test]
    fn a_blank_workspace_has_no_identity() {
        for workspace in ["", "   "] {
            let result = run(PROJECT_IDENTITY_REQUEST_SCHEMA, workspace, None);
            assert_eq!(result.status, "ok", "{workspace}");
            assert_eq!(identity(&result), None, "{workspace}");
        }
    }

    /// A workspace the resolver does not settle is an error, not an absent
    /// identity: the caller must not compose policy as if the workspace
    /// belonged to no project.
    #[test]
    fn an_unsettled_workspace_is_an_error() {
        for (workspace, cwd) in [
            ("relative/repository", None),
            ("~/repository", None),
            // A `~` name stays unsettled even with a reported directory,
            // because `expanduser` rewrites it against an environment the
            // runtime does not read.
            ("~/repository", Some("/")),
        ] {
            let result = run(PROJECT_IDENTITY_REQUEST_SCHEMA, workspace, cwd);
            assert_eq!(result.status, "error", "{workspace}");
            assert_eq!(
                result.code, "native_project_identity_unresolved",
                "{workspace}"
            );
            assert!(result.payload.is_none(), "{workspace}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_relative_workspace_is_read_under_the_reported_directory() {
        let root = scratch("relative");
        repository(&root);
        let cwd = root.to_str().expect("utf-8");

        // Without the asking process's directory the same workspace has no
        // directory to be read under, so it stays unsettled.
        let unsettled = run(PROJECT_IDENTITY_REQUEST_SCHEMA, "nested-workspace", None);
        assert_eq!(unsettled.status, "error");
        assert_eq!(unsettled.code, "native_project_identity_unresolved");

        let result = run(
            PROJECT_IDENTITY_REQUEST_SCHEMA,
            "nested-workspace",
            Some(cwd),
        );
        assert_eq!((result.status.as_str(), result.code.as_str()), ("ok", "ok"));
        let joined = identity(&result).expect("the checkout derives an identity");
        // It is the identity of that name under the checkout, not of the
        // checkout itself.
        let outer = run(PROJECT_IDENTITY_REQUEST_SCHEMA, cwd, Some(cwd));
        assert_ne!(Some(joined), identity(&outer));
    }

    #[test]
    fn a_foreign_schema_is_refused_without_a_payload() {
        let result = run("guard-project-identity-request.v0", "/", None);
        assert_eq!(result.status, "error");
        assert_eq!(result.code, "native_project_identity_schema_mismatch");
        assert!(result.payload.is_none());
    }
}
