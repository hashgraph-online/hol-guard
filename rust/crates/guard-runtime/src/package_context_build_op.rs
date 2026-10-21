//! `PackageContextBuild` resident op: the native package execution context
//! build.
//!
//! The resident reads the repository, executable, dependency and configuration
//! inputs named by the request and returns the component digests. A failure is a
//! typed `error` result; the caller never computes a context itself.

use guard_contracts::{
    PackageContextBuildContextV1, PackageContextBuildRequestV1, PackageContextBuildResultV1,
    PACKAGE_CONTEXT_BUILD_MAX_BYTES, PACKAGE_CONTEXT_BUILD_REQUEST_SCHEMA,
    PACKAGE_CONTEXT_BUILD_RESULT_SCHEMA,
};

use crate::package_authority_op::request_digest_with_limit;

const SCHEMA_MISMATCH: &str = "native_package_context_build_schema_mismatch";
const INVALID_REQUEST: &str = "native_package_context_build_invalid_request";
#[cfg(not(unix))]
const UNSUPPORTED_PLATFORM: &str = "native_package_context_build_unsupported_platform";
#[cfg(unix)]
const BUILD_FAILED: &str = "native_package_context_build_failed";
const RESPONSE_TOO_LARGE: &str = "native_package_context_build_response_too_large";

struct Failure {
    code: &'static str,
    detail: Option<String>,
}

#[cfg(unix)]
fn metadata_from(
    request: &PackageContextBuildRequestV1,
) -> serde_json::Map<String, serde_json::Value> {
    use serde_json::{json, Value};

    let metadata = &request.metadata;
    let mut map = serde_json::Map::new();
    if let Some(value) = &metadata.package_manager {
        map.insert("package_manager".to_owned(), Value::String(value.clone()));
    }
    if let Some(value) = &metadata.package_executable {
        map.insert(
            "package_executable".to_owned(),
            Value::String(value.clone()),
        );
    }
    map.insert("flags".to_owned(), json!(metadata.flags));
    map.insert("manifest_paths".to_owned(), json!(metadata.manifest_paths));
    map.insert("lockfile_paths".to_owned(), json!(metadata.lockfile_paths));
    map
}

#[cfg(unix)]
fn build(request: &PackageContextBuildRequestV1) -> Result<PackageContextBuildContextV1, Failure> {
    use guard_command::package_context_build::{
        build_package_execution_context, BuildError, BuildInput,
    };
    use guard_contracts::PackageContextBuildComponentV1;

    let metadata = metadata_from(request);
    let input = BuildInput {
        workspace_dir: &request.workspace_dir,
        metadata: &metadata,
        executable: request.executable.as_deref(),
        executable_args: &request.executable_args,
        environment: &request.environment,
        process_cwd: &request.process_cwd,
        process_home: &request.process_home,
        process_home_env: request.process_home_env.as_deref(),
        process_path: request.process_path.as_deref(),
    };
    match build_package_execution_context(&input) {
        Ok(built) => Ok(PackageContextBuildContextV1 {
            digest: built.digest,
            portable: built.portable,
            components: built
                .components
                .into_iter()
                .map(|component| PackageContextBuildComponentV1 {
                    name: component.name,
                    digest: component.digest,
                })
                .collect(),
            non_portable_reason: built.non_portable_reason,
        }),
        Err(BuildError::Fatal(reason)) => Err(Failure {
            code: BUILD_FAILED,
            detail: Some(reason),
        }),
        Err(BuildError::Unavailable(reason)) => Err(Failure {
            code: BUILD_FAILED,
            detail: Some(reason.to_owned()),
        }),
    }
}

#[cfg(not(unix))]
fn build(_request: &PackageContextBuildRequestV1) -> Result<PackageContextBuildContextV1, Failure> {
    // The native path model is POSIX; a Windows host fails closed.
    Err(Failure {
        code: UNSUPPORTED_PLATFORM,
        detail: Some("windows path semantics are not implemented".to_owned()),
    })
}

fn evaluate(
    request: &PackageContextBuildRequestV1,
) -> Result<PackageContextBuildContextV1, Failure> {
    if request.schema != PACKAGE_CONTEXT_BUILD_REQUEST_SCHEMA {
        return Err(Failure {
            code: SCHEMA_MISMATCH,
            detail: Some(request.schema.clone()),
        });
    }
    if request.guard_home.is_empty() {
        return Err(Failure {
            code: INVALID_REQUEST,
            detail: Some("guard_home must not be empty".to_owned()),
        });
    }
    build(request)
}

fn result_for(
    request: &PackageContextBuildRequestV1,
    request_sha256: &str,
    outcome: Result<PackageContextBuildContextV1, Failure>,
) -> PackageContextBuildResultV1 {
    let (status, code, detail, context) = match outcome {
        Ok(context) => ("ok", "ok", None, Some(context)),
        Err(failure) => ("error", failure.code, failure.detail, None),
    };
    PackageContextBuildResultV1 {
        schema: PACKAGE_CONTEXT_BUILD_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256: request_sha256.to_owned(),
        status: status.to_owned(),
        code: code.to_owned(),
        detail,
        context,
    }
}

/// The same build in process, for the resident's own lanes. A failure is one
/// code rather than a typed result: the caller is not a request to answer, so
/// it defers on anything this cannot build, the unsupported Windows path
/// semantics included.
pub(crate) fn build_execution_context(
    request: &PackageContextBuildRequestV1,
) -> Result<PackageContextBuildContextV1, &'static str> {
    evaluate(request).map_err(|failure| failure.code)
}

pub(crate) fn evaluate_package_context_build(
    request: &PackageContextBuildRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, PACKAGE_CONTEXT_BUILD_MAX_BYTES)
        .map_err(|_| "native_package_context_build_too_large".to_owned())?;
    let result = result_for(request, &request_sha256, evaluate(request));
    match crate::encode_response(&result) {
        Ok(bytes) => Ok(bytes),
        Err(reason) if reason == "native_response_too_large" && result.status == "ok" => {
            crate::encode_response(&result_for(
                request,
                &request_sha256,
                Err(Failure {
                    code: RESPONSE_TOO_LARGE,
                    detail: None,
                }),
            ))
        }
        Err(reason) => Err(reason),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use guard_contracts::PackageContextBuildMetadataV1;

    use super::*;

    fn request(workspace: &str) -> PackageContextBuildRequestV1 {
        PackageContextBuildRequestV1 {
            schema: PACKAGE_CONTEXT_BUILD_REQUEST_SCHEMA.to_owned(),
            request_id: "req-1".to_owned(),
            guard_home: "/tmp/guard-home".to_owned(),
            workspace_dir: workspace.to_owned(),
            metadata: PackageContextBuildMetadataV1 {
                package_manager: Some("npm".to_owned()),
                ..PackageContextBuildMetadataV1::default()
            },
            executable: None,
            executable_args: Vec::new(),
            environment: BTreeMap::new(),
            process_cwd: workspace.to_owned(),
            process_home: "/tmp".to_owned(),
            process_home_env: None,
            process_path: Some("/usr/bin:/bin".to_owned()),
        }
    }

    fn decode(request: &PackageContextBuildRequestV1) -> PackageContextBuildResultV1 {
        let bytes = evaluate_package_context_build(request).expect("encoded");
        serde_json::from_slice(&bytes).expect("result")
    }

    #[test]
    fn schema_mismatch_is_a_typed_error() {
        let mut bad = request("/tmp");
        bad.schema = "guard-package-context-build-request.v0".to_owned();
        let result = decode(&bad);
        assert_eq!(result.status, "error");
        assert_eq!(result.code, SCHEMA_MISMATCH);
        assert!(result.context.is_none());
    }

    #[test]
    fn empty_guard_home_is_invalid() {
        let mut bad = request("/tmp");
        bad.guard_home.clear();
        assert_eq!(decode(&bad).code, INVALID_REQUEST);
    }

    #[test]
    fn oversized_request_is_refused() {
        let mut big = request("/tmp");
        big.environment.insert(
            "BIG".to_owned(),
            "x".repeat(PACKAGE_CONTEXT_BUILD_MAX_BYTES + 1),
        );
        assert!(evaluate_package_context_build(&big).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn happy_path_returns_ordered_components_bound_to_the_request() {
        let dir = std::env::temp_dir().join(format!("pcb-op-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let workspace = dir.canonicalize().expect("canonical");
        let result = decode(&request(&workspace.to_string_lossy()));
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(result.status, "ok", "{:?}", result.detail);
        assert_eq!(result.request_id, "req-1");
        assert!(result.request_sha256.starts_with("sha256:"));
        let context = result.context.expect("context");
        let names: Vec<&str> = context
            .components
            .iter()
            .map(|component| component.name.as_str())
            .collect();
        assert_eq!(names.first(), Some(&"repository_identity"));
        assert!(names.contains(&"environment_policy"));
        assert_eq!(context.digest.len(), 64);
    }
}
