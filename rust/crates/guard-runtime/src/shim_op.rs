//! `ShimAdmin` resident op: the native package-shim administration surface.
//!
//! Every subop runs `guard_command::shims` against the explicit process facts
//! in the request. A failure is a typed `error` result; the caller never
//! recomputes a shim result itself.

use guard_command::shims::{self, ProbeOptions, ShimContext, ShimFacts};
use guard_contracts::{
    ShimAdminFactsV2, ShimAdminRequestV2, ShimAdminResultV2, SHIM_ADMIN_MAX_BYTES,
    SHIM_ADMIN_REQUEST_SCHEMA, SHIM_ADMIN_RESULT_SCHEMA,
};
use serde_json::{json, Map, Value};

use crate::package_authority_op::request_digest_with_limit;

const SCHEMA_MISMATCH: &str = "native_shim_admin_schema_mismatch";
const UNKNOWN_SUBOP: &str = "native_shim_admin_unknown_subop";
const UNSUPPORTED_PLATFORM: &str = "native_shim_admin_unsupported_platform";
const INVALID_REQUEST: &str = "native_shim_admin_invalid_request";
const SUBOP_FAILED: &str = "native_shim_admin_failed";
const RESPONSE_TOO_LARGE: &str = "native_shim_admin_response_too_large";
/// Ceiling on a caller-supplied per-shim probe timeout.
const MAX_PROBE_TIMEOUT_SECONDS: u64 = 600;

struct Failure {
    code: &'static str,
    detail: Option<String>,
}

fn facts_from(request: &ShimAdminFactsV2) -> ShimFacts {
    ShimFacts {
        environ: request.environ.clone(),
        home: request.home.clone(),
        cwd: request.cwd.clone(),
        executable: request.executable.clone(),
        frozen: request.frozen,
        frozen_cli: request.frozen_cli.clone(),
        trusted_frozen_cli_paths: request.trusted_frozen_cli_paths.clone(),
        python_version: (request.python_version[0], request.python_version[1]),
        import_root: request.import_root.clone(),
        argv0: request.argv0.clone(),
        windows: request.windows,
        sqlite_connect_timeout_seconds: request.sqlite_connect_timeout_seconds,
        now: request.now.clone(),
        shim_dir_transient: request.shim_dir_transient,
    }
}

fn context_from(request: &ShimAdminRequestV2) -> ShimContext {
    ShimContext::new(
        &request.guard_home,
        request.home_dir.as_deref(),
        request.workspace_dir.as_deref(),
        facts_from(&request.facts),
    )
}

fn subop_failed(detail: String) -> Failure {
    Failure {
        code: SUBOP_FAILED,
        detail: Some(detail),
    }
}

fn object(map: Map<String, Value>) -> Value {
    Value::Object(map)
}

fn dispatch(request: &ShimAdminRequestV2) -> Result<Value, Failure> {
    let context = context_from(request);
    let managers = request.managers.as_deref();
    let path_env = request.path_env.as_deref();
    let value = match request.subop.as_str() {
        "status" => shims::package_shim_status(&context, path_env).map(object),
        "dashboard_status" => shims::package_shim_dashboard_status(&context).map(object),
        "cloud_coverage" => {
            shims::package_shim_cloud_coverage(&context, request.generated_at.as_deref())
        }
        "path_order" => {
            let manager = request.manager.as_deref().ok_or(Failure {
                code: INVALID_REQUEST,
                detail: Some("path_order requires manager".to_owned()),
            })?;
            shims::get_path_order_status(&context, manager, path_env).map(object)
        }
        "install" => shims::install_package_shims(&context, managers, path_env).map(object),
        "activate" => {
            shims::activate_package_shims(&context, managers, request.repair.unwrap_or(false))
                .map(object)
        }
        "repair" => shims::repair_package_shims(&context, managers, path_env).map(object),
        "uninstall" => shims::uninstall_package_shims(&context, managers).map(object),
        "probe_intercepts" => {
            let default_timeout = request.facts.sqlite_connect_timeout_seconds;
            let fallback = if default_timeout.is_finite() && default_timeout >= 0.0 {
                (default_timeout as u64).saturating_add(5)
            } else {
                35
            };
            shims::probe_package_shim_intercepts(
                &context,
                &ProbeOptions {
                    managers: request.managers.clone(),
                    workspace_dir: request.workspace_dir.clone(),
                    allow_inactive_path: request.allow_inactive_path.unwrap_or(false),
                    project_shell_profile: request.project_shell_profile.unwrap_or(false),
                    timeout_seconds: request
                        .timeout_seconds
                        .unwrap_or(fallback)
                        .min(MAX_PROBE_TIMEOUT_SECONDS),
                },
            )
            .map(object)
        }
        "record_audit" => {
            shims::record_package_shim_audit_result(&context, request.generated_at.as_deref())
        }
        "digest_binding_sink" => {
            let manager = request.manager.as_deref().ok_or(Failure {
                code: INVALID_REQUEST,
                detail: Some("digest_binding_sink requires manager".to_owned()),
            })?;
            let executable = request.executable.as_deref().ok_or(Failure {
                code: INVALID_REQUEST,
                detail: Some("digest_binding_sink requires executable".to_owned()),
            })?;
            shims::package_shim_digest_binding_sink(
                &context,
                manager,
                executable,
                request.command.as_deref(),
                path_env,
            )
            .map(|bound| json!({"bound": bound}))
        }
        "supported_managers" => Ok(json!(shims::package_shim_supported_managers())),
        "ensure_package_shim_profile" => shims::ensure_package_shim_path_in_shell_profile(&context),
        "remove_guard_profile_blocks" => shims::remove_guard_profile_blocks(&context),
        _ => {
            return Err(Failure {
                code: UNKNOWN_SUBOP,
                detail: Some(request.subop.clone()),
            })
        }
    };
    value.map_err(subop_failed)
}

fn evaluate(request: &ShimAdminRequestV2) -> Result<Value, Failure> {
    if request.schema != SHIM_ADMIN_REQUEST_SCHEMA {
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
    // The path model follows `facts.windows` (`os.name == "nt"`), but the
    // filesystem operations are the host's: a request whose flavour differs from
    // the host's would resolve one platform's spelling on the other's filesystem.
    if request.facts.windows != cfg!(windows) {
        return Err(Failure {
            code: UNSUPPORTED_PLATFORM,
            detail: Some("path flavour does not match the host platform".to_owned()),
        });
    }
    if matches!(request.subop.as_str(), "install" | "activate" | "repair")
        && request.facts.frozen
        && (request.facts.frozen_cli.is_empty()
            || !request
                .facts
                .trusted_frozen_cli_paths
                .contains(&request.facts.frozen_cli))
    {
        return Err(Failure {
            code: INVALID_REQUEST,
            detail: Some("frozen_cli must be one of trusted_frozen_cli_paths".to_owned()),
        });
    }
    dispatch(request)
}

fn result_for(
    request: &ShimAdminRequestV2,
    request_sha256: &str,
    outcome: Result<Value, Failure>,
) -> ShimAdminResultV2 {
    let (status, code, detail, result) = match outcome {
        Ok(value) => ("ok", "ok", None, Some(value)),
        Err(failure) => ("error", failure.code, failure.detail, None),
    };
    ShimAdminResultV2 {
        schema: SHIM_ADMIN_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256: request_sha256.to_owned(),
        status: status.to_owned(),
        code: code.to_owned(),
        detail,
        result,
    }
}

pub(crate) fn evaluate_shim_admin(request: &ShimAdminRequestV2) -> Result<Vec<u8>, String> {
    // Bound the complete canonical request before any work; an oversized
    // request has no digest to bind.
    let request_sha256 = request_digest_with_limit(request, SHIM_ADMIN_MAX_BYTES)
        .map_err(|_| "native_shim_admin_too_large".to_owned())?;
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

    use super::*;

    fn request(subop: &str) -> ShimAdminRequestV2 {
        ShimAdminRequestV2 {
            schema: SHIM_ADMIN_REQUEST_SCHEMA.to_owned(),
            request_id: "r1".to_owned(),
            subop: subop.to_owned(),
            guard_home: "/nonexistent-guard-home".to_owned(),
            home_dir: None,
            workspace_dir: None,
            managers: None,
            path_env: None,
            manager: None,
            executable: None,
            command: None,
            repair: None,
            allow_inactive_path: None,
            project_shell_profile: None,
            timeout_seconds: None,
            generated_at: None,
            facts: ShimAdminFactsV2 {
                environ: BTreeMap::new(),
                home: "/nonexistent-home".to_owned(),
                cwd: "/".to_owned(),
                executable: "/usr/bin/python3".to_owned(),
                frozen: false,
                frozen_cli: String::new(),
                trusted_frozen_cli_paths: Vec::new(),
                python_version: [3, 12],
                import_root: "/opt/guard/src".to_owned(),
                argv0: None,
                windows: cfg!(windows),
                sqlite_connect_timeout_seconds: 30.0,
                now: "2026-01-01T00:00:00+00:00".to_owned(),
                shim_dir_transient: None,
            },
        }
    }

    fn decode(request: &ShimAdminRequestV2) -> ShimAdminResultV2 {
        let bytes = evaluate_shim_admin(request).expect("encoded");
        serde_json::from_slice(&bytes).expect("result")
    }

    #[test]
    fn the_digest_binding_sink_refuses_a_request_that_names_no_shim() {
        let mut without_manager = request("digest_binding_sink");
        without_manager.executable = Some("/shims/uv".to_owned());
        without_manager.command = Some("/shims/uv run tool".to_owned());
        assert_eq!(decode(&without_manager).code, INVALID_REQUEST);

        let mut without_executable = request("digest_binding_sink");
        without_executable.manager = Some("uv".to_owned());
        without_executable.command = Some("/shims/uv run tool".to_owned());
        assert_eq!(decode(&without_executable).code, INVALID_REQUEST);
    }

    /// A complete request answers; an uninstalled shim owns no approval.
    #[test]
    fn the_digest_binding_sink_answers_no_when_no_shim_is_installed() {
        let mut asked = request("digest_binding_sink");
        asked.manager = Some("uv".to_owned());
        asked.executable = Some("/shims/uv".to_owned());
        asked.command = Some("/shims/uv run tool".to_owned());
        asked.path_env = Some(String::new());
        let result = decode(&asked);
        assert_eq!(result.status, "ok", "{:?}", result.detail);
        assert_eq!(result.result, Some(serde_json::json!({"bound": false})));
    }

    #[test]
    fn a_path_flavour_that_differs_from_the_host_fails_closed() {
        let mut mismatched = request("status");
        mismatched.facts.windows = !cfg!(windows);
        assert_eq!(decode(&mismatched).code, UNSUPPORTED_PLATFORM);
    }

    /// Shim install and status through the resident op with Windows paths: the
    /// regression this guards is a Windows request being refused or mis-resolved.
    #[cfg(windows)]
    #[test]
    fn windows_install_and_status_run_through_the_op() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let base = std::env::temp_dir().join(format!("hol-shim-op-{}-{nanos}", std::process::id()));
        let guard_home = base.join("guard");
        let home = base.join("home");
        std::fs::create_dir_all(&home).expect("home");
        let mut install = request("install");
        install.guard_home = guard_home.to_string_lossy().into_owned();
        install.home_dir = Some(home.to_string_lossy().into_owned());
        install.managers = Some(vec!["npm".to_owned()]);
        install.facts.home = home.to_string_lossy().into_owned();
        install.facts.cwd = base.to_string_lossy().into_owned();
        install.facts.executable = base
            .join("py")
            .join("python.exe")
            .to_string_lossy()
            .into_owned();
        install.facts.environ = BTreeMap::from([
            ("USERPROFILE".to_owned(), install.facts.home.clone()),
            ("PATH".to_owned(), String::new()),
            ("PATHEXT".to_owned(), ".COM;.EXE;.BAT;.CMD".to_owned()),
        ]);
        let installed = decode(&install);
        assert_eq!(installed.status, "ok", "{:?}", installed.detail);
        let shim_dir = guard_home.join("package-shims").join("bin");
        assert!(shim_dir.join("npm").is_file(), "posix launcher missing");
        let launcher = std::fs::read_to_string(shim_dir.join("npm.cmd")).expect("cmd launcher");
        assert!(launcher.starts_with("@echo off"), "{launcher}");
        assert!(launcher.contains("python.exe"), "{launcher}");
        let mut status = install.clone();
        status.subop = "status".to_owned();
        status.managers = None;
        let reported = decode(&status);
        assert_eq!(reported.status, "ok", "{:?}", reported.detail);
        let text = serde_json::to_string(&reported.result).expect("status json");
        assert!(text.contains("npm"), "{text}");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn frozen_install_requires_a_trusted_interpreter() {
        for (cli, trusted) in [
            ("", vec![]),
            ("/evil/guard", vec!["/opt/guard"]),
            ("/opt/guard", vec![]),
        ] {
            let mut frozen = request("install");
            frozen.facts.frozen = true;
            frozen.facts.frozen_cli = cli.to_owned();
            frozen.facts.trusted_frozen_cli_paths =
                trusted.into_iter().map(str::to_owned).collect();
            assert_eq!(decode(&frozen).code, INVALID_REQUEST);
        }
    }

    #[test]
    fn unknown_subop_is_a_typed_error() {
        let result = decode(&request("explode"));
        assert_eq!(result.status, "error");
        assert_eq!(result.code, UNKNOWN_SUBOP);
        assert!(result.result.is_none());
    }

    #[test]
    fn schema_mismatch_fails_closed() {
        let mut bad = request("status");
        bad.schema = "guard-shim-admin-request.v1".to_owned();
        assert_eq!(decode(&bad).code, SCHEMA_MISMATCH);
    }

    #[test]
    fn path_order_needs_a_manager() {
        assert_eq!(decode(&request("path_order")).code, INVALID_REQUEST);
    }

    #[test]
    fn empty_guard_home_is_refused() {
        let mut bad = request("status");
        bad.guard_home.clear();
        assert_eq!(decode(&bad).code, INVALID_REQUEST);
    }

    #[test]
    fn supported_managers_lists_twenty() {
        let result = decode(&request("supported_managers"));
        assert_eq!(result.status, "ok");
        assert_eq!(
            result
                .result
                .and_then(|value| value.as_array().map(Vec::len)),
            Some(20)
        );
    }

    #[test]
    fn oversized_request_is_refused_before_work() {
        let mut big = request("status");
        big.facts
            .environ
            .insert("X".to_owned(), "y".repeat(SHIM_ADMIN_MAX_BYTES));
        assert!(evaluate_shim_admin(&big).is_err());
    }

    #[test]
    fn status_of_empty_home_reports_no_managers() {
        let result = decode(&request("status"));
        assert_eq!(result.status, "ok");
        let body = result.result.expect("body");
        assert_eq!(body["installed_managers"], json!([]));
        assert_eq!(body["manifest_state"], json!("absent"));
    }
}
