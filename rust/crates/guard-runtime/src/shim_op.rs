//! `ShimAdmin` resident op — subop-multiplexed dispatcher over
//! `guard_command::shims` admin surface (`probe_intercepts`, `status`,
//! `activate`, `repair`, `supported_managers`).

use std::path::PathBuf;

use guard_command::shims::{self, HarnessContext};
use guard_contracts::{
    ShimAdminRequestV1, ShimAdminResultV1, SHIM_ADMIN_REQUEST_SCHEMA, SHIM_ADMIN_RESULT_SCHEMA,
};
use serde_json::{json, Value};

fn harness_context(request: &ShimAdminRequestV1) -> HarnessContext {
    HarnessContext {
        guard_home: PathBuf::from(&request.guard_home),
        home_dir: None,
        workspace_dir: request.workspace_dir.as_deref().map(PathBuf::from),
        home_override_explicit: false,
    }
}

fn manager_refs(managers: Option<&Vec<String>>) -> Option<Vec<&str>> {
    managers.map(|v| v.iter().map(String::as_str).collect())
}

pub(crate) fn evaluate_shim_admin(request: &ShimAdminRequestV1) -> Result<Vec<u8>, String> {
    if request.schema != SHIM_ADMIN_REQUEST_SCHEMA {
        return Err(format!("schema_mismatch:{}", request.schema));
    }
    let context = harness_context(request);
    let payload = match request.subop.as_str() {
        "probe_intercepts" => {
            let managers = manager_refs(request.managers.as_ref());
            let workspace_dir = request.workspace_dir.as_deref().map(std::path::Path::new);
            Value::Object(shims::probe_package_shim_intercepts(
                &context,
                managers.as_deref(),
                workspace_dir,
                request.allow_inactive_path.unwrap_or(false),
                request.timeout_seconds,
            ))
        }
        "status" => Value::Object(shims::package_shim_status(
            &context,
            request.path_env.as_deref(),
        )),
        "activate" => {
            let managers = manager_refs(request.install_managers.as_ref());
            Value::Object(shims::activate_package_shims(
                &context,
                managers.as_deref(),
                request.path_env.as_deref(),
            ))
        }
        "repair" => {
            let managers = manager_refs(request.install_managers.as_ref());
            Value::Object(shims::repair_package_shims(
                &context,
                managers.as_deref(),
                request.path_env.as_deref(),
            ))
        }
        "supported_managers" => {
            let managers = shims::package_shim_supported_managers();
            json!(managers)
        }
        other => return Err(format!("unknown_shim_subop:{other}")),
    };
    crate::encode_response(&ShimAdminResultV1 {
        schema: SHIM_ADMIN_RESULT_SCHEMA.to_owned(),
        result: Some(payload),
    })
}
