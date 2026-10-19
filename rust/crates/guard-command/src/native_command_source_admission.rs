//! Destination admission reads one declarative contribution at a time. No IR
//! from inactive contributions is retained or installed by this operation.
use super::*;
use std::path::Path;

fn executable(value: &str) -> String {
    let value = value.replace('\\', "/");
    let value = value.rsplit('/').next().unwrap_or("").to_lowercase();
    let value = value.strip_suffix(".exe").unwrap_or(&value);
    value.strip_suffix(".cmd").unwrap_or(value).to_owned()
}

pub(super) fn with_catalog(request: &Value, catalog: &[Value]) -> Result<Value, &'static str> {
    let mut result = authoring_admission(
        &serde_json::to_vec(request).map_err(|_| "authoring_admission_request_invalid")?,
    )?;
    // Global interfaces provide coverage only. Trust/activation comes from
    // neither this inventory nor a contribution's destination checkout.
    if request["kind"] == "cli" {
        let wanted = executable(
            request["executable"]
                .as_str()
                .ok_or("authoring_admission_request_invalid")?,
        );
        for entry in catalog {
            if entry["extension_id"] == request["catalog_id"] {
                continue;
            }
            if entry["executables"].as_array().is_some_and(|names| {
                names
                    .iter()
                    .any(|name| name.as_str().is_some_and(|name| executable(name) == wanted))
            }) {
                return Err("authoring_installed_executable_collision");
            }
        }
    }
    result["kind"] = serde_json::json!("admission");
    Ok(result)
}

pub fn authoring_admission(bytes: &[u8]) -> Result<Value, &'static str> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Request {
        root: std::path::PathBuf,
        kind: String,
        contribution_id: String,
        catalog_id: String,
        executable: String,
        package: String,
    }
    let request: Request = serde_json::from_value(json::decode(bytes)?)
        .map_err(|_| "authoring_admission_request_invalid")?;
    if !request.root.is_absolute() || !matches!(request.kind.as_str(), "cli" | "mcp") {
        return Err("authoring_admission_request_invalid");
    }
    let family = if request.kind == "cli" {
        "extensions"
    } else {
        "mcp-servers"
    };
    let directory = request.root.join("contributions").join(family);
    if guard_secure_fs::contains_symlink_component(&directory) || !directory.is_dir() {
        return Err("authoring_contribution_directory_missing");
    }
    let mut count = 0usize;
    let mut bytes = 0usize;
    let wanted = executable(&request.executable);
    for entry in
        std::fs::read_dir(&directory).map_err(|_| "authoring_contribution_directory_missing")?
    {
        let path = entry
            .map_err(|_| "authoring_contribution_inventory_invalid")?
            .path();
        if path.extension().and_then(|v| v.to_str()) != Some("json") {
            continue;
        }
        count += 1;
        if count > 100_000 {
            return Err("authoring_contribution_inventory_budget_exceeded");
        }
        let data = guard_secure_fs::read_bounded(Path::new(&path), MAX_SOURCE_INPUT_BYTES)
            .map_err(|_| "authoring_contribution_inventory_invalid")?;
        bytes = bytes
            .checked_add(data.bytes.len())
            .ok_or("authoring_contribution_inventory_budget_exceeded")?;
        if bytes > 128 * 1024 * 1024 {
            return Err("authoring_contribution_inventory_budget_exceeded");
        }
        let payload = json::decode(&data.bytes)?;
        if payload["id"] == request.contribution_id {
            continue;
        }
        if request.kind == "mcp" {
            if !payload["launch"].is_object() {
                return Err("authoring_contribution_inventory_invalid");
            }
            if payload["launch"]["package"]
                .as_str()
                .is_some_and(|v| v.trim().to_lowercase() == request.package.to_lowercase())
            {
                return Err("authoring_mcp_package_collision");
            }
        } else {
            let names = payload["executables"]
                .as_array()
                .ok_or("authoring_executable_inventory_invalid")?;
            for name in names {
                if executable(
                    name.as_str()
                        .ok_or("authoring_executable_inventory_invalid")?,
                ) == wanted
                {
                    return Err("authoring_executable_contribution_collision");
                }
            }
        }
    }
    if request.kind == "cli" {
        let program: Value = serde_json::from_slice(packaged_command_program_bytes())
            .map_err(|_| "authoring_installed_coverage_invalid")?;
        for rule in program["rules"]
            .as_array()
            .ok_or("authoring_installed_coverage_invalid")?
        {
            if rule["extension_id"] == request.catalog_id {
                continue;
            }
            if rule["candidate_executables"]
                .as_array()
                .is_some_and(|names| {
                    names
                        .iter()
                        .any(|v| v.as_str().is_some_and(|v| executable(v) == wanted))
                })
            {
                return Err("authoring_installed_executable_collision");
            }
        }
        let catalog: Value =
            serde_json::from_slice(crate::native_command_catalog::embedded_catalog_bytes())
                .map_err(|_| "authoring_installed_coverage_invalid")?;
        for entry in catalog["catalog"]
            .as_array()
            .ok_or("authoring_installed_coverage_invalid")?
        {
            if entry["extension_id"] != request.catalog_id
                && entry["executables"].as_array().is_some_and(|names| {
                    names
                        .iter()
                        .any(|v| v.as_str().is_some_and(|v| executable(v) == wanted))
                })
            {
                return Err("authoring_installed_executable_collision");
            }
        }
    }
    Ok(serde_json::json!({"ok":true,"contributions":count}))
}
