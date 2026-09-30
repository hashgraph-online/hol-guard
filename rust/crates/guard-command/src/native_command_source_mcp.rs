//! Project existing canonical MCP JSON; matching stays in native admission/evaluation.
use super::{contract::*, *};

#[derive(Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct McpSource {
    schema_version: String,
    id: String,
    version: String,
    name: String,
    description: String,
    trust_class: String,
    activation: String,
    publisher: McpPublisher,
    icon: SourceIcon,
    homepage: Option<String>,
    license: Option<String>,
    launch: Launch,
    risk_classes: Vec<String>,
    tools: Vec<Tool>,
    #[serde(default)]
    reference_urls: Vec<String>,
    safer_alternatives: Vec<String>,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct McpPublisher {
    id: String,
    display_name: String,
    url: Option<String>,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Launch {
    PackageLauncher {
        command: String,
        package: String,
    },
    RemoteHttp {
        url: String,
        #[serde(rename = "serverNames")]
        server_names: Vec<String>,
    },
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct Tool {
    name: String,
    state: String,
}

pub(super) struct LoweredMcp {
    pub document: SourceDocument,
    pub wire: Value,
    pub canonical: Value,
}

pub(super) fn lower(bytes: &[u8]) -> Result<LoweredMcp, &'static str> {
    let canonical = json::decode(bytes)?;
    if ["homepage", "license"]
        .iter()
        .any(|key| canonical.get(key).is_some_and(Value::is_null))
        || canonical["publisher"]
            .get("url")
            .is_some_and(Value::is_null)
    {
        return Err("command_source_mcp_contract_invalid");
    }
    let input: McpSource = serde_json::from_value(canonical.clone())
        .map_err(|_| "command_source_mcp_contract_invalid")?;
    if input.schema_version != "guard.mcp-server-contribution.v1"
        || !input.id.starts_with("mcp.")
        || input.id.len() > 256
        || input.trust_class != "external"
        || input.activation != "opt-in"
        || input.name.chars().count() > 128
        || input.description.chars().count() > 512
        || input.risk_classes.len() > 16
        || input.risk_classes.iter().any(|s| s.chars().count() > 64)
        || input.reference_urls.len() > 32
        || input.reference_urls.iter().any(|s| s.chars().count() > 512)
        || input.safer_alternatives.len() > 8
        || input
            .safer_alternatives
            .iter()
            .any(|s| s.chars().count() > 256)
        || input.tools.is_empty()
        || input.tools.len() > 80
    {
        return Err("command_source_mcp_contract_invalid");
    }
    let (executables, example, remote) = match &input.launch {
        Launch::PackageLauncher { command, package } => {
            if !matches!(
                command.as_str(),
                "npx" | "uvx" | "bunx" | "pnpm" | "npm" | "yarn" | "pipx"
            ) || package.is_empty()
                || package.chars().count() > 256
            {
                return Err("command_source_mcp_launcher_invalid");
            }
            (
                vec![command.clone()],
                format!("{command} -y {package}"),
                false,
            )
        }
        Launch::RemoteHttp { url, server_names } => {
            if server_names.is_empty() || server_names.len() > 8 {
                return Err("command_source_mcp_alias_invalid");
            }
            (Vec::new(), canonical_endpoint(url)?, true)
        }
    };
    let mut names = BTreeSet::new();
    for tool in &input.tools {
        if tool.name.is_empty()
            || tool.name.len() > 128
            || !matches!(
                tool.state.as_str(),
                "inherit" | "allow" | "review" | "block"
            )
            || (remote && tool.state == "allow")
            || !names.insert(crate::native_command_controls::normalized_tool(&tool.name))
        {
            return Err("command_source_mcp_tool_invalid");
        }
    }
    let suffix = input.id.strip_prefix("mcp.").unwrap();
    let extension_id = format!("command.mcp-{suffix}");
    let encoded = suffix
        .replace('x', "xx")
        .replace('.', "xd")
        .replace('-', "xh");
    let action = format!("mcp {encoded} tool");
    let permission_id = format!("{extension_id}.permission.{}", action.replace(' ', "-"));
    let wire =
        serde_json::json!({"surface":"mcp","mcp_launch":input.launch,"mcp_tools":input.tools});
    let permission = serde_json::json!({"permission_id":permission_id,"implementation_version":input.version,
        "label":action,"description":format!("Controls the {action} capability."),"risk_tier":"high",
        "baseline_floor":"review","default_enabled":true,"configurable":false,
        "fixed_reason":"This safety permission is immutable.","typed_capabilities":[],"action_classes":[action],
        "dependencies":[],"conflicts":[],"implied_permissions":[],"introduced_version":"2.2.0",
        "deprecated":false,"replacement_permission_id":null,"safer_guidance":input.safer_alternatives,
        "example_command":example,"family":null});
    let document = serde_json::from_value(serde_json::json!({
        "schema":SOURCE_SCHEMA,"extension":{
            "extension_id":extension_id,"version":input.version,"name":input.name,"description":input.description,
            "publisher":{"id":input.publisher.id,"display_name":input.publisher.display_name,"url":input.publisher.url},
            "icon":input.icon,"homepage":input.homepage,"license":input.license,
            "action_classes":[action],"risk_classes":input.risk_classes,"safer_alternatives":input.safer_alternatives,
            "reference_urls":input.reference_urls,"required":false,"source":"built-in",
            "aliases":[],"dependencies":[],"conflicts":[],"delegated_protection":null,
            "ecosystem_ids":[],"executables":executables,"project_markers":[],"rules":[],
            "permissions":[permission]
        }
    })).map_err(|_| "command_source_mcp_projection_invalid")?;
    Ok(LoweredMcp {
        document,
        wire,
        canonical,
    })
}

/// Canonical endpoint identity for collision detection, after existing native
/// public-HTTPS admission. Queries are not part of endpoint identity.
fn canonical_endpoint(value: &str) -> Result<String, &'static str> {
    if !super::super::admission::valid_remote_mcp_url(value) {
        return Err("command_source_mcp_endpoint_invalid");
    }
    let rest = value.strip_prefix("https://").unwrap();
    let boundary = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..boundary];
    let host = if let Some(bracketed) = authority.strip_prefix('[') {
        let raw = bracketed.split(']').next().unwrap();
        let address: std::net::Ipv6Addr = raw
            .parse()
            .map_err(|_| "command_source_mcp_endpoint_invalid")?;
        address
            .to_ipv4_mapped()
            .map(|v4| v4.to_string())
            .unwrap_or_else(|| format!("[{address}]"))
    } else {
        authority
            .strip_suffix(":443")
            .unwrap_or(authority)
            .trim_end_matches('.')
            .to_ascii_lowercase()
    };
    let path = rest[boundary..].split('?').next().unwrap();
    let bytes = path.as_bytes();
    let mut normalized = String::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let decoded = u8::from_str_radix(&path[index + 1..index + 3], 16)
                .map_err(|_| "command_source_mcp_endpoint_invalid")?;
            if decoded.is_ascii_alphanumeric() || b"-._~".contains(&decoded) {
                normalized.push(decoded as char);
            } else {
                normalized.push_str(&format!("%{decoded:02X}"));
            }
            index += 3;
        } else {
            normalized.push(bytes[index] as char);
            index += 1;
        }
    }
    let mut segments = Vec::new();
    for segment in normalized.split('/') {
        match segment {
            ".." => {
                segments.pop();
            }
            "." => {}
            _ => segments.push(segment),
        }
    }
    if normalized.ends_with("/.") || normalized.ends_with("/..") {
        segments.push("");
    }
    let mut path = segments.join("/");
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    Ok(format!("https://{host}{path}"))
}

pub(super) fn validate_inventory(program: &Value) -> Result<(), &'static str> {
    let mut packages = BTreeSet::new();
    let mut endpoints = BTreeSet::new();
    let mut aliases = BTreeSet::new();
    for extension in program["extensions"]
        .as_array()
        .ok_or("command_source_mcp_projection_invalid")?
    {
        let launch = &extension["mcp"]["mcp_launch"];
        match launch["kind"].as_str() {
            Some("package-launcher") => {
                let package = launch["package"]
                    .as_str()
                    .ok_or("command_source_mcp_projection_invalid")?;
                if !packages.insert(package.trim().to_lowercase()) {
                    return Err("command_source_mcp_package_duplicate");
                }
            }
            Some("remote-http") => {
                let url = launch["url"]
                    .as_str()
                    .ok_or("command_source_mcp_projection_invalid")?;
                if !endpoints.insert(canonical_endpoint(url)?) {
                    return Err("command_source_mcp_endpoint_duplicate");
                }
                for name in launch["serverNames"]
                    .as_array()
                    .ok_or("command_source_mcp_projection_invalid")?
                {
                    let name = name
                        .as_str()
                        .ok_or("command_source_mcp_projection_invalid")?;
                    if !aliases.insert(name.to_owned()) {
                        return Err("command_source_mcp_alias_duplicate");
                    }
                }
            }
            None => {}
            _ => return Err("command_source_mcp_launcher_invalid"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_identity_preserves_existing_alias_collision_rules() {
        assert_eq!(
            canonical_endpoint("https://EXAMPLE.com.:443/a/%2e%2e/%62?view=1").unwrap(),
            "https://example.com/b"
        );
        assert_eq!(
            canonical_endpoint("https://[::ffff:8.8.8.8]/").unwrap(),
            "https://8.8.8.8/"
        );
        assert!(canonical_endpoint("https://127.0.0.1/mcp").is_err());
        let program = serde_json::json!({"extensions":[
            {"mcp":{"mcp_launch":{"kind":"remote-http","url":"https://example.com/a/%62?one=1","serverNames":["one"]}}},
            {"mcp":{"mcp_launch":{"kind":"remote-http","url":"https://example.com/a/b?two=2","serverNames":["two"]}}}
        ]});
        assert_eq!(
            validate_inventory(&program),
            Err("command_source_mcp_endpoint_duplicate")
        );
    }
}
