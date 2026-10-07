//! Exact stable npm pins for authored MCP launch metadata.

pub(crate) fn valid_package_pin(command: &str, package: &str, version: &str) -> bool {
    if !matches!(command, "npx" | "npm" | "pnpm" | "yarn" | "bunx")
        || package.len() > 214
        || version.len() > 64
    {
        return false;
    }
    let components: Vec<_> = version.split('.').collect();
    if components.len() != 3
        || components.iter().any(|part| {
            part.is_empty()
                || !part.bytes().all(|byte| byte.is_ascii_digit())
                || (part.len() > 1 && part.starts_with('0'))
        })
    {
        return false;
    }
    let name = if let Some(scoped) = package.strip_prefix('@') {
        let Some((scope, name)) = scoped.split_once('/') else {
            return false;
        };
        if scope.is_empty() || !scope.bytes().all(package_character) {
            return false;
        }
        name
    } else {
        package
    };
    !name.is_empty()
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name.bytes().all(package_character)
}

pub(crate) fn configured_package_pin(identity: &serde_json::Value) -> Option<String> {
    let identity = identity.as_object()?;
    let command = identity.get("command")?.as_str()?;
    let package = identity.get("package_name")?.as_str()?;
    let version = identity.get("package_version")?.as_str()?;
    let launcher = crate::mcp_decision::package_launcher_name(command)?;
    if identity.get("package_source")?.as_str()? != "default"
        || identity.get("transport")?.as_str()? != "stdio"
        || !default_package_source_environment(identity.get("env_keys")?)
        || !valid_package_pin(&launcher, package, version)
    {
        return None;
    }
    Some(format!("{launcher}:{package}@{version}"))
}

fn default_package_source_environment(keys: &serde_json::Value) -> bool {
    let Some(keys) = keys.as_array() else {
        return false;
    };
    keys.len() <= 256
        && keys.iter().all(|key| {
            let Some(key) = key.as_str() else {
                return false;
            };
            let key = key.trim().to_ascii_lowercase();
            !(matches!(
                key.as_str(),
                "home"
                    | "userprofile"
                    | "homedrive"
                    | "homepath"
                    | "appdata"
                    | "localappdata"
                    | "xdg_config_home"
                    | "xdg_config_dirs"
                    | "node_options"
                    | "node_path"
                    | "path"
            ) || key.starts_with("npm_config_")
                || key.starts_with("yarn_")
                || key.starts_with("bun_"))
        })
}

fn package_character(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
}
