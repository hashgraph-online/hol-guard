//! Harness MCP registration and custom command parsing for
//! `parse_protect_command`.

use super::*;

pub(super) fn simple_registration(
    command: &[String],
    executor: &str,
    ecosystem: &str,
    artifact_type: &str,
) -> ProtectRequest {
    let name = &command[3];
    registration(
        command,
        executor,
        ecosystem,
        target(
            format!("install:{ecosystem}:{name}"),
            name,
            artifact_type,
            ecosystem,
            Some(name.clone()),
            None,
            Some(name.clone()),
            None,
            option_value(command, "--url"),
            Some(ecosystem),
        ),
    )
}

pub(super) fn verb_is(command: &[String], first: &str, second: &str) -> bool {
    command[1] == first && command[2] == second
}

pub(super) fn parse_codex(command: &[String]) -> Result<ProtectRequest, ProtectParseError> {
    if command.len() >= 4 && verb_is(command, "mcp", "add") {
        return Ok(simple_registration(command, "codex", "codex", "mcp_server"));
    }
    Ok(parse_custom(command))
}

pub(super) fn parse_cursor(command: &[String]) -> Result<ProtectRequest, ProtectParseError> {
    if command.len() >= 4 && verb_is(command, "mcp", "add") {
        return Ok(simple_registration(
            command,
            "cursor",
            "cursor",
            "mcp_server",
        ));
    }
    Ok(parse_custom(command))
}

pub(super) fn parse_opencode(command: &[String]) -> Result<ProtectRequest, ProtectParseError> {
    if command.len() >= 4
        && matches!(command[1].as_str(), "plugin" | "skill")
        && matches!(command[2].as_str(), "add" | "install")
    {
        let artifact_type = if command[1] == "plugin" {
            "plugin"
        } else {
            "skill"
        };
        return Ok(simple_registration(
            command,
            "opencode",
            "opencode",
            artifact_type,
        ));
    }
    Ok(parse_custom(command))
}

pub(super) fn parse_claude(command: &[String]) -> Result<ProtectRequest, ProtectParseError> {
    if command.len() >= 5 && verb_is(command, "mcp", "add") {
        let positional = remaining_positionals(&command[3..]);
        if positional.len() < 2 {
            return Ok(parse_custom(command));
        }
        let (name, command_or_url) = (&positional[0], &positional[1]);
        let source_url = (command_or_url.starts_with("http://")
            || command_or_url.starts_with("https://"))
        .then(|| command_or_url.clone());
        return Ok(registration(
            command,
            "claude",
            "claude-code",
            target(
                format!("install:claude-code:mcp:{name}"),
                name,
                "mcp_server",
                "claude-code",
                Some(name.clone()),
                None,
                Some(command_or_url.clone()),
                None,
                source_url,
                Some("claude-code"),
            ),
        ));
    }
    if command.len() >= 5 && verb_is(command, "mcp", "add-json") {
        let positional = remaining_positionals(&command[3..]);
        if positional.len() < 2 {
            return Ok(parse_custom(command));
        }
        let target =
            json_registration_target(&positional[1], "claude-code", Some(&positional[0]), true)?;
        return Ok(registration(command, "claude", "claude-code", target));
    }
    Ok(parse_custom(command))
}

pub(super) fn parse_gemini(command: &[String]) -> Result<ProtectRequest, ProtectParseError> {
    if command.len() >= 4 && verb_is(command, "extensions", "install") {
        return Ok(simple_registration(
            command,
            "gemini",
            "gemini",
            "extension",
        ));
    }
    if command.len() >= 4
        && (verb_is(command, "extensions", "link")
            || verb_is(command, "skills", "install")
            || verb_is(command, "skills", "link"))
    {
        let spec = &command[3];
        let name = target_name_from_spec(spec)?;
        let extension = command[1] == "extensions";
        let artifact_type = if extension { "extension" } else { "skill" };
        let package_name = extension.then(|| name.clone());
        return Ok(registration(
            command,
            "gemini",
            "gemini",
            target(
                format!("install:gemini:{artifact_type}:{name}"),
                &name,
                artifact_type,
                "gemini",
                package_name.clone(),
                build_package_url("gemini", package_name.as_deref(), None),
                Some(spec.clone()),
                None,
                spec_url(spec),
                Some("gemini"),
            ),
        ));
    }
    if command.len() >= 5 && verb_is(command, "mcp", "add") {
        let (name, command_or_url) = (&command[3], &command[4]);
        let transport =
            option_value(command, "--transport").or_else(|| option_value(command, "--type"));
        let source_url = is_remote_transport(command_or_url, transport.as_deref())
            .then(|| command_or_url.clone());
        return Ok(registration(
            command,
            "gemini",
            "gemini",
            target(
                format!("install:gemini:mcp:{name}"),
                name,
                "mcp_server",
                "gemini",
                Some(name.clone()),
                None,
                Some(command_or_url.clone()),
                None,
                source_url,
                Some("gemini"),
            ),
        ));
    }
    Ok(parse_custom(command))
}

pub(super) fn parse_antigravity(command: &[String]) -> Result<ProtectRequest, ProtectParseError> {
    if let Some(extension) = option_value(command, "--install-extension") {
        return Ok(registration(
            command,
            "antigravity",
            "antigravity",
            target(
                format!("install:antigravity:extension:{extension}"),
                &extension,
                "extension",
                "antigravity",
                Some(extension.clone()),
                build_package_url("antigravity", Some(&extension), None),
                Some(extension.clone()),
                None,
                spec_url(&extension),
                Some("antigravity"),
            ),
        ));
    }
    if let Some(raw_payload) = option_value(command, "--add-mcp") {
        let target = json_registration_target(&raw_payload, "antigravity", None, false)?;
        return Ok(registration(command, "antigravity", "antigravity", target));
    }
    Ok(parse_custom(command))
}

/// `_parse_claude_mcp_target` / `_parse_antigravity_mcp_target`: a JSON MCP
/// server registration payload; anything but a JSON object reads as `{}`.
pub(super) fn json_registration_target(
    raw_payload: &str,
    ecosystem: &str,
    name: Option<&String>,
    reads_transport: bool,
) -> Result<ProtectTarget, ProtectParseError> {
    let payload = match parse_python_json(raw_payload) {
        Ok(OValue::Map(map)) => Some(map),
        Ok(_) | Err(PyJsonError::Decode) => None,
        Err(PyJsonError::Unsupported) => return Err(ProtectParseError::UnsupportedPayload),
    };
    let text = |key: &str| match payload.as_ref().and_then(|map| map.get(key)) {
        Some(OValue::Str(value)) => Some(value.clone()),
        _ => None,
    };
    let name = match name {
        Some(name) => name.clone(),
        None => text("name").unwrap_or_else(|| "antigravity-mcp".to_owned()),
    };
    let transport = if reads_transport {
        text("transport")
    } else {
        None
    };
    let command_or_url = text("url").or_else(|| text("command"));
    let source_url =
        command_or_url.filter(|value| is_remote_transport(value, transport.as_deref()));
    let prefix = if ecosystem == "antigravity" {
        "install:antigravity:mcp"
    } else {
        "install:claude-code:mcp"
    };
    Ok(target(
        format!("{prefix}:{name}"),
        &name,
        "mcp_server",
        ecosystem,
        Some(name.clone()),
        None,
        Some(raw_payload.to_owned()),
        None,
        source_url,
        Some(ecosystem),
    ))
}

pub(super) fn is_remote_transport(command_or_url: &str, transport: Option<&str>) -> bool {
    transport != Some("stdio")
        && (command_or_url.starts_with("http://") || command_or_url.starts_with("https://"))
}

pub(super) fn parse_custom(command: &[String]) -> ProtectRequest {
    let executable = path_name(&command[0]);
    ProtectRequest {
        command: command.to_vec(),
        install_kind: "custom".into(),
        executor: executable.into(),
        package_manager: None,
        harness: None,
        targets: vec![target(
            format!("install:custom:{}", &command_fingerprint(command)[..16]),
            executable,
            "custom_command",
            "custom",
            None,
            None,
            Some(shlex_join(command)),
            None,
            first_url(command),
            None,
        )],
    }
}
