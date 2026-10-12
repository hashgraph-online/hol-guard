//! Package manager install parsing for `parse_protect_command`.

use super::*;

pub(super) fn remaining_positionals(args: &[String]) -> Vec<String> {
    let mut positionals = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let token = &args[index];
        if token == "--" {
            positionals.extend(args[index + 1..].iter().cloned());
            break;
        }
        let takes_value = index + 1 < args.len() && !args[index + 1].starts_with('-');
        if token.starts_with("--") {
            index += if !token.contains('=') && takes_value {
                2
            } else {
                1
            };
            continue;
        }
        if token.starts_with('-') && token != "-" {
            index += if token.chars().count() == 2 && takes_value {
                2
            } else {
                1
            };
            continue;
        }
        positionals.push(token.clone());
        index += 1;
    }
    positionals
}

pub(super) fn spec_name(spec: &str) -> Result<Option<String>, ProtectParseError> {
    if starts_with_url(spec) {
        let parts = urlsplit(spec).map_err(ProtectParseError::InvalidUrl)?;
        let path = &parts.path[..urlparse_path_end(&parts)];
        let candidate = path_name(if path.is_empty() { spec } else { path });
        return Ok(Some(
            if candidate.is_empty() {
                spec
            } else {
                candidate
            }
            .to_owned(),
        ));
    }
    if spec.starts_with("./") || spec.starts_with("../") || spec.starts_with('/') {
        let name = path_name(spec);
        return Ok(Some(if name.is_empty() { spec } else { name }.to_owned()));
    }
    Ok((!spec.is_empty()).then(|| spec.to_owned()))
}

pub(super) fn spec_url(spec: &str) -> Option<String> {
    starts_with_url(spec).then(|| spec.to_owned())
}

pub(super) fn target_name_from_spec(spec: &str) -> Result<String, ProtectParseError> {
    Ok(match spec_name(spec)? {
        Some(name) => name.strip_suffix(".git").unwrap_or(&name).to_owned(),
        None => spec.to_owned(),
    })
}

pub(super) fn split_once_owned(
    spec: &str,
    separator: &str,
    last: bool,
) -> (Option<String>, Option<String>) {
    let split = if last {
        spec.rsplit_once(separator)
    } else {
        spec.split_once(separator)
    };
    let (name, version) = split.expect("separator presence checked by caller");
    (Some(name.to_owned()), Some(version.to_owned()))
}

pub(super) fn parse_package_identity(
    ecosystem: &str,
    spec: &str,
) -> Result<(Option<String>, Option<String>), ProtectParseError> {
    if matches!(ecosystem, "pip" | "uv") && spec.contains("==") {
        return Ok(split_once_owned(spec, "==", false));
    }
    if ecosystem == "go" && spec.contains('@') {
        return Ok(split_once_owned(spec, "@", true));
    }
    if spec.starts_with('@') {
        if spec.matches('@').count() >= 2 {
            return Ok(split_once_owned(spec, "@", true));
        }
        return Ok((Some(spec.to_owned()), None));
    }
    if spec.contains('@') && !starts_with_url(spec) {
        return Ok(split_once_owned(spec, "@", true));
    }
    Ok((spec_name(spec)?, None))
}

pub(super) fn package_target(
    ecosystem: &str,
    spec: &str,
) -> Result<ProtectTarget, ProtectParseError> {
    let (package_name, version) = parse_package_identity(ecosystem, spec)?;
    let package_name = package_name.map(|name| python_strip(&name).to_owned());
    let version = version.map(|version| python_strip(&version).to_owned());
    let source_url = spec_url(spec).or_else(|| version.as_deref().and_then(spec_url));
    let identity = package_name
        .clone()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| spec.to_owned());
    Ok(target(
        format!("install:{ecosystem}:{identity}"),
        &identity,
        &format!("{ecosystem}_package"),
        ecosystem,
        package_name.clone(),
        build_package_url(ecosystem, package_name.as_deref(), version.as_deref()),
        Some(spec.to_owned()),
        version,
        source_url,
        None,
    ))
}

pub(super) fn collect_package_specs(values: &[String]) -> Vec<String> {
    const VALUE_OPTIONS: [&str; 6] = [
        "-r",
        "--extra-index-url",
        "--index-url",
        "--prefix",
        "--registry",
        "--requirement",
    ];
    let mut specs = Vec::new();
    let mut skip_next = false;
    for (index, value) in values.iter().enumerate() {
        if skip_next {
            skip_next = false;
            continue;
        }
        if value.starts_with('-') {
            skip_next = VALUE_OPTIONS.contains(&value.as_str());
            continue;
        }
        if index > 0 && matches!(values[index - 1].as_str(), "-r" | "--requirement") {
            continue;
        }
        specs.push(value.clone());
    }
    specs
}

pub(super) fn package_manager_request(
    command: &[String],
    ecosystem: &str,
    specs: &[String],
) -> Result<ProtectRequest, ProtectParseError> {
    let mut targets = specs
        .iter()
        .map(|spec| package_target(ecosystem, spec))
        .collect::<Result<Vec<_>, _>>()?;
    if targets.is_empty() {
        targets.push(target(
            format!(
                "install:{ecosystem}:{}",
                &command_fingerprint(command)[..16]
            ),
            ecosystem,
            "package_request",
            ecosystem,
            None,
            None,
            Some(shlex_join(command)),
            None,
            first_url(command),
            None,
        ));
    }
    Ok(ProtectRequest {
        command: command.to_vec(),
        install_kind: "package_install".into(),
        executor: ecosystem.into(),
        package_manager: Some(ecosystem.into()),
        harness: None,
        targets,
    })
}

pub(super) fn specs_after(command: &[String], verbs: &[&str]) -> Vec<String> {
    if command.len() > 1 && verbs.contains(&command[1].as_str()) {
        collect_package_specs(&command[2..])
    } else {
        Vec::new()
    }
}

pub(super) fn parse_package_manager(
    command: &[String],
    ecosystem: &str,
) -> Result<ProtectRequest, ProtectParseError> {
    let specs = match ecosystem {
        "go" => specs_after(command, &["get", "install"]),
        _ => {
            let normalized = strip_package_manager_global_options(command);
            match ecosystem {
                "npm" => specs_after(&normalized, &["install", "add", "i"]),
                "pnpm" => specs_after(&normalized, &["add", "install"]),
                "pip" => specs_after(&normalized, &["install"]),
                "yarn" => {
                    let working = if normalized.len() >= 4 && normalized[1] == "workspace" {
                        std::iter::once(normalized[0].clone())
                            .chain(normalized[3..].iter().cloned())
                            .collect()
                    } else {
                        normalized
                    };
                    specs_after(&working, &["add"])
                }
                _ => {
                    if normalized.len() >= 3 && normalized[1] == "pip" && normalized[2] == "install"
                    {
                        collect_package_specs(&normalized[3..])
                    } else {
                        specs_after(&normalized, &["add"])
                    }
                }
            }
        }
    };
    package_manager_request(command, ecosystem, &specs)
}
