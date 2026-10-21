use super::*;

// package_intent_parser.py `_parse_pip_intent`
pub(super) fn parse_pip_intent(
    tokens: &[String],
    workspace: Option<&Path>,
) -> Option<PackageIntent> {
    let working_tokens = strip_package_manager_global_options(tokens);
    if working_tokens.len() < 2 || working_tokens[1] != "install" {
        return None;
    }
    let mut targets: Vec<PackageIntentTarget> = Vec::new();
    let mut manifest_paths: Vec<String> = Vec::new();
    let mut index = 2usize;
    while index < working_tokens.len() {
        let token = &working_tokens[index];
        if matches!(
            token.as_str(),
            "-r" | "--requirement" | "-c" | "--constraint"
        ) && index + 1 < working_tokens.len()
        {
            manifest_paths.push(working_tokens[index + 1].clone());
            index += 2;
            continue;
        }
        if token.starts_with("--requirement=") || token.starts_with("--constraint=") {
            manifest_paths.push(
                token
                    .split_once('=')
                    .map(|(_, v)| v)
                    .unwrap_or("")
                    .to_owned(),
            );
            index += 1;
            continue;
        }
        if token.starts_with("-r") && token != "-r" {
            manifest_paths.push(token[2..].to_owned());
            index += 1;
            continue;
        }
        if token.starts_with("-c") && token != "-c" {
            manifest_paths.push(token[2..].to_owned());
            index += 1;
            continue;
        }
        if matches!(token.as_str(), "-e" | "--editable") && index + 1 < working_tokens.len() {
            targets.push(python_target(
                &working_tokens[index + 1],
                true,
                None,
                Vec::new(),
            ));
            index += 2;
            continue;
        }
        if matches!(
            token.as_str(),
            "--index-url" | "--extra-index-url" | "--hash"
        ) && index + 1 < tokens.len()
        {
            index += 2;
            continue;
        }
        if token.starts_with("--hash=") || token.starts_with('-') {
            index += 1;
            continue;
        }
        targets.push(python_target(token, false, None, Vec::new()));
        index += 1;
    }
    Some(build_intent(
        "pip",
        "install",
        tokens,
        targets,
        workspace,
        &[],
        &[],
        &existing_relative_paths(workspace, &manifest_paths),
        &[],
    ))
}

// package_intent_parser.py `_parse_pipx_intent`
pub(super) fn parse_pipx_intent(
    tokens: &[String],
    workspace: Option<&Path>,
) -> Option<PackageIntent> {
    let working_tokens = strip_package_manager_global_options(tokens);
    if working_tokens.len() < 3 || !matches!(working_tokens[1].as_str(), "install" | "run") {
        return None;
    }
    let target_spec = first_positional(&working_tokens[2..], &["--python"])?;
    Some(build_intent(
        "pipx",
        if working_tokens[1] == "run" {
            "execute"
        } else {
            "install"
        },
        tokens,
        vec![python_target(&target_spec, false, None, Vec::new())],
        workspace,
        &[],
        &[],
        &[],
        &[],
    ))
}

// package_intent_parser.py `_parse_uv_intent`
pub(super) fn parse_uv_intent(
    tokens: &[String],
    workspace: Option<&Path>,
) -> Option<PackageIntent> {
    let working_tokens = strip_package_manager_global_options(tokens);
    if working_tokens.len() < 2 {
        return None;
    }
    if working_tokens[1] == "add" {
        return Some(build_intent(
            "uv",
            "install",
            tokens,
            collect_package_specs(&working_tokens[2..])
                .iter()
                .map(|s| python_target(s, false, None, Vec::new()))
                .collect(),
            workspace,
            &["pyproject.toml".to_owned()],
            &["uv.lock".to_owned()],
            &[],
            &[],
        ));
    }
    if working_tokens.len() >= 3 && working_tokens[1] == "pip" && working_tokens[2] == "install" {
        return Some(build_intent(
            "uv",
            "install",
            tokens,
            collect_package_specs(&working_tokens[3..])
                .iter()
                .map(|s| python_target(s, false, None, Vec::new()))
                .collect(),
            workspace,
            &["pyproject.toml".to_owned()],
            &["uv.lock".to_owned()],
            &[],
            &[],
        ));
    }
    if working_tokens[1] == "sync" {
        return Some(build_intent(
            "uv",
            "sync",
            tokens,
            Vec::new(),
            workspace,
            &["pyproject.toml".to_owned()],
            &["uv.lock".to_owned()],
            &[],
            &[],
        ));
    }
    None
}

// package_intent_parser.py `_parse_poetry_intent`
pub(super) fn parse_poetry_intent(
    tokens: &[String],
    workspace: Option<&Path>,
) -> Option<PackageIntent> {
    let working_tokens = strip_package_manager_global_options(tokens);
    if working_tokens.len() < 2 {
        return None;
    }
    if working_tokens[1] == "install" {
        return Some(build_intent(
            "poetry",
            "sync",
            tokens,
            Vec::new(),
            workspace,
            &["pyproject.toml".to_owned()],
            &["poetry.lock".to_owned()],
            &[],
            &[],
        ));
    }
    if working_tokens[1] != "add" {
        return None;
    }
    let group =
        option_value(&working_tokens, "--group").or_else(|| option_value(&working_tokens, "-G"));
    let extras_value = option_value(&working_tokens, "--extras");
    let extras: Vec<String> = extras_value
        .as_deref()
        .unwrap_or("")
        .split(',')
        .filter(|item| !item.is_empty())
        .map(|item| item.to_owned())
        .collect();
    let targets = collect_package_specs(&working_tokens[2..])
        .iter()
        .map(|s| python_target(s, false, group.as_deref(), extras.clone()))
        .collect();
    Some(build_intent(
        "poetry",
        "install",
        tokens,
        targets,
        workspace,
        &["pyproject.toml".to_owned()],
        &["poetry.lock".to_owned()],
        &[],
        &[],
    ))
}

// package_intent_parser.py `_parse_pipenv_intent`
pub(super) fn parse_pipenv_intent(
    tokens: &[String],
    workspace: Option<&Path>,
) -> Option<PackageIntent> {
    let working_tokens = strip_package_manager_global_options(tokens);
    if working_tokens.len() < 2 {
        return None;
    }
    if working_tokens[1] == "sync" {
        return Some(build_intent(
            "pipenv",
            "sync",
            tokens,
            Vec::new(),
            workspace,
            &["Pipfile".to_owned()],
            &["Pipfile.lock".to_owned()],
            &[],
            &[],
        ));
    }
    if working_tokens[1] != "install" {
        return None;
    }
    Some(build_intent(
        "pipenv",
        "install",
        tokens,
        collect_package_specs(&working_tokens[2..])
            .iter()
            .map(|s| python_target(s, false, None, Vec::new()))
            .collect(),
        workspace,
        &["Pipfile".to_owned()],
        &["Pipfile.lock".to_owned()],
        &[],
        &[],
    ))
}
