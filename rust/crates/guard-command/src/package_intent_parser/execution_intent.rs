use super::*;

// Value-taking uv tool run options (uvx is its alias). Keep both package and
// dependency traversal on the same arity rules.
const UVX_VALUE_OPTIONS: &[&str] = &[
    "--from",
    "--with",
    "-w",
    "--with-editable",
    "--with-requirements",
    "--constraints",
    "--constraint",
    "-c",
    "--build-constraints",
    "--build-constraint",
    "-b",
    "--overrides",
    "--override",
    "--env-file",
    "--python-platform",
    "--torch-backend",
    "--index",
    "--default-index",
    "--index-url",
    "-i",
    "--extra-index-url",
    "--find-links",
    "-f",
    "--index-strategy",
    "--keyring-provider",
    "--upgrade-package",
    "-P",
    "--resolution",
    "--prerelease",
    "--fork-strategy",
    "--exclude-newer",
    "--exclude-newer-package",
    "--no-sources-package",
    "--reinstall-package",
    "--link-mode",
    "--config-setting",
    "--config-settings",
    "-C",
    "--config-settings-package",
    "--no-build-isolation-package",
    "--no-build-package",
    "--no-binary-package",
    "--cache-dir",
    "--refresh-package",
    "--python",
    "-p",
    "--color",
    "--allow-insecure-host",
    "--trusted-host",
    "--directory",
    "--project",
    "--config-file",
    "--python-preference",
    "--python-fetch",
    "--preview-features",
    "--preview-feature",
];

enum UvxArgument<'a> {
    Option(&'a str, &'a str),
    Command(&'a str),
}

fn uvx_arguments(tokens: &[String]) -> impl Iterator<Item = UvxArgument<'_>> {
    let mut tokens = tokens.iter().skip(1);
    let mut finished = false;
    std::iter::from_fn(move || {
        if finished {
            return None;
        }
        while let Some(token) = tokens.next() {
            if token == "--" {
                finished = true;
                return tokens.next().map(|token| UvxArgument::Command(token));
            }
            if !token.starts_with('-') {
                finished = true;
                return Some(UvxArgument::Command(token));
            }
            let (name, attached) = token
                .split_once('=')
                .map_or((token.as_str(), None), |(name, value)| (name, Some(value)));
            if UVX_VALUE_OPTIONS.contains(&name) {
                let value = attached.or_else(|| tokens.next().map(String::as_str))?;
                return Some(UvxArgument::Option(name, value));
            }
            // Clap accepts short values both attached and with an equals sign.
            if !token.starts_with("--") && token.len() > 2 {
                if let Some(name) = token.get(..2) {
                    if UVX_VALUE_OPTIONS.contains(&name) {
                        return Some(UvxArgument::Option(name, &token[2..]));
                    }
                }
            }
        }
        None
    })
}

// package_intent_parser.py `_parse_exec_intent`
#[allow(clippy::too_many_arguments)]
pub(super) fn parse_exec_intent(
    tokens: &[String],
    workspace: Option<&Path>,
    effective_path: Option<&str>,
    path_source: &str,
    effective_cwd: Option<&Path>,
    cwd_source: &str,
    execution_context_hash: &str,
    execution_context_complete: bool,
) -> Option<PackageIntent> {
    let package_token_value = exec_package_spec(tokens)?;
    let command = command_name(&tokens[0]);
    let ecosystem = if matches!(command.as_str(), "uvx" | "pipx") {
        "pypi"
    } else {
        "npm"
    };
    let target = if ecosystem == "pypi" {
        python_target(&package_token_value, false, None, Vec::new())
    } else {
        js_target(&package_token_value)
    };
    let mut targets = vec![target];
    if command == "uvx" {
        for argument in uvx_arguments(tokens) {
            if let UvxArgument::Option("--with" | "-w", spec) = argument {
                targets.push(python_target(spec, false, None, Vec::new()));
            }
        }
    }
    let is_local = LOCAL_EXECUTION_COMMANDS.contains(command.as_str());
    let manifest_candidates: &[&str] = if is_local { &["package.json"] } else { &[] };
    let lockfile_candidates: &[&str] = if is_local { JS_LOCKFILE_NAMES } else { &[] };
    let intent_workspace = if is_local { effective_cwd } else { workspace };
    let manifest_candidates: Vec<String> =
        manifest_candidates.iter().map(|s| s.to_string()).collect();
    let lockfile_candidates: Vec<String> =
        lockfile_candidates.iter().map(|s| s.to_string()).collect();
    let mut intent = build_intent(
        &command,
        "execute",
        tokens,
        targets,
        if execution_context_complete {
            intent_workspace
        } else {
            None
        },
        &manifest_candidates,
        &lockfile_candidates,
        &[],
        &[],
    );
    if !is_local {
        return Some(intent);
    }
    let mut local_execution = local_package_execution_evidence(
        &command,
        tokens,
        workspace,
        effective_path,
        path_source,
        if execution_context_complete {
            effective_cwd
        } else {
            None
        },
        cwd_source,
        execution_context_hash,
        &intent.manifest_paths,
        &intent.lockfile_paths,
    );
    if let Some(launch) =
        build_typescript_launch_evidence(&typescript_launch_inputs(tokens, &local_execution))
    {
        local_execution.typescript_launch = Some(launch.to_dict());
    }
    intent.local_executions = vec![local_execution];
    intent
        .notes
        .push("local-execution-requires-review".to_owned());
    Some(intent)
}

/// `_parse_exec_intent` called from non-local manager paths with Python's
/// default context arguments.
pub(super) fn parse_exec_intent_default(
    tokens: &[String],
    workspace: Option<&Path>,
) -> Option<PackageIntent> {
    parse_exec_intent(
        tokens,
        workspace,
        None,
        "not_applicable",
        None,
        "not_applicable",
        "not_applicable",
        true,
    )
}

// package_intent_parser.py `_exec_package_spec`
pub(super) fn exec_package_spec(tokens: &[String]) -> Option<String> {
    let command = command_name(&tokens[0]);
    if command == "npm" && tokens.len() >= 2 && matches!(tokens[1].as_str(), "exec" | "x") {
        let explicit_package = option_value(tokens, "--package");
        let positional_package = first_positional(&tokens[2..], &["--package"]);
        if let (Some(positional), Some(explicit)) =
            (positional_package.clone(), explicit_package.clone())
        {
            let positional_target = js_target(&positional);
            let explicit_target = js_target(&explicit);
            if positional_target.package_name == explicit_target.package_name {
                let positional_specifier = positional_target
                    .requested_specifier
                    .clone()
                    .or(positional_target.source_url.clone());
                let explicit_specifier = explicit_target
                    .requested_specifier
                    .clone()
                    .or(explicit_target.source_url.clone());
                if positional_specifier.is_none() && explicit_specifier.is_some() {
                    return Some(explicit);
                }
                return Some(positional);
            }
            return Some(explicit);
        }
        return explicit_package.or(positional_package);
    }
    if command == "pipx" && tokens.len() >= 2 && tokens[1] == "run" {
        return first_positional(&tokens[2..], &["--python"]);
    }
    if matches!(command.as_str(), "pnpm" | "yarn") && tokens.len() >= 2 && tokens[1] == "dlx" {
        return first_positional(&tokens[2..], &[]);
    }
    if command == "npx" {
        return option_value(tokens, "--package")
            .or_else(|| first_positional(&tokens[1..], &["--package", "-p"]));
    }
    if command == "bunx" {
        return first_positional(&tokens[1..], &["--bun"]);
    }
    if command == "uvx" {
        return uvx_arguments(tokens).find_map(|argument| match argument {
            UvxArgument::Option("--from", spec) | UvxArgument::Command(spec) => {
                Some(spec.to_owned())
            }
            _ => None,
        });
    }
    None
}
