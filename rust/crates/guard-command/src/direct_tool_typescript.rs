//! Local no-emit TypeScript commands and bounded diagnostic observers.
use super::*;

pub(super) fn direct_typescript_diagnostic_filter_context(
    context: &ShellExecutionContext,
    workspace: &Path,
    home: &Path,
    authority: &dyn DirectToolAuthority,
) -> Option<ShellExecutionContext> {
    if routine_context(context, workspace, home, authority) {
        return Some(context.clone());
    }
    if !context.complete || context.segments.len() != 4 {
        return None;
    }
    let [directory, compiler, grep, marker] = context.segments.as_slice() else {
        return None;
    };
    if directory.directory_operation.as_deref() != Some("cd")
        || !directory.control_before.is_empty()
        || compiler.control_before != ["&&"]
        || compiler.effective_cwd.as_deref() != Some(workspace)
        || grep.control_before != ["|"]
        || marker.control_before != ["||"]
        || compiler.tokens != ["npx", "tsc", "--noEmit", "2>&1"]
        || !compiler_is_bound(workspace, home, authority)
        || grep.tokens.len() != 3
        || grep.tokens[..2] != ["grep", "-E"]
        || grep.tokens[2].chars().count() > 512
        || !diagnostic_path_filter(&grep.tokens[2])
        || !trusted_path_command("grep", workspace, home, authority)
        || marker.tokens != ["echo", "NO_ERRORS_IN_TOUCHED_FILES"]
    {
        return None;
    }
    Some(context.clone())
}

fn compiler_is_bound(workspace: &Path, home: &Path, authority: &dyn DirectToolAuthority) -> bool {
    authority.within_budget()
        && shell_read_execution_environment_is_safe(workspace, authority)
        && !node_execution_environment_is_configurable(workspace, home, authority)
        && trusted_path_command("npx", workspace, home, authority)
        && trusted_path_command("node", workspace, home, authority)
        && workspace_typescript_is_bound(workspace, authority)
        && workspace_npx_typescript_runner_is_bound(workspace)
}

fn routine_context(
    context: &ShellExecutionContext,
    workspace: &Path,
    home: &Path,
    authority: &dyn DirectToolAuthority,
) -> bool {
    if !context.complete || ![2, 4, 5].contains(&context.segments.len()) {
        return false;
    }
    let directory = &context.segments[0];
    let compiler = &context.segments[1];
    if directory.directory_operation.as_deref() != Some("cd")
        || !directory.control_before.is_empty()
        || compiler.control_before != ["&&"]
        || compiler.effective_cwd.as_deref() != Some(workspace)
    {
        return false;
    }
    let mut tokens = compiler.tokens.as_slice();
    let stderr_merged = tokens.last().map(String::as_str) == Some("2>&1");
    if stderr_merged {
        tokens = &tokens[..tokens.len() - 1];
    }
    if tokens
        .first()
        .is_some_and(|t| t.starts_with("NODE_OPTIONS="))
    {
        if !safe_typecheck_node_options(&tokens[0]) {
            return false;
        }
        tokens = &tokens[1..];
    }
    if tokens.len() < 2
        || tokens[..2] != ["npx", "tsc"]
        || !typescript_no_emit_args_are_safe(&tokens[2..], workspace)
        || !compiler_is_bound(workspace, home, authority)
    {
        return false;
    }
    let mut observers = &context.segments[2..];
    if observers.is_empty() {
        return true;
    }
    if !stderr_merged {
        return false;
    }
    if observers.last().is_some_and(|s| s.control_before == [";"]) {
        let marker = observers.last().unwrap();
        if marker.tokens.len() != 2
            || marker.tokens[0] != "echo"
            || !static_marker_is_safe(&marker.tokens[1])
        {
            return false;
        }
        observers = &observers[..observers.len() - 1];
    }
    !observers.is_empty()
        && observers
            .iter()
            .all(|s| typescript_stream_observer_is_safe(s, workspace, home, authority))
        && observers
            .iter()
            .any(|s| s.tokens.first().is_some_and(|t| t == "head" || t == "tail"))
}

fn typescript_no_emit_args_are_safe(args: &[String], workspace: &Path) -> bool {
    const WRITE: &[&str] = &[
        "--build",
        "-b",
        "--composite",
        "--declaration",
        "--declarationMap",
        "--emitDeclarationOnly",
        "--generateCpuProfile",
        "--generateTrace",
        "--incremental",
        "--init",
        "--out",
        "--outDir",
        "--tsBuildInfoFile",
    ];
    const BOOLEAN: &[&str] = &[
        "--esModuleInterop",
        "--noEmit",
        "--skipLibCheck",
        "--strict",
    ];
    const PATH_FLAGS: &[&str] = &["--baseUrl", "--project", "-p", "--rootDir", "--typeRoots"];
    const VALUE: &[&str] = &[
        "--jsx",
        "--lib",
        "--module",
        "--moduleResolution",
        "--target",
        "--types",
        "--baseUrl",
        "--project",
        "-p",
        "--rootDir",
        "--typeRoots",
    ];
    if args.iter().filter(|s| s.as_str() == "--noEmit").count() != 1
        || args.iter().any(|s| {
            token_has_shell_dynamics(s)
                || s.contains(['<', '>'])
                || WRITE.contains(&s.as_str())
                || WRITE
                    .iter()
                    .any(|f| f.starts_with("--") && s.starts_with(&format!("{f}=")))
        })
    {
        return false;
    }
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg.starts_with('@') {
            return false;
        }
        if let Some((flag, value)) = arg.split_once('=') {
            if !VALUE.contains(&flag)
                || value.is_empty()
                || (flag == "--types" && !typescript_package_list_is_safe(value))
                || (PATH_FLAGS.contains(&flag) && !typescript_path_is_contained(value, workspace))
            {
                return false;
            }
            index += 1;
        } else if BOOLEAN.contains(&arg.as_str()) {
            if args
                .get(index + 1)
                .is_some_and(|v| matches!(v.to_lowercase().as_str(), "false" | "true"))
            {
                return false;
            }
            index += 1;
        } else if VALUE.contains(&arg.as_str()) {
            let Some(value) = args.get(index + 1) else {
                return false;
            };
            if (arg == "--types" && !typescript_package_list_is_safe(value))
                || (PATH_FLAGS.contains(&arg.as_str())
                    && !typescript_path_is_contained(value, workspace))
            {
                return false;
            }
            index += 2;
        } else {
            if arg.starts_with('-') || !typescript_path_is_contained(arg, workspace) {
                return false;
            }
            index += 1;
        }
    }
    true
}

fn typescript_path_is_contained(value: &str, workspace: &Path) -> bool {
    let candidate = if Path::new(value).is_absolute() {
        PathBuf::from(value)
    } else {
        workspace.join(value)
    };
    match (candidate.canonicalize(), workspace.canonicalize()) {
        (Ok(path), Ok(root)) => path.starts_with(root),
        _ => false,
    }
}

fn typescript_package_list_is_safe(value: &str) -> bool {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^(?:@[A-Za-z0-9][A-Za-z0-9._-]*/)?[A-Za-z0-9][A-Za-z0-9._-]*$").unwrap()
    });
    !value.is_empty() && value.split(',').all(|s| RE.is_match(s))
}

fn typescript_stream_observer_is_safe(
    segment: &ShellExecutionSegment,
    workspace: &Path,
    home: &Path,
    authority: &dyn DirectToolAuthority,
) -> bool {
    let tokens = &segment.tokens;
    if segment.control_before != ["|"]
        || tokens.is_empty()
        || tokens.iter().any(|s| token_has_shell_dynamics(s))
        || !trusted_path_command(&tokens[0], workspace, home, authority)
    {
        return false;
    }
    if tokens[0] == "grep" {
        let pattern = tokens.last().unwrap();
        return !pattern.is_empty()
            && !pattern.starts_with('-')
            && pattern.chars().count() <= 512
            && tokens
                .get(1..tokens.len().saturating_sub(1))
                .unwrap_or(&[])
                .iter()
                .all(|s| ["-a", "-E", "-i", "-v", "-aE", "-ai", "-iv"].contains(&s.as_str()));
    }
    if ["head", "tail"].contains(&tokens[0].as_str()) && tokens.len() == 2 {
        let count = tokens[1].strip_prefix('-').unwrap_or(&tokens[1]);
        return count.parse::<u32>().is_ok_and(|n| (1..=200).contains(&n))
            && count.chars().all(|c| c.is_ascii_digit());
    }
    false
}

fn diagnostic_path_filter(value: &str) -> bool {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^(?:[A-Za-z0-9_-]|\\\.)+(?:/(?:[A-Za-z0-9_-]|\\\.)+)*(?:\|(?:[A-Za-z0-9_-]|\\\.)+(?:/(?:[A-Za-z0-9_-]|\\\.)+)*)*$").unwrap()
    });
    RE.is_match(value)
}

fn static_marker_is_safe(value: &str) -> bool {
    static RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$").unwrap());
    RE.is_match(value)
}

fn safe_typecheck_node_options(value: &str) -> bool {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^NODE_OPTIONS=--max-old-space-size=([1-9][0-9]{2,4})$").unwrap()
    });
    RE.captures(value)
        .and_then(|c| c[1].parse::<u32>().ok())
        .is_some_and(|n| (256..=65536).contains(&n))
}

fn token_has_shell_dynamics(value: &str) -> bool {
    ["$", "`", "<(", ">(", "*", "?", "[", "\0", "\n"]
        .iter()
        .any(|s| value.contains(s))
}

fn node_execution_environment_is_configurable(
    workspace: &Path,
    home: &Path,
    authority: &dyn DirectToolAuthority,
) -> bool {
    authority.environment().iter().any(|(key, value)| {
        let key = key.to_lowercase();
        !value.is_empty()
            && (["node_options", "node_path"].contains(&key.as_str())
                || key.starts_with("npm_config_"))
    }) || [workspace.join(".npmrc"), home.join(".npmrc")]
        .iter()
        .any(|p| npm_configuration_can_load_code(p))
}

fn npm_configuration_can_load_code(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    let Ok(metadata) = path.metadata() else {
        return true;
    };
    if !metadata.is_file() || metadata.len() > 64 * 1024 {
        return true;
    }
    let Ok(text) = read_bounded_text(path, 64 * 1024) else {
        return true;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        let Some((key, _)) = line.split_once('=') else {
            return true;
        };
        if !npm_configuration_key_is_nonexecuting(&key.trim().to_lowercase().replace('_', "-")) {
            return true;
        }
    }
    false
}

fn npm_configuration_key_is_nonexecuting(key: &str) -> bool {
    [
        "always-auth",
        "audit",
        "color",
        "fund",
        "loglevel",
        "progress",
        "registry",
        "strict-ssl",
    ]
    .contains(&key)
        || (key.starts_with('@') && key.ends_with(":registry"))
        || (key.starts_with("//")
            && [
                ":-auth",
                ":-authtoken",
                ":-password",
                ":always-auth",
                ":email",
                ":username",
            ]
            .iter()
            .any(|s| key.ends_with(s)))
}

fn workspace_npx_typescript_runner_is_bound(workspace: &Path) -> bool {
    let bin = workspace.join("node_modules/.bin/tsc");
    let compiler = workspace.join("node_modules/typescript/bin/tsc");
    bin.is_symlink()
        && match (bin.canonicalize(), compiler.canonicalize()) {
            (Ok(bin), Ok(compiler)) => bin == compiler,
            _ => false,
        }
}
