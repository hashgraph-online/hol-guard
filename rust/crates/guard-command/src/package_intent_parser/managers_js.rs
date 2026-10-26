use super::*;

// package_intent_parser.py `_parse_npm_intent`
pub(super) fn parse_npm_intent(
    tokens: &[String],
    workspace: Option<&Path>,
) -> Option<PackageIntent> {
    let working_tokens = strip_package_manager_global_options(tokens);
    if working_tokens.len() < 2 {
        return None;
    }
    if matches!(
        working_tokens[1].as_str(),
        "install" | "i" | "add" | "update"
    ) {
        return Some(build_intent(
            "npm",
            "install",
            tokens,
            collect_package_specs(&working_tokens[2..])
                .iter()
                .map(|s| js_target(s))
                .collect(),
            workspace,
            &["package.json".to_owned()],
            &["package-lock.json".to_owned()],
            &[],
            &[],
        ));
    }
    if working_tokens[1] == "ci"
        || (working_tokens.len() >= 3 && working_tokens[1] == "audit" && working_tokens[2] == "fix")
    {
        return Some(build_intent(
            "npm",
            "sync",
            tokens,
            Vec::new(),
            workspace,
            &["package.json".to_owned()],
            &["package-lock.json".to_owned()],
            &[],
            &[],
        ));
    }
    if matches!(working_tokens[1].as_str(), "exec" | "x") {
        return parse_exec_intent_default(&working_tokens, workspace);
    }
    None
}

// package_intent_parser.py `_parse_pnpm_intent`
pub(super) fn parse_pnpm_intent(
    tokens: &[String],
    workspace: Option<&Path>,
) -> Option<PackageIntent> {
    let working_tokens = strip_package_manager_global_options(tokens);
    if working_tokens.len() < 2 {
        return None;
    }
    if matches!(working_tokens[1].as_str(), "add" | "install" | "i") {
        return Some(build_intent(
            "pnpm",
            "install",
            tokens,
            collect_specs(&working_tokens[2..], &["--filter", "-F"])
                .iter()
                .map(|s| js_target(s))
                .collect(),
            workspace,
            &["package.json".to_owned(), "pnpm-workspace.yaml".to_owned()],
            &["pnpm-lock.yaml".to_owned()],
            &[],
            &[],
        ));
    }
    if working_tokens[1] == "dlx" {
        return parse_exec_intent_default(&working_tokens, workspace);
    }
    None
}

// package_intent_parser.py `_parse_yarn_intent`
pub(super) fn parse_yarn_intent(
    tokens: &[String],
    workspace: Option<&Path>,
) -> Option<PackageIntent> {
    let mut notes: Vec<String> = Vec::new();
    let mut working_tokens = strip_package_manager_global_options(tokens);
    if working_tokens.len() >= 4 && working_tokens[1] == "workspace" {
        notes.push(format!("workspace:{}", working_tokens[2]));
        let mut next = vec![working_tokens[0].clone()];
        next.extend_from_slice(&working_tokens[3..]);
        working_tokens = next;
    }
    if working_tokens.len() < 2 {
        return None;
    }
    if matches!(working_tokens[1].as_str(), "add" | "install" | "up") {
        return Some(build_intent(
            "yarn",
            "install",
            tokens,
            collect_package_specs_with(&working_tokens[2..], YARN_VALUE_OPTIONS)
                .iter()
                .map(|s| js_target(s))
                .collect(),
            workspace,
            &["package.json".to_owned()],
            &["yarn.lock".to_owned()],
            &[],
            &notes,
        ));
    }
    if working_tokens[1] == "dlx" {
        return parse_exec_intent_default(&working_tokens, workspace);
    }
    None
}

// package_intent_parser.py `_parse_bun_intent`
pub(super) fn parse_bun_intent(
    tokens: &[String],
    workspace: Option<&Path>,
) -> Option<PackageIntent> {
    let verb_index = bun_verb_index(tokens)?;
    Some(build_intent(
        "bun",
        "install",
        tokens,
        collect_package_specs_with(&tokens[verb_index + 1..], BUN_VALUE_OPTIONS)
            .iter()
            .map(|s| js_target(s))
            .collect(),
        workspace,
        &["package.json".to_owned()],
        &["bun.lock".to_owned(), "bun.lockb".to_owned()],
        &[],
        &[],
    ))
}

/// `add` / `install` after leading Bun options, including `bun --cwd <dir> install`.
fn bun_verb_index(tokens: &[String]) -> Option<usize> {
    if tokens.len() < 2 {
        return None;
    }
    let mut index = 1usize;
    while index < tokens.len() {
        let token = tokens[index].as_str();
        if matches!(token, "add" | "install") {
            return Some(index);
        }
        if token == "--" || !token.starts_with('-') {
            return None;
        }
        if let Some(value) = token.strip_prefix("--cwd=") {
            if value.is_empty() {
                return None;
            }
            index += 1;
            continue;
        }
        if BUN_VALUE_OPTIONS.contains(&token) {
            let value = tokens.get(index + 1)?;
            if value.is_empty() || value.starts_with('-') {
                return None;
            }
            index += 2;
            continue;
        }
        index += 1;
    }
    None
}

/// Where a Bun or Yarn `--cwd` sits relative to the evaluation workspace.
pub(super) enum ManagerCwd {
    /// This command does not select a package directory.
    NotDeclared,
    /// The directory exists inside the evaluation workspace.
    Inside(PathBuf),
    /// `--cwd` is present, but its directory cannot be evaluated here.
    Unresolved,
}

/// Resolve Bun and Yarn `--cwd` the way package-directory flags do, then keep
/// it only when the directory is inside the evaluation workspace.
pub(super) fn manager_install_cwd(
    manager: &str,
    tokens: &[String],
    context_complete: bool,
    effective_cwd: Option<&Path>,
    evaluation_workspace: Option<&Path>,
) -> ManagerCwd {
    if !matches!(manager, "bun" | "yarn") {
        return ManagerCwd::NotDeclared;
    }
    let declared = match declared_package_cwd(tokens) {
        DeclaredCwd::Absent => return ManagerCwd::NotDeclared,
        DeclaredCwd::Invalid => {
            return if evaluation_workspace.is_some() {
                ManagerCwd::Unresolved
            } else {
                ManagerCwd::NotDeclared
            };
        }
        DeclaredCwd::Value(value) => value,
    };
    let Some(evaluation_workspace) = evaluation_workspace else {
        return ManagerCwd::NotDeclared;
    };
    if !context_complete {
        return ManagerCwd::Unresolved;
    }
    let Some(base) = effective_cwd else {
        return ManagerCwd::Unresolved;
    };
    let Some(base) = base.to_str() else {
        return ManagerCwd::Unresolved;
    };
    let Some(resolved) = resolve_package_directory(declared, base) else {
        return ManagerCwd::Unresolved;
    };
    let workspace_root = expand_resolve(evaluation_workspace);
    if resolved.starts_with(&workspace_root) {
        ManagerCwd::Inside(resolved)
    } else {
        ManagerCwd::Unresolved
    }
}

enum DeclaredCwd<'a> {
    Absent,
    Value(&'a str),
    Invalid,
}

/// The single `--cwd <dir>` or `--cwd=<dir>` on a Bun or Yarn command.
fn declared_package_cwd(tokens: &[String]) -> DeclaredCwd<'_> {
    let mut found: Option<&str> = None;
    let mut index = 1usize;
    while index < tokens.len() {
        let token = tokens[index].as_str();
        if token == "--" {
            break;
        }
        if let Some(value) = token.strip_prefix("--cwd=") {
            if found.is_some() || value.is_empty() {
                return DeclaredCwd::Invalid;
            }
            found = Some(value);
            index += 1;
            continue;
        }
        if token == "--cwd" {
            let Some(value) = tokens.get(index + 1) else {
                return DeclaredCwd::Invalid;
            };
            if found.is_some() || value.is_empty() || value.starts_with('-') {
                return DeclaredCwd::Invalid;
            }
            found = Some(value.as_str());
            index += 2;
            continue;
        }
        index += 1;
    }
    match found {
        Some(value) => DeclaredCwd::Value(value),
        None => DeclaredCwd::Absent,
    }
}

/// Same directory resolution as `pretool/package_directory_flags.rs`: lexical
/// join onto the physical cwd, then the real directory.
fn resolve_package_directory(value: &str, cwd: &str) -> Option<PathBuf> {
    if value.starts_with(['-', '~']) || value.contains("//") || !plain_directory_word(value) {
        return None;
    }
    let base = std::fs::canonicalize(cwd).ok()?;
    let directory = std::fs::canonicalize(lexical_directory(&base.join(value))?).ok()?;
    let directory = directory
        .to_str()
        .filter(|path| plain_directory_word(path))?;
    Path::new(directory)
        .is_dir()
        .then(|| PathBuf::from(directory))
}

fn plain_directory_word(word: &str) -> bool {
    !word.is_empty()
        && word.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'/' | b'.' | b'_' | b'-' | b'@' | b'+' | b'=' | b':' | b','
                )
        })
}

fn lexical_directory(path: &Path) -> Option<PathBuf> {
    let mut resolved = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::RootDir => resolved.push("/"),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !resolved.pop() {
                    return None;
                }
            }
            std::path::Component::Normal(part) => resolved.push(part),
            std::path::Component::Prefix(_) => return None,
        }
    }
    resolved.is_absolute().then_some(resolved)
}
