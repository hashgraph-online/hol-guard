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
            collect_package_specs(&working_tokens[2..])
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
    if tokens.len() < 2 || !matches!(tokens[1].as_str(), "add" | "install") {
        return None;
    }
    Some(build_intent(
        "bun",
        "install",
        tokens,
        collect_package_specs(&tokens[2..])
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
