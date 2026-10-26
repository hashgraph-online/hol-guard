use super::*;

// package_intent_parser.py `_parse_cargo_intent`
pub(super) fn parse_cargo_intent(
    tokens: &[String],
    workspace: Option<&Path>,
) -> Option<PackageIntent> {
    if tokens.len() < 2 || !matches!(tokens[1].as_str(), "add" | "install") {
        return None;
    }
    let mut source_url = option_value(tokens, "--path").map(|value| format!("file:{value}"));
    if source_url.is_none() {
        source_url = option_value(tokens, "--git");
    }
    let targets = collect_specs(
        &tokens[2..],
        &[
            "--branch",
            "--git",
            "--index",
            "--path",
            "--registry",
            "--rev",
            "--tag",
        ],
    )
    .iter()
    .map(|spec| version_target("cargo", spec, source_url.as_deref()))
    .collect();
    Some(build_intent(
        "cargo",
        "install",
        tokens,
        targets,
        workspace,
        &["Cargo.toml".to_owned()],
        &["Cargo.lock".to_owned()],
        &[],
        &[],
    ))
}

// package_intent_parser.py `_parse_go_intent`
pub(super) fn parse_go_intent(
    tokens: &[String],
    workspace: Option<&Path>,
) -> Option<PackageIntent> {
    if tokens.len() < 2 || !matches!(tokens[1].as_str(), "get" | "install") {
        return None;
    }
    Some(build_intent(
        "go",
        "install",
        tokens,
        collect_package_specs(&tokens[2..])
            .iter()
            .map(|s| version_target("go", s, None))
            .collect(),
        workspace,
        &["go.mod".to_owned()],
        &[],
        &[],
        &[],
    ))
}

// package_intent_parser.py `_parse_maven_intent`
pub(super) fn parse_maven_intent(
    tokens: &[String],
    workspace: Option<&Path>,
) -> Option<PackageIntent> {
    let mut artifact_value = property_value(tokens, "artifact");
    if artifact_value.is_none() {
        let includes = property_value(tokens, "includes");
        let dep_version = property_value(tokens, "depVersion");
        artifact_value = match (includes, dep_version) {
            (Some(includes), Some(dep_version)) => Some(format!("{includes}:{dep_version}")),
            _ => None,
        };
    }
    let artifact_value = artifact_value?;
    Some(build_intent(
        "maven",
        "install",
        tokens,
        vec![coordinate_target("maven", &artifact_value)],
        workspace,
        &["pom.xml".to_owned()],
        &[],
        &[],
        &[],
    ))
}

// package_intent_parser.py `_parse_gradle_intent`
pub(super) fn parse_gradle_intent(
    tokens: &[String],
    workspace: Option<&Path>,
) -> Option<PackageIntent> {
    let dependency_value = option_value(tokens, "--dependency")?;
    Some(build_intent(
        "gradle",
        "install",
        tokens,
        vec![coordinate_target("maven", &dependency_value)],
        workspace,
        &["build.gradle".to_owned(), "build.gradle.kts".to_owned()],
        &[],
        &[],
        &[],
    ))
}

// package_intent_parser.py `_parse_composer_intent`
pub(super) fn parse_composer_intent(
    tokens: &[String],
    workspace: Option<&Path>,
) -> Option<PackageIntent> {
    if tokens.len() < 2 || !matches!(tokens[1].as_str(), "require" | "install" | "update") {
        return None;
    }
    Some(build_intent(
        "composer",
        "install",
        tokens,
        collect_package_specs(&tokens[2..])
            .iter()
            .map(|s| composer_target(s))
            .collect(),
        workspace,
        &["composer.json".to_owned()],
        &["composer.lock".to_owned()],
        &[],
        &[],
    ))
}

// package_intent_parser.py `_parse_bundle_intent`
pub(super) fn parse_bundle_intent(
    tokens: &[String],
    workspace: Option<&Path>,
) -> Option<PackageIntent> {
    if tokens.len() < 2 {
        return None;
    }
    if tokens[1] == "install" {
        return Some(build_intent(
            "bundle",
            "sync",
            tokens,
            Vec::new(),
            workspace,
            &["Gemfile".to_owned()],
            &["Gemfile.lock".to_owned()],
            &[],
            &[],
        ));
    }
    if tokens[1] != "add" || tokens.len() < 3 {
        return None;
    }
    let version = option_value(tokens, "--version");
    Some(build_intent(
        "bundle",
        "install",
        tokens,
        vec![PackageIntentTarget {
            ecosystem: "rubygems".to_owned(),
            package_name: Some(tokens[2].clone()),
            raw_spec: tokens[2].clone(),
            requested_specifier: version,
            ..Default::default()
        }],
        workspace,
        &["Gemfile".to_owned()],
        &["Gemfile.lock".to_owned()],
        &[],
        &[],
    ))
}

// package_intent_parser.py `_parse_gem_intent`
pub(super) fn parse_gem_intent(
    tokens: &[String],
    workspace: Option<&Path>,
) -> Option<PackageIntent> {
    if tokens.len() < 3 || tokens[1] != "install" {
        return None;
    }
    let version = option_value(tokens, "-v").or_else(|| option_value(tokens, "--version"));
    Some(build_intent(
        "gem",
        "install",
        tokens,
        vec![PackageIntentTarget {
            ecosystem: "rubygems".to_owned(),
            package_name: Some(tokens[2].clone()),
            raw_spec: tokens[2].clone(),
            requested_specifier: version,
            ..Default::default()
        }],
        workspace,
        &[],
        &[],
        &[],
        &[],
    ))
}

// package_intent_parser.py `_parse_system_package_intent`
pub(super) fn parse_system_package_intent(
    tokens: &[String],
    workspace: Option<&Path>,
) -> Option<PackageIntent> {
    if tokens.len() < 2 {
        return None;
    }
    let name = command_name(&tokens[0]);
    let verb = tokens[1].to_lowercase();
    let install_verbs: &[&str] = match name.as_str() {
        "apk" => &["add"],
        "apt" | "apt-get" | "dnf" | "yum" => &["install"],
        "brew" => &["install"],
        "pacman" => &["-s", "-sy", "-syu", "-suy"],
        "zypper" => &["install", "in"],
        _ => &[],
    };
    if !install_verbs.contains(&verb.as_str()) {
        return None;
    }
    let targets = collect_specs(&tokens[2..], &["--repo", "--repository", "-c"])
        .iter()
        .map(|spec| PackageIntentTarget {
            ecosystem: "system".to_owned(),
            package_name: Some(spec.clone()),
            raw_spec: spec.clone(),
            ..Default::default()
        })
        .collect();
    Some(build_intent(
        &name,
        "install",
        tokens,
        targets,
        workspace,
        &[],
        &[],
        &[],
        &[],
    ))
}

// package_intent_parser.py `_parse_helm_intent`
pub(super) fn parse_helm_intent(
    tokens: &[String],
    workspace: Option<&Path>,
) -> Option<PackageIntent> {
    if tokens.len() < 4 || tokens[1] != "install" {
        return None;
    }
    let chart = first_positional(&tokens[3..], &["--version", "--repo", "-n", "--namespace"])
        .unwrap_or_else(|| tokens[3].clone());
    let version = option_value(tokens, "--version");
    let target = PackageIntentTarget {
        ecosystem: "unsupported".to_owned(),
        package_name: Some(chart.clone()),
        raw_spec: chart,
        requested_specifier: version,
        ..Default::default()
    };
    Some(build_intent(
        "helm",
        "install",
        tokens,
        vec![target],
        workspace,
        &[],
        &[],
        &[],
        &[],
    ))
}
