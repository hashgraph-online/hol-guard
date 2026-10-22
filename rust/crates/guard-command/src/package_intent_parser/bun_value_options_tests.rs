use super::*;

fn target_names(command: &str) -> Vec<String> {
    let intent = parse_package_intent(command, None, None, None, None)
        .expect("the install must produce a package intent");
    intent
        .targets
        .into_iter()
        .map(|target| target.package_name.expect("a named package"))
        .collect()
}

#[test]
fn bun_value_options_do_not_become_package_targets() {
    for options in [
        "--cwd /tmp/project/dashboard",
        "--cwd=/tmp/project/dashboard",
        "--cache-dir /tmp/bun-cache",
        "-c bunfig.toml",
        "--config bunfig.toml",
        "--backend copyfile",
        "--omit dev",
        "--linker isolated",
        "-F app",
        "--filter app",
    ] {
        let command = format!("bun add {options} evil-pkg");
        assert_eq!(target_names(&command), ["evil-pkg"], "{command}");
    }
}

#[test]
fn a_bun_lockfile_install_in_another_directory_names_no_package() {
    // #4808: the directory after --cwd was reviewed as `<dir>@latest`.
    for command in [
        "bun install --cwd /tmp/project/dashboard --frozen-lockfile --ignore-scripts",
        "bun install --frozen-lockfile --cwd /tmp/project/dashboard",
    ] {
        assert!(target_names(command).is_empty(), "{command}");
    }
}

#[test]
fn yarn_cwd_after_the_subcommand_is_a_directory() {
    assert_eq!(
        target_names("yarn add --cwd /tmp/project evil-pkg"),
        ["evil-pkg"]
    );
}

#[test]
fn managers_without_a_cwd_value_still_review_the_next_word() {
    // npm does not read `--cwd`'s next token as its value, so skipping it
    // would let a package go unevaluated.
    assert_eq!(target_names("npm install --cwd evil-pkg"), ["evil-pkg"]);
}

fn write_project(dir: &std::path::Path, manifest: &str, lock_name: &str, lock_body: &str) {
    std::fs::create_dir_all(dir).expect("project directory");
    std::fs::write(dir.join("package.json"), manifest).expect("manifest");
    std::fs::write(dir.join(lock_name), lock_body).expect("lockfile");
}

struct TempTree(std::path::PathBuf);

impl TempTree {
    fn new() -> Self {
        let nanos = crate::unique_nanos::unique_nanos();
        let path =
            std::env::temp_dir().join(format!("hol-guard-bun-cwd-{nanos}-{}", std::process::id()));
        std::fs::create_dir_all(&path).expect("temp tree");
        Self(path)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(unix)]
fn lockfile_digest(
    workspace: &std::path::Path,
    home: &std::path::Path,
    metadata: &serde_json::Map<String, serde_json::Value>,
) -> String {
    use crate::package_context_build::{build_package_execution_context, BuildInput};
    let workspace = workspace
        .canonicalize()
        .expect("workspace")
        .to_string_lossy()
        .into_owned();
    let home = home
        .canonicalize()
        .expect("home")
        .to_string_lossy()
        .into_owned();
    let environment = std::collections::BTreeMap::new();
    let args = Vec::new();
    let built = build_package_execution_context(&BuildInput {
        workspace_dir: &workspace,
        metadata,
        executable: Some("bun"),
        executable_args: &args,
        environment: &environment,
        process_cwd: &workspace,
        process_home: &home,
        process_home_env: None,
        process_path: None,
    })
    .expect("package context");
    built
        .components
        .iter()
        .find(|component| component.name == "manifests_and_lockfiles")
        .expect("lockfile component")
        .digest
        .clone()
}

#[cfg(unix)]
#[test]
fn bun_cwd_lockfile_inside_the_workspace_is_the_one_that_is_hashed() {
    let tree = TempTree::new();
    let workspace = tree.0.join("workspace");
    let app = workspace.join("app");
    write_project(&workspace, "{}\n", "bun.lock", "caller-lock\n");
    write_project(&app, "{\"name\":\"app\"}\n", "bun.lock", "app-lock-v1\n");
    for command in [
        "bun install --cwd app --frozen-lockfile",
        "bun install --cwd=app --frozen-lockfile",
        "bun --cwd app install --frozen-lockfile",
    ] {
        let intent = parse_package_intent(command, Some(&workspace), None, None, None)
            .expect("bun install intent");
        assert!(intent.targets.is_empty(), "{command}");
        assert_eq!(intent.lockfile_paths, ["app/bun.lock"], "{command}");
        assert_eq!(intent.manifest_paths, ["app/package.json"], "{command}");
        assert!(!intent
            .notes
            .iter()
            .any(|note| note == PACKAGE_CWD_UNRESOLVED_NOTE));
    }

    let intent = parse_package_intent(
        "bun install --cwd app --frozen-lockfile",
        Some(&workspace),
        None,
        None,
        None,
    )
    .expect("intent");
    let artifact = build_package_request_artifact("codex", &intent, "hol-guard.toml", "project");
    let metadata = artifact.metadata.as_object().expect("metadata");
    let home = tree.0.join("home");
    std::fs::create_dir_all(&home).expect("home");
    let before = lockfile_digest(&workspace, &home, metadata);
    std::fs::write(app.join("bun.lock"), "app-lock-tampered\n").expect("tamper");
    let after = lockfile_digest(&workspace, &home, metadata);
    assert_ne!(
        before, after,
        "the lockfile in --cwd must be part of the evaluation"
    );
}

// Windows canonical paths carry `\\?\` and backslashes, which `--cwd`
// resolution refuses, so the directory stays unresolved there.
#[cfg(unix)]
#[test]
fn yarn_cwd_lockfile_is_read_from_that_directory() {
    let tree = TempTree::new();
    let workspace = tree.0.join("workspace");
    let app = workspace.join("app");
    write_project(&workspace, "{}\n", "yarn.lock", "caller\n");
    write_project(&app, "{\"name\":\"app\"}\n", "yarn.lock", "app\n");
    let intent = parse_package_intent(
        "yarn add --cwd app left-pad",
        Some(&workspace),
        None,
        None,
        None,
    )
    .expect("yarn add intent");
    assert_eq!(target_names("yarn add --cwd app left-pad"), ["left-pad"]);
    assert_eq!(intent.lockfile_paths, ["app/yarn.lock"]);
    assert_eq!(intent.manifest_paths, ["app/package.json"]);
}

#[test]
fn bun_cwd_outside_the_workspace_is_not_an_empty_allow() {
    let tree = TempTree::new();
    let workspace = tree.0.join("workspace");
    let outside = tree.0.join("outside");
    write_project(&workspace, "{}\n", "bun.lock", "caller-lock\n");
    write_project(
        &outside,
        "{\"name\":\"outside\"}\n",
        "bun.lock",
        "tampered-outside\n",
    );
    let outside = outside.canonicalize().expect("outside");
    let command = format!("bun install --cwd {} --frozen-lockfile", outside.display());
    let intent = parse_package_intent(&command, Some(&workspace), None, None, None)
        .expect("outside cwd is still an install");
    assert!(intent.targets.is_empty());
    assert!(
        intent.lockfile_paths.is_empty(),
        "caller lockfile must not stand in"
    );
    assert!(intent.manifest_paths.is_empty());
    assert!(intent
        .notes
        .iter()
        .any(|note| note == PACKAGE_CWD_UNRESOLVED_NOTE));

    let artifact = build_package_request_artifact("codex", &intent, "hol-guard.toml", "project");
    let evaluation = crate::supply_chain_package_eval::empty_package_material_result(
        &artifact, None, None, "intent", None,
    );
    assert_eq!(evaluation.decision, "ask");
    assert_ne!(evaluation.policy_action, "allow");
}

fn held(
    artifact: &GuardArtifact,
    decision: &str,
) -> crate::supply_chain_package_eval::PackageEvalResult {
    let mut evaluation = crate::supply_chain_package_eval::empty_package_material_result(
        artifact, None, None, "intent", None,
    );
    evaluation.decision = decision.to_string();
    evaluation.policy_action = decision.to_string();
    evaluation.reasons.clear();
    let mut package = serde_json::Map::new();
    package.insert(
        "name".to_string(),
        serde_json::Value::String("left-pad".into()),
    );
    package.insert(
        "decision".to_string(),
        serde_json::Value::String(decision.into()),
    );
    evaluation.packages.push(package);
    crate::supply_chain_package_eval::hold_unresolved_package_cwd(artifact, evaluation)
}

#[test]
fn bun_add_outside_the_workspace_keeps_the_package_and_stays_in_review() {
    let tree = TempTree::new();
    let workspace = tree.0.join("workspace");
    let outside = tree.0.join("outside");
    write_project(&workspace, "{}\n", "bun.lock", "caller-lock\n");
    write_project(
        &outside,
        "{\"name\":\"outside\"}\n",
        "bun.lock",
        "tampered\n",
    );
    let outside = outside.canonicalize().expect("outside");
    let command = format!("bun add --cwd {} left-pad", outside.display());
    let intent =
        parse_package_intent(&command, Some(&workspace), None, None, None).expect("bun add intent");
    assert_eq!(
        intent
            .targets
            .iter()
            .map(|target| target.package_name.clone().expect("named"))
            .collect::<Vec<_>>(),
        ["left-pad"]
    );
    assert!(intent.lockfile_paths.is_empty());
    assert!(intent
        .notes
        .iter()
        .any(|note| note == PACKAGE_CWD_UNRESOLVED_NOTE));
    let artifact = build_package_request_artifact("codex", &intent, "hol-guard.toml", "project");
    let raised = held(&artifact, "allow");
    assert_eq!(raised.decision, "ask");
    assert_ne!(raised.policy_action, "allow");
    assert_eq!(raised.packages[0]["decision"], "ask");
    assert!(raised.reasons.iter().any(|reason| {
        reason.get("code").and_then(|value| value.as_str()) == Some("package_cwd_unresolved")
    }));
    let monitored = held(&artifact, "monitor");
    assert_eq!(monitored.decision, "ask");
    assert_eq!(monitored.packages[0]["decision"], "ask");
    assert_eq!(
        monitored
            .to_cache_dict()
            .get("decision")
            .and_then(|value| value.as_str()),
        Some("ask")
    );
    let blocked = held(&artifact, "block");
    assert_eq!(blocked.decision, "block");
    assert_eq!(blocked.packages[0]["decision"], "block");
}

#[test]
fn a_chained_install_keeps_an_unresolved_cwd_beside_the_other_lockfile() {
    let tree = TempTree::new();
    let workspace = tree.0.join("workspace");
    let outside = tree.0.join("outside");
    write_project(
        &workspace,
        "{}\n",
        "package-lock.json",
        "{\"lockfileVersion\":3}\n",
    );
    write_project(
        &outside,
        "{\"name\":\"outside\"}\n",
        "bun.lock",
        "tampered\n",
    );
    let outside = outside.canonicalize().expect("outside");
    let command = format!(
        "bun install --cwd {} --frozen-lockfile; npm ci",
        outside.display()
    );
    let intent = parse_package_intent(&command, Some(&workspace), None, None, None)
        .expect("chained install");
    assert!(intent
        .notes
        .iter()
        .any(|note| note == PACKAGE_CWD_UNRESOLVED_NOTE));
    assert!(intent
        .lockfile_paths
        .iter()
        .any(|path| path == "package-lock.json"));
    assert!(intent
        .lockfile_paths
        .iter()
        .all(|path| !path.contains("tampered") && path != "bun.lock"));
    let artifact = build_package_request_artifact("codex", &intent, "hol-guard.toml", "project");
    assert_eq!(held(&artifact, "monitor").decision, "ask");
}
