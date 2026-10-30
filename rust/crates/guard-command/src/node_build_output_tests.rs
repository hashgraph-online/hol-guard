use super::*;
use serde_json::json;

fn project(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "guard-node-build-{name}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default()
    ));
    std::fs::create_dir_all(root.join("app")).expect("project");
    std::fs::write(root.join("package.json"), "{}").expect("manifest");
    root
}

fn refusal(reply: &Value) -> String {
    assert_eq!(reply["reason_code"], REASON, "{reply}");
    reply["message"].as_str().expect("message").to_owned()
}

fn root_request(workspace: &Path, cwd: &Path, arguments: &[&str]) -> Value {
    evaluate(
        "node_build_output_root",
        &json!({
            "workspace": workspace.to_string_lossy(),
            "cwd": cwd.to_string_lossy(),
            "arguments": arguments,
        }),
    )
    .expect("answered")
}

#[test]
fn an_unrelated_operation_is_left_to_the_next_reader() {
    assert!(evaluate("normalized_command", &json!({})).is_none());
}

#[test]
fn the_default_build_writes_the_working_directory_dist() {
    let workspace = project("default");
    let reply = root_request(&workspace, &workspace, &["build"]);
    assert_eq!(
        reply["value"].as_str().map(PathBuf::from),
        Some(workspace.join("dist"))
    );
}

#[test]
fn a_package_below_the_workspace_builds_into_its_own_dist() {
    let workspace = project("package");
    let app = workspace.join("app");
    std::fs::write(app.join("package.json"), "{}").expect("manifest");
    let reply = root_request(&workspace, &app, &["build"]);
    assert_eq!(
        reply["value"].as_str().map(PathBuf::from),
        Some(app.join("dist"))
    );
}

#[test]
fn a_directory_below_the_workspace_without_a_manifest_is_not_a_package() {
    let workspace = project("unowned");
    let reply = root_request(&workspace, &workspace.join("app"), &["build"]);
    assert_eq!(
        refusal(&reply),
        "Build output must be a dedicated generated directory."
    );
}

#[test]
fn the_command_line_output_directory_wins_over_the_default() {
    let workspace = project("outdir");
    for arguments in [
        vec!["build", "--outDir", "build"],
        vec!["build", "--outDir=build"],
    ] {
        let reply = root_request(&workspace, &workspace, &arguments);
        assert_eq!(
            reply["value"].as_str().map(PathBuf::from),
            Some(workspace.join("build")),
            "{arguments:?}"
        );
    }
}

#[test]
fn an_empty_output_directory_names_nothing_and_leaves_the_default() {
    let workspace = project("empty-outdir");
    let reply = root_request(&workspace, &workspace, &["build", "--outDir="]);
    assert_eq!(
        reply["value"].as_str().map(PathBuf::from),
        Some(workspace.join("dist"))
    );
}

#[test]
fn an_output_directory_with_no_value_refuses() {
    let workspace = project("missing-outdir");
    let reply = root_request(&workspace, &workspace, &["build", "--outDir"]);
    assert_eq!(refusal(&reply), "Missing output directory.");
}

#[test]
fn a_config_with_no_file_refuses() {
    let workspace = project("missing-config");
    for arguments in [
        vec!["build", "--config"],
        vec!["build", "-c", "--mode"],
        vec!["build", "--config="],
    ] {
        let reply = root_request(&workspace, &workspace, &arguments);
        assert_eq!(refusal(&reply), "Missing Vite config.", "{arguments:?}");
    }
}

#[test]
fn a_named_config_is_read_instead_of_the_default_one() {
    // Naming a config Vite cannot load leaves the build its own default, and
    // the unverifiable directory the default config declares is not read in
    // its place.
    let workspace = project("named-config");
    std::fs::write(
        workspace.join("vite.config.ts"),
        "export default { build: { outDir: process.env.OUT } }",
    )
    .expect("config");
    let reply = root_request(
        &workspace,
        &workspace,
        &["build", "--config", "vite.alt.ts"],
    );
    assert_eq!(
        reply["value"].as_str().map(PathBuf::from),
        Some(workspace.join("dist"))
    );
}

#[test]
fn a_named_config_declares_an_output_the_check_admits() {
    // The admissibility check reads the config the build loads. Reading the
    // default one beside it refused the directory `vite.alt.ts` declares.
    let workspace = project("named-config-output");
    std::fs::write(
        workspace.join("vite.config.ts"),
        "export default { build: { outDir: 'dist' } }",
    )
    .expect("default config");
    std::fs::write(
        workspace.join("vite.alt.ts"),
        "export default { build: { outDir: 'release' } }",
    )
    .expect("named config");
    let arguments = ["build", "--config", "vite.alt.ts"];
    let reply = root_request(&workspace, &workspace, &arguments);
    assert_eq!(
        reply["value"].as_str().map(PathBuf::from),
        Some(workspace.join("release"))
    );
    let reply = evaluate(
        "node_build_output_admissible",
        &json!({
            "workspace": workspace.to_string_lossy(),
            "cwd": workspace.to_string_lossy(),
            "path": workspace.join("release").to_string_lossy(),
            "arguments": arguments,
        }),
    )
    .expect("answered");
    assert_eq!(reply["value"], json!(true), "{reply}");
}

#[test]
fn an_unverifiable_default_config_does_not_refuse_a_named_one() {
    // The build never loads the default config, so what it declares is not
    // the reading that decides this build's output.
    let workspace = project("named-over-unverified");
    std::fs::write(
        workspace.join("vite.config.ts"),
        "export default { build: { outDir: process.env.OUT } }",
    )
    .expect("default config");
    std::fs::write(
        workspace.join("vite.alt.ts"),
        "export default { build: { outDir: 'release' } }",
    )
    .expect("named config");
    let reply = root_request(
        &workspace,
        &workspace,
        &["build", "--config", "vite.alt.ts"],
    );
    assert_eq!(
        reply["value"].as_str().map(PathBuf::from),
        Some(workspace.join("release"))
    );
}

#[test]
fn a_recheck_whose_words_name_no_config_file_refuses() {
    let workspace = project("recheck-missing-config");
    let reply = evaluate(
        "node_build_output_admissible",
        &json!({
            "workspace": workspace.to_string_lossy(),
            "cwd": workspace.to_string_lossy(),
            "path": workspace.join("dist").to_string_lossy(),
            "arguments": ["build", "--config"],
        }),
    )
    .expect("answered");
    assert_eq!(refusal(&reply), "Missing Vite config.");
}

#[test]
fn a_recheck_whose_words_are_not_the_commands_own_refuses() {
    let workspace = project("recheck-bad-words");
    let reply = evaluate(
        "node_build_output_admissible",
        &json!({
            "workspace": workspace.to_string_lossy(),
            "cwd": workspace.to_string_lossy(),
            "path": workspace.join("dist").to_string_lossy(),
            "arguments": ["build", 4],
        }),
    )
    .expect("answered");
    assert_eq!(
        refusal(&reply),
        "HOL Guard could not read the project this build writes into."
    );
}

#[test]
fn the_default_config_declares_the_output_when_the_command_names_none() {
    let workspace = project("default-config");
    std::fs::write(
        workspace.join("vite.config.ts"),
        "export default { build: { outDir: 'release' } }",
    )
    .expect("config");
    let reply = root_request(&workspace, &workspace, &["build"]);
    assert_eq!(
        reply["value"].as_str().map(PathBuf::from),
        Some(workspace.join("release"))
    );
}

#[test]
fn a_config_output_the_reader_cannot_verify_refuses() {
    let workspace = project("unverified-config");
    std::fs::write(
        workspace.join("vite.config.ts"),
        "export default { build: { outDir: process.env.OUT } }",
    )
    .expect("config");
    let reply = root_request(&workspace, &workspace, &["build"]);
    assert_eq!(refusal(&reply), UNVERIFIED);
}

#[test]
fn a_command_line_output_directory_skips_an_unverifiable_config() {
    let workspace = project("outdir-over-config");
    std::fs::write(
        workspace.join("vite.config.ts"),
        "export default { build: { outDir: process.env.OUT } }",
    )
    .expect("config");
    let reply = root_request(&workspace, &workspace, &["build", "--outDir", "build"]);
    assert_eq!(
        reply["value"].as_str().map(PathBuf::from),
        Some(workspace.join("build"))
    );
}

#[test]
fn build_outputs_cannot_grant_source_or_host_writes() {
    let workspace = project("source-writes");
    for name in ["src", ".git", ".env", "../outside", "."] {
        let reply = root_request(&workspace, &workspace, &["build", "--outDir", name]);
        assert_eq!(
            refusal(&reply),
            "Build output must be a dedicated generated directory.",
            "{name}"
        );
    }
}

#[test]
fn a_build_cannot_write_through_a_link_into_the_project() {
    let workspace = project("linked-output");
    #[cfg(unix)]
    std::os::unix::fs::symlink(workspace.join("app"), workspace.join("dist")).expect("link");
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(workspace.join("app"), workspace.join("dist")).expect("link");
    let reply = root_request(&workspace, &workspace, &["build"]);
    assert_eq!(
        refusal(&reply),
        "Build output must be a dedicated generated directory."
    );
}

#[test]
fn an_output_name_already_held_by_a_file_refuses() {
    let workspace = project("file-output");
    std::fs::write(workspace.join("dist"), "report").expect("file");
    let reply = root_request(&workspace, &workspace, &["build"]);
    assert_eq!(refusal(&reply), "Build output is not a directory.");
}

#[test]
fn existing_protected_data_in_the_output_refuses() {
    let workspace = project("protected");
    let output = workspace.join("dist");
    std::fs::create_dir_all(&output).expect("output");
    std::fs::write(output.join(".env"), "TOKEN=x").expect("secret");
    let reply = root_request(&workspace, &workspace, &["build"]);
    assert_eq!(refusal(&reply), "Build output contains protected data.");
}

#[test]
fn existing_links_in_the_output_refuse() {
    let workspace = project("existing-links");
    let output = workspace.join("dist");
    std::fs::create_dir_all(output.join("assets")).expect("output");
    let target = workspace.join("app/keep.txt");
    std::fs::write(&target, "keep").expect("target");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target, output.join("assets/app.js")).expect("link");
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&target, output.join("assets/app.js")).expect("link");
    let reply = root_request(&workspace, &workspace, &["build"]);
    assert_eq!(refusal(&reply), UNVERIFIED_LINKS);
}

#[test]
fn a_second_name_for_a_file_outside_the_output_refuses() {
    let workspace = project("hard-link");
    let output = workspace.join("dist");
    std::fs::create_dir_all(&output).expect("output");
    let target = workspace.join("app/keep.txt");
    std::fs::write(&target, "keep").expect("target");
    std::fs::hard_link(&target, output.join("app.js")).expect("alias");
    let reply = root_request(&workspace, &workspace, &["build"]);
    assert_eq!(refusal(&reply), UNVERIFIED_LINKS);
}

#[test]
fn an_ordinary_existing_output_is_accepted() {
    let workspace = project("existing");
    let output = workspace.join("dist");
    std::fs::create_dir_all(output.join("assets")).expect("output");
    std::fs::write(output.join("assets/app.js"), "built").expect("asset");
    let reply = root_request(&workspace, &workspace, &["build"]);
    assert_eq!(
        reply["value"].as_str().map(PathBuf::from),
        Some(workspace.join("dist"))
    );
}

#[test]
fn a_plan_directory_is_rechecked_on_its_own() {
    let workspace = project("recheck");
    let reply = evaluate(
        "node_build_output_admissible",
        &json!({
            "workspace": workspace.to_string_lossy(),
            "cwd": workspace.to_string_lossy(),
            "path": workspace.join("dist").to_string_lossy(),
        }),
    )
    .expect("answered");
    assert_eq!(reply["value"], json!(true));
}

#[test]
fn a_recheck_without_a_working_directory_still_accepts_a_conventional_output() {
    let workspace = project("recheck-outdir");
    let reply = evaluate(
        "node_build_output_admissible",
        &json!({
            "workspace": workspace.to_string_lossy(),
            "path": workspace.join("build").to_string_lossy(),
        }),
    )
    .expect("answered");
    assert_eq!(reply["value"], json!(true));
}

#[test]
fn a_request_that_names_no_project_refuses_rather_than_guessing() {
    let workspace = project("incomplete");
    for (operation, input) in [
        (
            "node_build_output_root",
            json!({"cwd": workspace.to_string_lossy(), "arguments": ["build"]}),
        ),
        (
            "node_build_output_root",
            json!({"workspace": workspace.to_string_lossy(), "arguments": ["build"]}),
        ),
        (
            "node_build_output_root",
            json!({"workspace": workspace.to_string_lossy(), "cwd": workspace.to_string_lossy()}),
        ),
        (
            "node_build_output_root",
            json!({
                "workspace": workspace.to_string_lossy(),
                "cwd": workspace.to_string_lossy(),
                "arguments": ["build", 4],
            }),
        ),
        (
            "node_build_output_admissible",
            json!({"workspace": workspace.to_string_lossy()}),
        ),
    ] {
        let reply = evaluate(operation, &input).expect("answered");
        assert_eq!(
            refusal(&reply),
            "HOL Guard could not read the project this build writes into.",
            "{input}"
        );
    }
}

#[test]
fn a_hidden_or_vendored_package_directory_owns_no_output() {
    let workspace = project("hidden");
    for part in [".cache", "node_modules"] {
        let directory = workspace.join(part).join("app");
        std::fs::create_dir_all(&directory).expect("directory");
        std::fs::write(directory.join("package.json"), "{}").expect("manifest");
        assert!(!package_directory(&directory, &workspace), "{part}");
    }
}

#[test]
fn a_package_reached_through_a_link_owns_no_output() {
    let workspace = project("linked-package");
    let real = workspace.join("app/real");
    std::fs::create_dir_all(&real).expect("package");
    std::fs::write(real.join("package.json"), "{}").expect("manifest");
    let linked = workspace.join("linked");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real, &linked).expect("link");
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(&real, &linked).expect("link");
    assert!(!package_directory(&linked, &workspace));
    assert!(package_directory(&real, &workspace));
}

#[test]
fn the_workspace_root_is_a_package_directory() {
    let workspace = project("root");
    assert!(package_directory(&workspace, &workspace));
}
