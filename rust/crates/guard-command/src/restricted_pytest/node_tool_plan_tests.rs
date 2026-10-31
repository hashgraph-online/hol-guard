use super::*;
use std::os::unix::fs::PermissionsExt;

/// A project with an approved Node runtime of its own and `manifest` as
/// its `package.json`.
fn project(manifest: &str) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let workspace = directory.path().canonicalize().unwrap().join("project");
    fs::create_dir_all(workspace.join("bin")).unwrap();
    fs::write(workspace.join("package.json"), manifest).unwrap();
    let node = workspace.join("bin/node");
    fs::write(&node, b"\xcf\xfa\xed\xfenative-fixture").unwrap();
    fs::set_permissions(&node, fs::Permissions::from_mode(0o755)).unwrap();
    (directory, workspace)
}

fn install(modules: &Path, relative: &str) -> PathBuf {
    let entry = modules.join(relative);
    fs::create_dir_all(entry.parent().unwrap()).unwrap();
    fs::write(&entry, "").unwrap();
    entry
}

fn plan(command: &[&str], workspace: &Path, cwd: &Path) -> Value {
    evaluate(
        "prepare_node_tool",
        &json!({
            "command": command,
            "workspace": workspace,
            "cwd": cwd,
            "home": null,
            "platform": "darwin",
            "backend_executable": "/usr/bin/true",
            "search_path": workspace.join("bin"),
        }),
    )
    .unwrap()
}

#[test]
fn a_report_runs_the_installed_tool_on_the_projects_node() {
    let (_directory, workspace) = project("{}");
    let entry = install(&workspace.join("node_modules"), "eslint/bin/eslint.js");
    let plan = &plan(&["eslint", "src"], &workspace, &workspace)["value"];
    assert_eq!(plan["profile_version"], READ_ONLY_PROFILE);
    assert_eq!(
        plan["command"],
        json!([workspace.join("bin/node"), entry, "src"])
    );
    assert!(plan.get("output_roots").is_none());
    assert!(plan["denied_capabilities"]
        .as_array()
        .unwrap()
        .contains(&json!("workspace-write")));
}

#[test]
fn a_tool_the_project_does_not_install_is_never_fetched() {
    let (_directory, workspace) = project("{}");
    let reply = plan(&["eslint", "src"], &workspace, &workspace);
    assert_eq!(reply["reason_code"], "node_tool_dependency_unavailable");
}

#[test]
fn the_nearest_install_wins_over_a_hoisted_copy() {
    let (_directory, workspace) = project("{}");
    install(&workspace.join("node_modules"), "eslint/bin/eslint.js");
    let app = workspace.join("packages/app");
    let entry = install(&app.join("node_modules"), "eslint/bin/eslint.js");
    let plan = &plan(&["eslint", "."], &workspace, &app)["value"];
    assert_eq!(plan["command"][1], json!(entry));
}

#[test]
fn an_entrypoint_linked_out_of_node_modules_is_unavailable() {
    let (directory, workspace) = project("{}");
    let outside = directory.path().join("eslint.js");
    fs::write(&outside, "").unwrap();
    let entry = workspace.join("node_modules/eslint/bin/eslint.js");
    fs::create_dir_all(entry.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&outside, &entry).unwrap();
    let reply = plan(&["eslint", "src"], &workspace, &workspace);
    assert_eq!(reply["reason_code"], "node_tool_dependency_unavailable");
}

#[test]
fn a_package_script_runs_as_the_words_it_spells() {
    let (_directory, workspace) = project(r#"{"scripts":{"lint":"eslint src"}}"#);
    let entry = install(&workspace.join("node_modules"), "eslint/bin/eslint.js");
    let plan = &plan(&["npm", "run", "lint"], &workspace, &workspace)["value"];
    assert_eq!(
        plan["command"],
        json!([workspace.join("bin/node"), entry, "src"])
    );
}

#[test]
fn a_script_with_lifecycle_actions_or_none_at_all_is_refused() {
    for manifest in [
        r#"{"scripts":{"lint":"eslint src","prelint":"curl x"}}"#,
        r#"{"scripts":{"lint":"eslint src","postlint":"rm -rf dist"}}"#,
        r#"{"scripts":{}}"#,
        "not json",
    ] {
        let (_directory, workspace) = project(manifest);
        install(&workspace.join("node_modules"), "eslint/bin/eslint.js");
        let reply = plan(&["npm", "run", "lint"], &workspace, &workspace);
        assert_eq!(
            reply["reason_code"], "node_tool_invalid_command",
            "{manifest}"
        );
    }
    let (_directory, workspace) = project(r#"{"scripts":{"lint":"eslint src","prelint":""}}"#);
    install(&workspace.join("node_modules"), "eslint/bin/eslint.js");
    assert!(plan(&["npm", "run", "lint"], &workspace, &workspace)
        .get("value")
        .is_some());
}

#[test]
fn a_command_that_names_no_tool_is_refused_before_node_is_resolved() {
    let (_directory, workspace) = project("{}");
    fs::remove_file(workspace.join("bin/node")).unwrap();
    let reply = plan(&["eslint", "--fix", "src"], &workspace, &workspace);
    assert_ne!(reply["reason_code"], "node_test_restricted_invalid_command");
    assert!(reply.get("value").is_none());
}

#[test]
fn a_build_is_granted_its_output_directory_but_not_the_sources() {
    let (_directory, workspace) = project(r#"{"name":"app"}"#);
    let entry = install(&workspace.join("node_modules"), "vite/bin/vite.js");
    let plan = &plan(&["vite", "build"], &workspace, &workspace)["value"];
    assert_eq!(plan["profile_version"], BUILD_PROFILE);
    assert_eq!(plan["command"][1], json!(entry));
    assert_eq!(plan["command"][2], "build");
    let roots = plan["output_roots"].as_array().unwrap();
    assert_eq!(roots[0], json!(workspace.join("dist")));
    let denied = plan["denied_capabilities"].as_array().unwrap();
    assert!(denied.contains(&json!("workspace-source-write")));
    assert!(!denied.contains(&json!("workspace-write")));
}

#[test]
fn the_nearest_spelling_of_a_tool_wins_over_a_hoisted_one() {
    // A package that pins its own major runs its own copy, not the root's.
    let (_directory, workspace) = project("{}");
    let hoisted = install(&workspace.join("node_modules"), "prettier/bin/prettier.cjs");
    let app = workspace.join("packages/app");
    let local = install(&app.join("node_modules"), "prettier/bin-prettier.js");
    let check = ["prettier", "--check", "."];
    assert_eq!(
        plan(&check, &workspace, &app)["value"]["command"][1],
        json!(local)
    );
    assert_eq!(
        plan(&check, &workspace, &workspace)["value"]["command"][1],
        json!(hoisted)
    );
}

#[test]
fn a_relative_entrypoint_resolves_from_the_command_directory() {
    for spelling in [
        "node_modules/vite/bin/vite.js",
        "./node_modules/vite/bin/vite.js",
    ] {
        let (_directory, workspace) = project(r#"{"name":"app"}"#);
        let entry = install(&workspace.join("node_modules"), "vite/bin/vite.js");
        let plan = &plan(&["node", spelling, "build"], &workspace, &workspace)["value"];
        assert_eq!(plan["command"][1], json!(entry), "{spelling}");
        assert_eq!(
            plan["output_roots"],
            json!([
                workspace.join("dist"),
                workspace.join("node_modules/.vite-temp")
            ]),
            "{spelling}"
        );
    }
}

#[test]
fn a_bounded_heap_option_stays_before_the_verified_entrypoint() {
    let (_directory, workspace) = project("{}");
    let entry = install(&workspace.join("node_modules"), "typescript/bin/tsc");
    let entry_text = entry.to_str().unwrap();
    let command = [
        "node",
        "--max-old-space-size=12288",
        entry_text,
        "--noEmit",
        "--incremental",
        "false",
    ];
    let plan = &plan(&command, &workspace, &workspace)["value"];
    assert_eq!(plan["profile_version"], READ_ONLY_PROFILE);
    assert_eq!(
        plan["command"],
        json!([
            workspace.join("bin/node"),
            "--max-old-space-size=12288",
            entry,
            "--noEmit",
            "--incremental",
            "false"
        ])
    );
}

/// A Vite app below the workspace, built with `config` as its config.
fn vite_app(config: &str) -> (tempfile::TempDir, PathBuf, PathBuf) {
    let (directory, workspace) = project("{}");
    let app = workspace.join("dashboard");
    fs::create_dir_all(&app).unwrap();
    fs::write(app.join("package.json"), "{}").unwrap();
    fs::write(app.join("vite.config.ts"), config).unwrap();
    install(&app.join("node_modules"), "vite/bin/vite.js");
    (directory, workspace, app)
}

fn vite_config(out_dir: &str) -> String {
    format!(
        "import path, {{ resolve }} from \"path\";\nexport default defineConfig({{\n  build: {{ outDir: {out_dir}, emptyOutDir: true }},\n}});\n"
    )
}

fn vite_build(workspace: &Path, app: &Path, extra: &[&str]) -> Value {
    let command = [
        &["node", "node_modules/vite/bin/vite.js", "build"][..],
        extra,
    ]
    .concat();
    plan(&command, workspace, app)["value"].clone()
}

#[test]
fn the_build_plan_grants_the_declared_directory() {
    let (_directory, workspace, app) =
        vite_app(&vite_config(r#"resolve(__dirname, "../src/pkg/static")"#));
    let plan = vite_build(&workspace, &app, &[]);
    assert_eq!(
        plan["output_roots"],
        json!([
            workspace.join("src/pkg/static"),
            app.join("node_modules/.vite-temp")
        ])
    );
}

#[test]
fn command_line_output_or_config_overrides_the_declared_directory() {
    for extra in [["--outDir", "dist"], ["--config", "vite.alt.ts"]] {
        let (_directory, workspace, app) = vite_app(&vite_config("process.env.OUT_DIR"));
        let plan = vite_build(&workspace, &app, &extra);
        assert_eq!(
            plan["output_roots"][0],
            json!(app.join("dist")),
            "{extra:?}"
        );
    }
}

#[test]
fn the_default_config_loader_gets_only_its_bundle_directory() {
    let (_directory, workspace, app) = vite_app("export default {};\n");
    let plan = vite_build(&workspace, &app, &[]);
    assert_eq!(plan["command"].as_array().unwrap().last().unwrap(), "build");
    assert_eq!(
        plan["output_roots"],
        json!([app.join("dist"), app.join("node_modules/.vite-temp")])
    );
}

#[test]
fn an_explicit_config_or_loader_gets_no_bundle_directory() {
    for extra in [["--config", "vite.alt.ts"], ["--configLoader", "native"]] {
        let (_directory, workspace, app) = vite_app("export default {};\n");
        let plan = vite_build(&workspace, &app, &extra);
        assert_eq!(plan["output_roots"], json!([app.join("dist")]), "{extra:?}");
        let command = plan["command"].as_array().unwrap();
        let tail = if extra[0] == "--configLoader" {
            json!(extra)
        } else {
            json!(["--configLoader", "runner"])
        };
        assert_eq!(json!(command[command.len() - 2..]), tail, "{extra:?}");
    }
}

/// The edge's package-script receipts match what this sink runs.
///
/// `tests/pretool_package_script_routes.rs` classifies the same fixture
/// cases. A case the edge routes to a Node tool sink must be planned under
/// that sink's profile, and a case it routes nowhere must be refused here, so
/// the edge never issues a narrow receipt the sink then rejects. Package
/// tests run in their own sink and are read by its own parity test.
#[test]
fn the_sink_plans_exactly_the_scripts_the_edge_routes_to_it() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/package-script-routes.v1.json"
    ))
    .unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let words = ask("script_words", json!({ "script": case["command"] })).unwrap();
        let kinds = ask("contained_kind", json!({ "command": words })).unwrap();
        if kinds["package_test"] == true {
            continue;
        }
        let manifest = json!({ "name": name, "scripts": case["scripts"] });
        let (_directory, workspace) = project(&manifest.to_string());
        for entry in case["entries"].as_array().unwrap() {
            install(&workspace.join("node_modules"), entry.as_str().unwrap());
        }
        let command: Vec<String> = serde_json::from_value(words).unwrap();
        let command: Vec<&str> = command.iter().map(String::as_str).collect();
        let reply = plan(&command, &workspace, &workspace);
        let reason = match reply["value"]["profile_version"].as_str() {
            Some(BUILD_PROFILE) => json!("native_node_build_output_containment_required"),
            Some(READ_ONLY_PROFILE) => json!("native_node_tool_readonly_containment_required"),
            _ => Value::Null,
        };
        assert_eq!(reason, case["reason"], "{name}: {reply}");
    }
}
