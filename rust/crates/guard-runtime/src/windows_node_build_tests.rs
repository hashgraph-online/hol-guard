use super::*;
use crate::windows_readonly::COMMAND;
use std::fs;

const VITE_STUB: &str = r#"const fs = require("fs");
const path = require("path");
const visible = (name) => fs.existsSync(path.join(process.cwd(), name));
// Like Vite's default `emptyOutDir`.
fs.rmSync("dist", { recursive: true, force: true });
fs.mkdirSync("dist/assets", { recursive: true });
fs.writeFileSync("dist/index.html", "<!doctype html>");
fs.writeFileSync("dist/assets/app.js", "built");
fs.writeFileSync("scratch.txt", "not an output");
fs.writeFileSync("dist/report.txt", `${process.argv.slice(2).join(" ")} env=${visible(".env")} npmrc=${visible("node_modules/vite/.npmrc")}`);
"#;

const ESLINT_STUB: &str = r#"const fs = require("fs");
fs.writeFileSync("eslint-report.txt", process.argv.slice(2).join(" "));
fs.mkdirSync("dist", { recursive: true });
fs.writeFileSync("dist/app.js", "written");
"#;

fn project() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let workspace = canonical(directory.path()).unwrap();
    let app = workspace.join("dashboard");
    fs::create_dir_all(app.join("node_modules/vite/bin")).unwrap();
    fs::write(app.join("package.json"), "{}").unwrap();
    fs::write(app.join(".env"), "TOKEN=fixture").unwrap();
    fs::write(app.join("node_modules/vite/bin/vite.js"), VITE_STUB).unwrap();
    for entry in [
        "eslint/bin/eslint.js",
        "typescript/bin/tsc",
        "prettier/bin/prettier.cjs",
    ] {
        let placed = app.join("node_modules").join(entry);
        fs::create_dir_all(placed.parent().unwrap()).unwrap();
        fs::write(&placed, "// fixture").unwrap();
    }
    fs::write(
        app.join("node_modules/vite/.npmrc"),
        "//registry/:_authToken=x",
    )
    .unwrap();
    (directory, workspace, app)
}

fn fake_node(directory: &Path) -> PathBuf {
    let node = directory.join("node.exe");
    fs::write(&node, b"MZ fixture").unwrap();
    // The size a real runtime carries; a launcher for another install is far
    // smaller, and the sink reads that difference.
    fs::OpenOptions::new()
        .write(true)
        .open(&node)
        .unwrap()
        .set_len(MINIMUM_RUNTIME_BYTES)
        .unwrap();
    node
}

fn plan_tool(
    workspace: &Path,
    cwd: &Path,
    search_path: &Path,
    tool: &str,
    arguments: &[&str],
    expected: Option<&str>,
) -> Value {
    prepare_node_build(&json!({
        "workspace": workspace,
        "cwd": cwd,
        "tool": tool,
        "runtime_arguments": [],
        "arguments": arguments,
        "expected_entry": expected,
        "search_path": search_path,
    }))
}

fn plan_for(workspace: &Path, cwd: &Path, search_path: &Path, expected: Option<&str>) -> Value {
    plan_tool(workspace, cwd, search_path, "vite", &["build"], expected)
}

#[test]
fn runtime_options_are_bounded() {
    assert!(runtime_option("--max-old-space-size=4096"));
    for argument in [
        "--max-old-space-size=8",
        "--max-old-space-size=999999",
        "--max-old-space-size=",
        "--max-old-space-size=+64",
        "--require=x",
    ] {
        assert!(!runtime_option(argument), "{argument}");
    }
}

#[test]
fn node_executable_must_be_a_node_image() {
    let directory = tempfile::tempdir().unwrap();
    assert!(node_executable(&fake_node(directory.path())).is_ok());
    let script = directory.path().join("node.cmd");
    fs::write(&script, "@echo off").unwrap();
    assert!(node_executable(&script).is_err());
    let text = directory.path().join("other").join("node.exe");
    fs::create_dir_all(text.parent().unwrap()).unwrap();
    fs::write(&text, "#!/bin/sh").unwrap();
    assert!(node_executable(&text).is_err());
}

#[test]
fn a_launcher_for_another_install_is_not_the_runtime() {
    // What Volta, Scoop and Chocolatey put on PATH: an image named `node.exe`
    // that reaches the real runtime through its own install. Staged on its own
    // it has nothing to reach, so the command keeps the review prompt.
    let directory = tempfile::tempdir().unwrap();
    let shim = directory.path().join("node.exe");
    fs::write(&shim, b"MZ").unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&shim)
        .unwrap()
        .set_len(MINIMUM_RUNTIME_BYTES - 1)
        .unwrap();
    assert!(node_executable(&shim).is_err());
}

#[test]
fn a_linked_package_is_not_staged() {
    // `npm link` and a Yarn workspace leave a link where the package should
    // be. The copy that stages the snapshot walks directories and files, so a
    // build started from this install would run without that package.
    let (_directory, workspace, app) = project();
    let linked = workspace.join("shared");
    fs::create_dir_all(linked.join("dist")).unwrap();
    let placed = app.join("node_modules").join("shared");
    if std::os::windows::fs::symlink_dir(&linked, &placed).is_err() {
        // Linking needs a privilege this account may not hold; an account
        // that cannot create one cannot meet one either.
        return;
    }
    assert!(dependencies(&workspace, &app).is_err());
    fs::remove_dir(&placed).unwrap();
    assert!(dependencies(&workspace, &app).is_ok());
    // A scoped name holds its packages one level down, where its links are.
    let scope = app.join("node_modules").join("@acme");
    fs::create_dir_all(&scope).unwrap();
    std::os::windows::fs::symlink_dir(&linked, scope.join("shared")).unwrap();
    assert!(dependencies(&workspace, &app).is_err());
}

#[test]
fn dependencies_are_listed_from_the_run_directory_up() {
    let (_directory, workspace, app) = project();
    fs::create_dir(workspace.join("node_modules")).unwrap();
    let found = dependencies(&workspace, &app).unwrap();
    assert_eq!(
        found,
        vec![
            (
                app.join("node_modules"),
                PathBuf::from("dashboard").join("node_modules")
            ),
            (
                workspace.join("node_modules"),
                PathBuf::from("node_modules")
            ),
        ]
    );
    let entry = app.join("node_modules/vite/bin/vite.js");
    assert_eq!(
        staged_entry(&entry, &found, Path::new("dashboard")),
        Some(PathBuf::from(r"..\dashboard\node_modules\vite\bin\vite.js"))
    );
    assert_eq!(
        staged_entry(&app.join(".env"), &found, Path::new("dashboard")),
        None
    );
}

#[test]
fn a_pnpm_store_is_not_staged() {
    let (_directory, workspace, app) = project();
    fs::create_dir(app.join("node_modules/.pnpm")).unwrap();
    assert!(dependencies(&workspace, &app).is_err());
}

#[test]
fn outputs_stay_inside_the_workspace() {
    let (_directory, workspace, app) = project();
    assert_eq!(
        output_location(&app.join("dist"), &workspace),
        Some(PathBuf::from(r"dashboard\dist"))
    );
    assert_eq!(output_location(&workspace, &workspace), None);
    assert_eq!(output_location(&app.join(".."), &workspace), None);
    assert_eq!(
        output_location(&workspace.parent().unwrap().join("dist"), &workspace),
        None
    );
}

#[test]
fn plan_names_the_first_node_and_the_local_vite() {
    let (_directory, workspace, app) = project();
    let tools = tempfile::tempdir().unwrap();
    let node = canonical(&fake_node(tools.path())).unwrap();
    let response = plan_for(
        &workspace,
        &app,
        tools.path(),
        Some("node_modules/vite/bin/vite.js"),
    );
    let value = &response["value"];
    assert_eq!(value["profile_version"], PROFILE, "{response}");
    assert_eq!(value["backend"], BACKEND);
    let command: Vec<String> = serde_json::from_value(value["command"].clone()).unwrap();
    let entry = app.join(r"node_modules\vite\bin\vite.js");
    assert_eq!(
        command,
        vec![
            node.to_string_lossy().into_owned(),
            entry.to_string_lossy().replace('\\', "/"),
            "build".to_owned()
        ]
    );
    let other = plan_for(&workspace, &app, tools.path(), Some("vite.js"));
    assert_eq!(other["reason_code"], UNAVAILABLE, "{other}");
    let empty = tempfile::tempdir().unwrap();
    let missing = plan_for(&workspace, &app, empty.path(), None);
    assert_eq!(missing["reason_code"], UNAVAILABLE, "{missing}");
}

#[test]
fn installed_node_builds_and_publishes_only_the_output() {
    let search_path = std::env::var("PATH").unwrap_or_default();
    let Some(node) = first_on_path(&["node.exe".to_owned()], &search_path) else {
        eprintln!("skipped: no node.exe on PATH");
        return;
    };
    let (_directory, workspace, app) = project();
    fs::create_dir_all(app.join("dist")).unwrap();
    fs::write(app.join("dist/stale.js"), "old").unwrap();
    let response = plan_for(&workspace, &app, node.parent().unwrap(), None);
    let command: Vec<String> =
        serde_json::from_value(response["value"]["command"].clone()).expect("plan");
    let text = |path: &Path| path.to_string_lossy().into_owned();
    let mut arguments: Vec<String> = vec![
        COMMAND.to_owned(),
        "--profile".to_owned(),
        PROFILE.to_owned(),
        "--workspace".to_owned(),
        text(&workspace),
        "--cwd".to_owned(),
        text(&app),
        "--timeout-seconds".to_owned(),
        "60".to_owned(),
        "--output".to_owned(),
        text(&app.join("dist")),
        "--".to_owned(),
    ];
    arguments.extend(command);
    assert_eq!(crate::windows_readonly::main(&arguments), 0);
    assert_eq!(
        fs::read_to_string(app.join("dist/assets/app.js")).unwrap(),
        "built"
    );
    assert!(app.join("dist/index.html").is_file());
    assert_eq!(
        fs::read_to_string(app.join("dist/report.txt")).unwrap(),
        "build env=false npmrc=false"
    );
    assert!(!app.join("dist/stale.js").exists());
    assert!(!app.join("scratch.txt").exists());
}

#[test]
fn a_reporting_tool_plans_under_the_read_only_profile() {
    // ESLint, no-emit TypeScript and a Prettier check all stage the same way a
    // build does, because their executables live in `node_modules`, which an
    // ordinary read-only snapshot withholds. None of them writes, so none is
    // granted the source write a build needs to replace its output directory.
    let (_directory, workspace, app) = project();
    let tools = tempfile::tempdir().unwrap();
    let node = canonical(&fake_node(tools.path())).unwrap();
    for (tool, arguments, relative) in [
        ("eslint", vec!["src"], r"node_modules\eslint\bin\eslint.js"),
        ("tsc", vec!["--noEmit"], r"node_modules\typescript\bin\tsc"),
        (
            "prettier",
            vec!["--check", "src"],
            r"node_modules\prettier\bin\prettier.cjs",
        ),
    ] {
        let response = plan_tool(&workspace, &app, tools.path(), tool, &arguments, None);
        let value = &response["value"];
        assert_eq!(value["profile_version"], TOOL_PROFILE, "{response}");
        assert_eq!(value["backend"], BACKEND);
        let denied: Vec<String> =
            serde_json::from_value(value["denied_capabilities"].clone()).unwrap();
        assert!(denied.contains(&"workspace-write".to_owned()), "{tool}");
        assert!(
            !denied.contains(&"workspace-source-write".to_owned()),
            "{tool}"
        );
        let command: Vec<String> = serde_json::from_value(value["command"].clone()).unwrap();
        let mut expected = vec![
            node.to_string_lossy().into_owned(),
            app.join(relative).to_string_lossy().replace('\\', "/"),
        ];
        expected.extend(arguments.iter().map(|argument| (*argument).to_owned()));
        assert_eq!(command, expected, "{tool}");
    }
}

#[test]
fn only_the_build_declares_an_output_and_the_source_write_it_needs() {
    let (_directory, workspace, app) = project();
    let tools = tempfile::tempdir().unwrap();
    fake_node(tools.path());
    let build = plan_for(&workspace, &app, tools.path(), None);
    assert_eq!(build["value"]["profile_version"], PROFILE, "{build}");
    let denied: Vec<String> =
        serde_json::from_value(build["value"]["denied_capabilities"].clone()).unwrap();
    assert!(denied.contains(&"workspace-source-write".to_owned()));
    assert!(!denied.contains(&"workspace-write".to_owned()));
}

#[test]
fn only_the_reporting_mode_of_each_tool_is_admitted() {
    // The resident owns this refusal rather than trusting the sink's: it is
    // what admits a run into a writable staged copy of the workspace.
    for (tool, arguments) in [
        ("tsc", vec![]),
        ("tsc", vec!["--build"]),
        ("prettier", vec!["src"]),
        ("vite", vec![]),
        ("vite", vec!["preview"]),
        ("webpack", vec!["--mode", "production"]),
        ("eslint", vec!["src", "--fix"]),
        ("eslint", vec!["src", "--fix-dry-run"]),
        ("eslint", vec!["src", "--output-file=report.json"]),
        ("eslint", vec!["src", "-o", "report.json"]),
        ("tsc", vec!["--noEmit", "--emitDeclarationOnly"]),
        ("prettier", vec!["--check", "src", "--write"]),
        ("prettier", vec!["--check", "src", "--write=true"]),
    ] {
        assert!(
            !admitted_mode(tool, &owned(&arguments)) || rewrites_input(&owned(&arguments)),
            "{tool} {arguments:?}"
        );
    }
    for (tool, arguments) in [
        ("eslint", vec!["src", "--max-warnings", "0"]),
        ("tsc", vec!["-p", "tsconfig.json", "--noEmit"]),
        ("vite", vec!["build", "--outDir", "build"]),
        ("prettier", vec!["--list-different", "."]),
    ] {
        assert!(
            admitted_mode(tool, &owned(&arguments)) && !rewrites_input(&owned(&arguments)),
            "{tool} {arguments:?}"
        );
    }
}

fn owned(arguments: &[&str]) -> Vec<String> {
    arguments.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn a_refused_mode_never_reaches_a_staged_run() {
    let (_directory, workspace, app) = project();
    let tools = tempfile::tempdir().unwrap();
    fake_node(tools.path());
    for (tool, arguments) in [
        ("tsc", vec![]),
        ("eslint", vec!["src", "--fix"]),
        ("webpack", vec!["--mode", "production"]),
    ] {
        let response = plan_tool(&workspace, &app, tools.path(), tool, &arguments, None);
        assert_eq!(response["reason_code"], INVALID, "{response}");
    }
}

#[test]
fn a_published_entrypoint_spelling_resolves_and_the_nearest_install_wins() {
    // Prettier 3 ships `bin/prettier.cjs` and Prettier 2 `bin-prettier.js`.
    let (_directory, workspace, app) = project();
    fs::remove_file(app.join("node_modules/prettier/bin/prettier.cjs")).unwrap();
    fs::write(app.join("node_modules/prettier/bin-prettier.js"), "// 2.x").unwrap();
    assert_eq!(
        tool_entry("prettier", &workspace, &app).unwrap(),
        canonical(&app.join("node_modules/prettier/bin-prettier.js")).unwrap()
    );
    // A package that pins its own major runs that copy, not one hoisted above it.
    let hoisted = workspace.join("node_modules/eslint/bin");
    fs::create_dir_all(&hoisted).unwrap();
    fs::write(hoisted.join("eslint.js"), "// hoisted").unwrap();
    assert_eq!(
        tool_entry("eslint", &workspace, &app).unwrap(),
        canonical(&app.join("node_modules/eslint/bin/eslint.js")).unwrap()
    );
    fs::remove_dir_all(app.join("node_modules/eslint")).unwrap();
    assert_eq!(
        tool_entry("eslint", &workspace, &app).unwrap(),
        canonical(&hoisted.join("eslint.js")).unwrap()
    );
    fs::remove_dir_all(workspace.join("node_modules")).unwrap();
    assert!(tool_entry("eslint", &workspace, &app).is_err());
}

#[test]
fn installed_node_reports_without_publishing_anything() {
    let search_path = std::env::var("PATH").unwrap_or_default();
    let Some(node) = first_on_path(&["node.exe".to_owned()], &search_path) else {
        eprintln!("skipped: no node.exe on PATH");
        return;
    };
    let (_directory, workspace, app) = project();
    fs::write(app.join("node_modules/eslint/bin/eslint.js"), ESLINT_STUB).unwrap();
    let response = plan_tool(
        &workspace,
        &app,
        node.parent().unwrap(),
        "eslint",
        &["src"],
        None,
    );
    let command: Vec<String> =
        serde_json::from_value(response["value"]["command"].clone()).expect("plan");
    let text = |path: &Path| path.to_string_lossy().into_owned();
    let mut arguments: Vec<String> = vec![
        COMMAND.to_owned(),
        "--profile".to_owned(),
        TOOL_PROFILE.to_owned(),
        "--workspace".to_owned(),
        text(&workspace),
        "--cwd".to_owned(),
        text(&app),
        "--timeout-seconds".to_owned(),
        "60".to_owned(),
        "--".to_owned(),
    ];
    arguments.extend(command);
    assert_eq!(crate::windows_readonly::main(&arguments), 0);
    // The staged copy is discarded whole: neither the file the tool wrote nor
    // the directory a build would have published reaches the live workspace.
    assert!(!app.join("eslint-report.txt").exists());
    assert!(!app.join("dist").exists());
}
