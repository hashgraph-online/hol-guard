//! The single reading of a Vite config's declared output.

use super::vite_output::{
    bundle_directory, config_output_is_verifiable, declared_output, Declared,
};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

struct Project {
    root: PathBuf,
}

impl Project {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "guard-vite-output-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("workspace");
        Self { root }
    }

    fn workspace(&self) -> &Path {
        &self.root
    }

    fn app(&self) -> PathBuf {
        let app = self.root.join("app");
        fs::create_dir_all(&app).expect("app");
        app
    }

    fn config(&self, body: &str) -> PathBuf {
        let app = self.app();
        let path = app.join("vite.config.ts");
        fs::write(&path, body).expect("config");
        path
    }
}

impl Drop for Project {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn a_literal_output_beside_the_config_is_the_declared_one() {
    let project = Project::new("literal");
    project.config("export default { build: { outDir: '../static' } }\n");
    assert_eq!(
        declared_output(&project.app(), project.workspace(), None),
        Declared::Output(project.workspace().join("static"))
    );
}

#[test]
fn a_resolved_dirname_output_reads_the_same_way() {
    let project = Project::new("dirname");
    project
        .config("import path from 'path'\nexport default { build: { outDir: path.resolve(__dirname, '../static') } }\n");
    assert_eq!(
        declared_output(&project.app(), project.workspace(), None),
        Declared::Output(project.workspace().join("static"))
    );
}

#[test]
fn a_config_that_names_no_output_keeps_the_build_default() {
    let project = Project::new("silent");
    project.config("export default { build: { sourcemap: true } }\n");
    assert_eq!(
        declared_output(&project.app(), project.workspace(), None),
        Declared::Default
    );
    assert!(config_output_is_verifiable(
        &project.app(),
        project.workspace()
    ));
}

#[test]
fn an_output_outside_the_workspace_is_unverifiable() {
    let project = Project::new("escape");
    project.config("export default { build: { outDir: '../../elsewhere' } }\n");
    assert_eq!(
        declared_output(&project.app(), project.workspace(), None),
        Declared::Unverified
    );
    assert!(!config_output_is_verifiable(
        &project.app(),
        project.workspace()
    ));
}

#[test]
fn an_output_covering_a_package_is_unverifiable() {
    let project = Project::new("package");
    let app = project.app();
    fs::write(app.join("package.json"), "{}").expect("manifest");
    project.config("export default { build: { outDir: '.' } }\n");
    assert_eq!(
        declared_output(&app, project.workspace(), None),
        Declared::Unverified
    );
}

#[test]
fn an_existing_output_holding_a_source_file_is_unverifiable() {
    let project = Project::new("sources");
    let static_dir = project.workspace().join("static");
    fs::create_dir_all(&static_dir).expect("static");
    fs::write(static_dir.join("main.ts"), "export {}\n").expect("source");
    project.config("export default { build: { outDir: '../static' } }\n");
    assert_eq!(
        declared_output(&project.app(), project.workspace(), None),
        Declared::Unverified
    );
}

#[test]
fn an_existing_output_holding_built_assets_is_accepted() {
    let project = Project::new("assets");
    let static_dir = project.workspace().join("static");
    fs::create_dir_all(static_dir.join("assets")).expect("static");
    fs::write(static_dir.join("index.html"), "<html></html>").expect("page");
    fs::write(static_dir.join("assets/app.JS"), "0\n").expect("bundle");
    fs::write(static_dir.join(".gitkeep"), "").expect("keep");
    project.config("export default { build: { outDir: '../static' } }\n");
    assert_eq!(
        declared_output(&project.app(), project.workspace(), None),
        Declared::Output(static_dir)
    );
}

#[test]
fn two_mentions_of_the_output_cannot_be_read() {
    let project = Project::new("twice");
    project
        .config("const outDir = '../static'\nexport default { build: { outDir: '../static' } }\n");
    assert_eq!(
        declared_output(&project.app(), project.workspace(), None),
        Declared::Unverified
    );
}

#[test]
fn two_configs_leave_the_output_to_the_build() {
    let project = Project::new("two-configs");
    let app = project.app();
    fs::write(
        app.join("vite.config.ts"),
        "export default { build: { outDir: '../static' } }\n",
    )
    .expect("ts");
    fs::write(
        app.join("vite.config.js"),
        "export default { build: { outDir: '../other' } }\n",
    )
    .expect("js");
    assert_eq!(
        declared_output(&app, project.workspace(), None),
        Declared::Default
    );
}

#[test]
fn a_named_config_replaces_the_conventional_one() {
    let project = Project::new("named");
    let app = project.app();
    project.config("export default { build: { outDir: '../static' } }\n");
    let named = app.join("vite.alt.ts");
    fs::write(&named, "export default { build: { outDir: '../other' } }\n").expect("alt");
    assert_eq!(
        declared_output(&app, project.workspace(), Some(&named)),
        Declared::Output(project.workspace().join("other"))
    );
}

#[test]
fn a_named_config_that_is_missing_leaves_the_output_to_the_build() {
    let project = Project::new("named-missing");
    let app = project.app();
    project.config("export default { build: { outDir: '../static' } }\n");
    assert_eq!(
        declared_output(&app, project.workspace(), Some(&app.join("missing.ts"))),
        Declared::Default
    );
}

#[test]
fn a_named_config_outside_the_workspace_is_unverifiable() {
    let project = Project::new("named-outside");
    let app = project.app();
    assert_eq!(
        declared_output(
            &app,
            project.workspace(),
            Some(Path::new("/etc/vite.config.ts"))
        ),
        Declared::Unverified
    );
}

#[test]
fn the_bundle_directory_is_the_nearest_modules_temp() {
    let project = Project::new("bundle");
    let app = project.app();
    let modules = app.join("node_modules");
    fs::create_dir_all(&modules).expect("modules");
    assert_eq!(
        bundle_directory(&app, project.workspace(), &modules),
        Some(modules.join(".vite-temp"))
    );
}

#[test]
fn another_packages_modules_is_not_the_bundle_directory() {
    let project = Project::new("bundle-other");
    let app = project.app();
    fs::create_dir_all(app.join("node_modules")).expect("modules");
    let other = project.workspace().join("node_modules");
    fs::create_dir_all(&other).expect("other");
    assert_eq!(bundle_directory(&app, project.workspace(), &other), None);
}

#[test]
fn the_operation_reports_the_refusal_the_build_shows() {
    let project = Project::new("operation");
    project.config("export default { build: { outDir: '../../elsewhere' } }\n");
    let reply = super::vite_output::evaluate(
        "vite_declared_output",
        &json!({"cwd": project.app(), "workspace": project.workspace()}),
    )
    .expect("answered");
    assert_eq!(reply["reason_code"], "node_build_invalid_output");
}

#[test]
fn an_unknown_operation_is_left_to_the_other_readers() {
    assert!(super::vite_output::evaluate("normalized_command", &json!({})).is_none());
}
