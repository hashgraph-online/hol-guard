//! Installed bytes and resolver choices, never execution/consent authority.
use super::*;

fn installed(manifest: &str) -> Project {
    let project = Project::new();
    project.write("package.json", r#"{"type":"module"}"#);
    project.write(
        "report.mjs",
        "import value from 'fixture-package'; console.log(value);\n",
    );
    project.write("node_modules/fixture-package/package.json", manifest);
    project
}

#[test]
fn installed_selected_entry_and_transitive_code_are_bound_but_unselected_code_is_not() {
    let project = installed(
        r#"{"name":"fixture-package","type":"module","main":"decoy.js","exports":"./entry.js"}"#,
    );
    project.write(
        "node_modules/fixture-package/entry.js",
        "export { value as default } from './lib/value.js';\n",
    );
    project.write(
        "node_modules/fixture-package/lib/value.js",
        "export const value = 1;\n",
    );
    project.write(
        "node_modules/fixture-package/decoy.js",
        "export default 10;\n",
    );
    let before = bind(&project, &["report.mjs"], &[]).unwrap();
    assert_eq!(before["modules"].as_array().unwrap().len(), 3);
    project.write(
        "node_modules/fixture-package/decoy.js",
        "export default 20;\n",
    );
    assert_eq!(before, bind(&project, &["report.mjs"], &[]).unwrap());
    project.write(
        "node_modules/fixture-package/lib/value.js",
        "export const value = 2;\n",
    );
    assert_ne!(before, bind(&project, &["report.mjs"], &[]).unwrap());
}

#[test]
fn installed_literal_subpath_and_unconditional_default_exports_bind_real_code() {
    let project = installed(
        r#"{"name":"fixture-package","type":"module","exports":{".":{"default":"./entry.js"},"./part":"./part.js"}}"#,
    );
    project.write(
        "node_modules/fixture-package/entry.js",
        "export default 1;\n",
    );
    project.write(
        "node_modules/fixture-package/part.js",
        "export default 2;\n",
    );
    assert!(bind(&project, &["report.mjs"], &[]).is_ok());
    project.write(
        "report.mjs",
        "import value from 'fixture-package/part'; console.log(value);\n",
    );
    let before = bind(&project, &["report.mjs"], &[]).unwrap();
    project.write(
        "node_modules/fixture-package/part.js",
        "export default 3;\n",
    );
    assert_ne!(before, bind(&project, &["report.mjs"], &[]).unwrap());
}

#[test]
fn installed_self_reference_precedes_a_same_named_installed_dependency() {
    let project = installed(r#"{"name":"fixture-package","type":"module","main":"index.js"}"#);
    project.write(
        "package.json",
        r#"{"name":"fixture-package","type":"module","exports":"./self.js"}"#,
    );
    project.write("self.js", "export default 1;\n");
    project.write(
        "node_modules/fixture-package/index.js",
        "export default 2;\n",
    );
    let before = bind(&project, &["report.mjs"], &[]).unwrap();
    project.write(
        "node_modules/fixture-package/index.js",
        "export default 3;\n",
    );
    assert_eq!(before, bind(&project, &["report.mjs"], &[]).unwrap());
    project.write("self.js", "export default 4;\n");
    assert_ne!(before, bind(&project, &["report.mjs"], &[]).unwrap());
}

#[test]
fn installed_exports_do_not_guess_conditions_extensions_or_escaped_targets() {
    for exports in [
        json!({"import":"./entry.js","require":"./other.js"}),
        json!({"./*":"./*.js"}),
        json!(["./entry.js"]),
        json!("../outside.js"),
        json!("./lib/../entry.js"),
        json!("./node_modules/other.js"),
        json!("./%2e%2e/entry.js"),
    ] {
        let project = installed(&json!({"name":"fixture-package","exports":exports}).to_string());
        project.write(
            "node_modules/fixture-package/entry.js",
            "export default 1;\n",
        );
        assert_eq!(
            bind(&project, &["report.mjs"], &[]),
            Err("node_package_exports_unproven")
        );
    }
    let project = installed(r#"{"name":"fixture-package","exports":"./entry"}"#);
    project.write(
        "node_modules/fixture-package/entry.js",
        "export default 1;\n",
    );
    assert_eq!(
        bind(&project, &["report.mjs"], &[]),
        Err("node_package_entrypoint_unproven")
    );
}

#[test]
fn installed_native_addons_and_missing_code_are_not_manifest_only_proofs() {
    let project = installed(r#"{"name":"fixture-package","main":"native.node"}"#);
    project.write(
        "node_modules/fixture-package/native.node",
        "not executable\n",
    );
    assert_eq!(
        bind(&project, &["report.mjs"], &[]),
        Err("node_package_native_addon_unproven")
    );
    project.write(
        "node_modules/fixture-package/package.json",
        r#"{"name":"fixture-package","main":"gone.js"}"#,
    );
    assert_eq!(
        bind(&project, &["report.mjs"], &[]),
        Err("node_package_entrypoint_unproven")
    );
}

#[test]
fn installed_writes_cannot_launder_later_package_code_loading() {
    let project = installed(r#"{"name":"fixture-package","type":"module","main":"entry.js"}"#);
    project.write(
        "node_modules/fixture-package/entry.js",
        "export default 1;\n",
    );
    project.write("report.mjs", "import { writeFileSync } from 'node:fs';\nwriteFileSync('out', 'data');\nawait import('fixture-package');\n");
    assert_eq!(
        bind(&project, &["report.mjs"], &[]),
        Err("node_runtime_package_mutation_unproven")
    );
}

#[test]
#[ignore = "select an installed Node executable with HOL_GUARD_TEST_NODE_BINARY for resolver parity"]
fn installed_resolution_matches_real_node_import_and_require() {
    let node =
        std::env::var_os("HOL_GUARD_TEST_NODE_BINARY").expect("select the tested Node executable");
    assert!(Path::new(&node).is_absolute());
    let version = std::process::Command::new(&node)
        .env_clear()
        .arg("--version")
        .output()
        .unwrap();
    assert!(version.status.success());
    eprintln!(
        "Node resolver parity: {}",
        String::from_utf8_lossy(&version.stdout).trim()
    );
    for (manifest, specifier, self_reference) in [
        (
            r#"{"name":"fixture-package","type":"module","main":"entry.js"}"#,
            "fixture-package",
            false,
        ),
        (
            r#"{"name":"fixture-package","type":"module","main":"entry"}"#,
            "fixture-package",
            false,
        ),
        (
            r#"{"name":"fixture-package","type":"module","main":"decoy.js","exports":"./entry.js"}"#,
            "fixture-package",
            false,
        ),
        (
            r#"{"name":"fixture-package","type":"module","exports":{".":{"default":"./entry.js"}}}"#,
            "fixture-package",
            false,
        ),
        (
            r#"{"name":"fixture-package","type":"module","exports":{"./part":"./part.js"}}"#,
            "fixture-package/part",
            false,
        ),
        (
            r#"{"name":"fixture-package","type":"module","main":"entry.js"}"#,
            "fixture-package",
            true,
        ),
    ] {
        let project = installed(manifest);
        if self_reference {
            project.write(
                "package.json",
                r#"{"name":"fixture-package","type":"module","exports":"./self.js"}"#,
            );
            project.write("self.js", "export default 5;\n");
        }
        project.write(
            "node_modules/fixture-package/entry.js",
            "export default 1;\n",
        );
        project.write(
            "node_modules/fixture-package/part.js",
            "export default 2;\n",
        );
        project.write(
            "node_modules/fixture-package/decoy.js",
            "export default 3;\n",
        );
        project.write(
            "report.mjs",
            &format!("import value from '{specifier}'; console.log(value);\n"),
        );
        let before = bind(&project, &["report.mjs"], &[]).unwrap();
        let quoted = serde_json::to_string(specifier).unwrap();
        for (mode, expression) in [
            ("module", format!("import {{fileURLToPath}} from 'node:url'; console.log(fileURLToPath(import.meta.resolve({quoted})));")),
            ("commonjs", format!("console.log(require.resolve({quoted}));")),
        ] {
            // Resolve metadata only; the synthetic package body is not run.
            let answer = std::process::Command::new(&node).env_clear().current_dir(&project.0)
                .args(["--input-type", mode, "--eval", &expression]).output().unwrap();
            assert!(answer.status.success(), "{}", String::from_utf8_lossy(&answer.stderr));
            let selected = String::from_utf8(answer.stdout).unwrap().trim().to_owned();
            assert!(before["modules"].as_array().unwrap().iter().any(|entry| entry["path"] == selected),
                "native closure missed the actual {mode} resolver target");
            std::fs::write(&selected, "export default 4;\n").unwrap();
            assert_ne!(before, bind(&project, &["report.mjs"], &[]).unwrap());
        }
    }
}

#[test]
fn installed_nearer_manifestless_package_does_not_fall_through_to_farther_code() {
    let project = installed(r#"{"name":"fixture-package","main":"entry.js"}"#);
    project.write(
        "node_modules/fixture-package/entry.js",
        "module.exports = 1;\n",
    );
    project.write(
        "nested/report.mjs",
        "import value from 'fixture-package'; console.log(value);\n",
    );
    project.write(
        "nested/node_modules/fixture-package/index.js",
        "module.exports = 2;\n",
    );
    assert_eq!(
        bind(&project, &["nested/report.mjs"], &[]),
        Err("node_package_manifest_unproven")
    );
}

#[test]
fn installed_symlink_package_binds_the_real_installed_code() {
    let project = Project::new();
    project.write("package.json", r#"{"type":"module"}"#);
    project.write(
        "report.mjs",
        "import value from 'fixture-package'; console.log(value);\n",
    );
    project.write(
        "store/pkg/package.json",
        r#"{"name":"fixture-package","type":"module","main":"entry.js"}"#,
    );
    project.write("store/pkg/entry.js", "export default 1;\n");
    std::fs::create_dir(project.0.join("node_modules")).unwrap();
    std::os::unix::fs::symlink(
        "../store/pkg",
        project.0.join("node_modules/fixture-package"),
    )
    .unwrap();
    let before = bind(&project, &["report.mjs"], &[]).unwrap();
    assert!(before["modules"].as_array().unwrap().iter().any(|entry| {
        entry["path"]
            .as_str()
            .is_some_and(|path| path.ends_with("store/pkg/entry.js"))
    }));
    project.write("store/pkg/entry.js", "export default 2;\n");
    assert_ne!(before, bind(&project, &["report.mjs"], &[]).unwrap());
}
