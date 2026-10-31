use super::{
    audit_arguments, hook_module_absent, inert_setting_line, outdated_arguments, settings_inert,
};

fn arguments(text: &str) -> Vec<String> {
    text.split_whitespace().map(str::to_owned).collect()
}

#[test]
fn an_outdated_report_takes_display_flags_and_package_names() {
    for text in [
        "",
        "--json",
        "--long",
        "--compatible",
        "--no-table",
        "--format=json",
        "--recursive",
        "-r",
        "zod",
        "@types/node react --json",
        "zod@^3",
    ] {
        assert!(outdated_arguments(&arguments(text)), "{text}");
    }
    for text in [
        "--dir packages/api",
        "--filter ./packages/api",
        "-g",
        "--global",
        "-w",
        "--workspace-root",
        "--registry=https://registry.example.test",
        "--format=yaml",
        "./local",
        "zod@npm:other",
        "https://example.test/pkg.tgz",
    ] {
        assert!(!outdated_arguments(&arguments(text)), "{text}");
    }
}

#[test]
fn an_advisory_report_reads_both_spellings_of_the_severity_bound() {
    for text in [
        "",
        "--json",
        "--recursive",
        "-r",
        "--dev",
        "--prod",
        "--no-optional",
        "--ignore-registry-errors",
        "--audit-level=high",
        "--audit-level high",
        "--audit-level moderate --json",
    ] {
        assert!(audit_arguments(&arguments(text)), "{text}");
    }
    for text in [
        "--fix",
        "--audit-level",
        "--audit-level none",
        "--audit-level=none",
        "--audit-level --json",
        "zod",
        "--dir packages/api",
    ] {
        assert!(!audit_arguments(&arguments(text)), "{text}");
    }
}

#[test]
fn a_hook_module_above_the_working_directory_keeps_the_review() {
    let root = tempfile::tempdir().expect("temp dir");
    let project = root.path().join("project");
    let nested = project.join("packages").join("api");
    std::fs::create_dir_all(&nested).expect("nested directories");
    fn context<'a>(home: &'a str, cwd: &'a str) -> super::super::PathContext<'a> {
        super::super::PathContext {
            home_dir: Some(home),
            cwd: Some(cwd),
            ..Default::default()
        }
    }
    let home = root.path().to_str().expect("utf-8 root");
    let nested = nested.to_str().expect("utf-8 nested");
    let project_cwd = project.to_str().expect("utf-8 project");

    assert!(hook_module_absent(context(home, nested)));

    std::fs::write(project.join(".pnpmfile.cjs"), "module.exports = {};\n").expect("hook module");
    assert!(!hook_module_absent(context(home, nested)));
    assert!(!hook_module_absent(context(home, project_cwd)));
}

#[test]
fn a_relative_or_missing_working_directory_proves_nothing() {
    let relative = super::super::PathContext {
        cwd: Some("project"),
        ..Default::default()
    };
    assert!(!hook_module_absent(relative));
    assert!(!hook_module_absent(super::super::PathContext::default()));
}

#[test]
fn either_spelling_of_the_hook_module_keeps_the_review() {
    for name in [".pnpmfile.cjs", ".pnpmfile.mjs"] {
        let root = tempfile::tempdir().expect("temp dir");
        let nested = root.path().join("project").join("packages");
        std::fs::create_dir_all(&nested).expect("nested directories");
        let home = root.path().to_str().expect("utf-8 root").to_owned();
        let nested = nested.to_str().expect("utf-8 nested").to_owned();
        let context = |home: &str, cwd: &str| super::super::PathContext {
            home_dir: Some(home),
            cwd: Some(cwd),
            ..Default::default()
        };
        assert!(hook_module_absent(context(&home, &nested)), "{name}");
        std::fs::write(
            root.path().join("project").join(name),
            "module.exports = {};\n",
        )
        .expect("hook module");
        assert!(!hook_module_absent(context(&home, &nested)), "{name}");
    }
}

#[test]
fn a_settings_line_that_moves_the_fetch_or_the_hook_module_is_not_inert() {
    for line in [
        "",
        "# registry: https://registry.example.test",
        "packages:",
        "  - 'packages/*'",
        "onlyBuiltDependencies:",
        "  - esbuild",
        "nodeVersion: \"22.22.3\"",
        "saveExact: true",
        "minimumReleaseAge: 1440",
        "catalog:",
        "  zod: ^3.23.8",
    ] {
        assert!(inert_setting_line(line), "{line}");
    }
    for line in [
        "registry: https://registry.example.test",
        "  registry: https://registry.example.test",
        "- registry: https://registry.example.test",
        "registries:",
        "  '@scope:registry': https://registry.example.test",
        "pnpmfile: ./hooks.cjs",
        "globalPnpmfile: ./hooks.cjs",
        "configDependencies:",
        "strictSsl: false",
        "strict-ssl: false",
        "cafile: /tmp/ca.pem",
        "globalDir: /tmp/pnpm",
        "nodeOptions: --require /tmp/hook.js",
        "'//registry.example.test/:_authToken': secret",
        "//registry.example.test/:_authToken: secret",
        "@scope:registry: https://registry.example.test",
        "\"${PREFIX}registry\": https://registry.example.test",
    ] {
        assert!(!inert_setting_line(line), "{line}");
    }
}

#[test]
fn pnpms_own_settings_files_are_read_beside_npms() {
    let root = tempfile::tempdir().expect("temp dir");
    let home = root.path().join("home");
    let project = home.join("project");
    let nested = project.join("packages").join("api");
    let configuration = home.join(".config").join("pnpm");
    std::fs::create_dir_all(&nested).expect("nested directories");
    std::fs::create_dir_all(&configuration).expect("configuration directory");
    let home = home.to_str().expect("utf-8 home").to_owned();
    let nested_text = nested.to_str().expect("utf-8 nested").to_owned();
    let context = |home: &str, cwd: &str| super::super::PathContext {
        home_dir: Some(home),
        cwd: Some(cwd),
        ..Default::default()
    };

    assert!(settings_inert(context(&home, &nested_text)));

    let manifest = project.join("pnpm-workspace.yaml");
    std::fs::write(&manifest, "packages:\n  - 'packages/*'\n").expect("workspace manifest");
    assert!(settings_inert(context(&home, &nested_text)));
    std::fs::write(
        &manifest,
        "packages:\n  - 'packages/*'\nregistry: https://registry.example.test\n",
    )
    .expect("workspace manifest");
    assert!(!settings_inert(context(&home, &nested_text)));
    std::fs::remove_file(&manifest).expect("remove workspace manifest");

    let global = configuration.join("config.yaml");
    std::fs::write(&global, "storeDir: /tmp/store\n").expect("global settings");
    assert!(settings_inert(context(&home, &nested_text)));
    std::fs::write(&global, "registry: https://registry.example.test\n").expect("global settings");
    assert!(!settings_inert(context(&home, &nested_text)));
    std::fs::remove_file(&global).expect("remove global settings");

    for name in ["rc", "auth.ini"] {
        let ini = configuration.join(name);
        std::fs::write(&ini, "loglevel=warn\n").expect("ini settings");
        assert!(settings_inert(context(&home, &nested_text)), "{name}");
        std::fs::write(&ini, "registry=https://registry.example.test\n").expect("ini settings");
        assert!(!settings_inert(context(&home, &nested_text)), "{name}");
        std::fs::remove_file(&ini).expect("remove ini settings");
    }
}

#[test]
fn a_relative_home_or_working_directory_proves_no_settings() {
    assert!(!settings_inert(super::super::PathContext {
        home_dir: Some("home"),
        cwd: Some("/tmp"),
        ..Default::default()
    }));
    assert!(!settings_inert(super::super::PathContext::default()));
}
