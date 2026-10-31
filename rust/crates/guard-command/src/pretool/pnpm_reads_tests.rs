use super::{audit_arguments, hook_module_absent, outdated_arguments};

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
        "-g",
        "zod",
        "@types/node react --json",
        "zod@^3",
    ] {
        assert!(outdated_arguments(&arguments(text)), "{text}");
    }
    for text in [
        "--dir packages/api",
        "--filter ./packages/api",
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
