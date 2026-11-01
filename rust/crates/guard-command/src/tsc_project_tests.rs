//! What a `tsc` run's own project says about emitting, read from disk.
//!
//! Every case plants a real config tree, because the reading is a sequence of
//! filesystem answers: what resolves, what a symlink moved, what parses, and
//! what an `extends` chain adds. A case that only built argv would exercise
//! none of it.

use std::fs;
use std::path::Path;

use tempfile::TempDir;

use super::declares_no_emit;

fn words(arguments: &[&str]) -> Vec<String> {
    arguments.iter().map(|word| (*word).to_owned()).collect()
}

fn plant(directory: &Path, name: &str, body: &str) {
    if let Some(parent) = Path::new(name).parent() {
        fs::create_dir_all(directory.join(parent)).expect("config directory");
    }
    fs::write(directory.join(name), body).expect("config");
}

/// A project directory under its own temporary root, so a case that walks
/// outwards has somewhere outside to walk to.
fn project() -> (TempDir, std::path::PathBuf) {
    let root = tempfile::tempdir().expect("temp root");
    let directory = root.path().join("project");
    fs::create_dir(&directory).expect("project directory");
    (root, directory)
}

fn reads_no_emit(arguments: &[&str], directory: &Path) -> bool {
    declares_no_emit(&words(arguments), Some(directory))
}

#[test]
fn a_named_project_declaring_no_emit_emits_nothing() {
    let (_root, directory) = project();
    plant(
        &directory,
        "tsconfig.check.json",
        r#"{"compilerOptions":{"noEmit":true}}"#,
    );

    assert!(reads_no_emit(&["-p", "tsconfig.check.json"], &directory));
    assert!(reads_no_emit(
        &["--project", "tsconfig.check.json"],
        &directory
    ));
    assert!(reads_no_emit(
        &["--project=tsconfig.check.json"],
        &directory
    ));
}

#[test]
fn a_run_naming_no_project_reads_the_default_config() {
    let (_root, directory) = project();
    plant(
        &directory,
        "tsconfig.json",
        r#"{"compilerOptions":{"noEmit":true}}"#,
    );

    assert!(reads_no_emit(&[], &directory));
    assert!(reads_no_emit(&["--pretty", "false"], &directory));
}

#[test]
fn a_named_directory_reads_the_config_inside_it() {
    let (_root, directory) = project();
    plant(
        &directory,
        "config/tsconfig.json",
        r#"{"compilerOptions":{"noEmit":true}}"#,
    );

    assert!(reads_no_emit(&["-p", "config"], &directory));
}

#[test]
fn comments_and_trailing_commas_are_read_like_tsc_reads_them() {
    let (_root, directory) = project();
    plant(
        &directory,
        "tsconfig.json",
        "{\n  // the generated type-check project\n  \"compilerOptions\": {\n    \"noEmit\": true,\n  },\n}\n",
    );

    assert!(reads_no_emit(&[], &directory));
}

#[test]
fn a_project_that_never_says_so_gives_no_verdict() {
    let (_root, directory) = project();
    plant(
        &directory,
        "tsconfig.json",
        r#"{"compilerOptions":{"strict":true}}"#,
    );

    assert!(!reads_no_emit(&[], &directory));
}

#[test]
fn a_project_declaring_emit_gives_no_verdict() {
    let (_root, directory) = project();
    plant(
        &directory,
        "tsconfig.json",
        r#"{"compilerOptions":{"noEmit":false}}"#,
    );

    assert!(!reads_no_emit(&[], &directory));
}

#[test]
fn a_value_that_is_not_a_boolean_gives_no_verdict() {
    let (_root, directory) = project();
    plant(
        &directory,
        "tsconfig.json",
        r#"{"compilerOptions":{"noEmit":"true"}}"#,
    );

    assert!(!reads_no_emit(&[], &directory));
}

#[test]
fn a_missing_or_unparsable_project_gives_no_verdict() {
    let (_root, directory) = project();

    assert!(!reads_no_emit(&["-p", "tsconfig.json"], &directory));

    plant(&directory, "tsconfig.json", "{\"compilerOptions\":");
    assert!(!reads_no_emit(&[], &directory));
}

/// `--noEmit` stops the JavaScript, not the build-info file: tsc still writes
/// `.tsbuildinfo` beside the project, which the contained profile refuses.
#[test]
fn a_build_info_project_gives_no_verdict() {
    for option in [
        r#""incremental":true"#,
        r#""composite":true"#,
        r#""tsBuildInfoFile":".cache/build.tsbuildinfo""#,
    ] {
        let (_root, directory) = project();
        plant(
            &directory,
            "tsconfig.json",
            &format!(r#"{{"compilerOptions":{{"noEmit":true,{option}}}}}"#),
        );

        assert!(!reads_no_emit(&[], &directory), "{option}");
    }
}

#[test]
fn a_build_info_option_on_the_command_line_gives_no_verdict() {
    let (_root, directory) = project();
    plant(
        &directory,
        "tsconfig.json",
        r#"{"compilerOptions":{"noEmit":true}}"#,
    );

    for argument in [
        "-b",
        "--build",
        "--incremental",
        "--composite",
        "--tsBuildInfoFile",
        "--incremental=true",
        "--composite=true",
        "--tsBuildInfoFile=out.tsbuildinfo",
    ] {
        assert!(!reads_no_emit(&[argument], &directory), "{argument}");
    }
}

#[test]
fn a_relative_base_inside_the_run_directory_is_followed() {
    let (_root, directory) = project();
    plant(
        &directory,
        "base.json",
        r#"{"compilerOptions":{"noEmit":true}}"#,
    );
    plant(&directory, "tsconfig.json", r#"{"extends":"./base.json"}"#);
    plant(&directory, "named.json", r#"{"extends":"./base"}"#);

    assert!(reads_no_emit(&[], &directory));
    assert!(reads_no_emit(&["-p", "named.json"], &directory));
}

/// The project's own answer overrides the base it extends, which is how tsc
/// merges them.
#[test]
fn the_project_overrides_the_base_it_extends() {
    let (_root, directory) = project();
    plant(
        &directory,
        "base.json",
        r#"{"compilerOptions":{"noEmit":true}}"#,
    );
    plant(
        &directory,
        "tsconfig.json",
        r#"{"extends":"./base.json","compilerOptions":{"noEmit":false}}"#,
    );

    assert!(!reads_no_emit(&[], &directory));
}

/// A base may be the one that turns the build-info file on, and the run reads
/// it either way.
#[test]
fn a_base_that_writes_build_info_gives_no_verdict() {
    let (_root, directory) = project();
    plant(
        &directory,
        "base.json",
        r#"{"compilerOptions":{"incremental":true}}"#,
    );
    plant(
        &directory,
        "tsconfig.json",
        r#"{"extends":"./base.json","compilerOptions":{"noEmit":true}}"#,
    );

    assert!(!reads_no_emit(&[], &directory));
}

#[test]
fn a_base_this_reading_does_not_resolve_gives_no_verdict() {
    let (_root, directory) = project();
    for specifier in [
        r#""@tsconfig/node20/tsconfig.json""#,
        r#""/etc/tsconfig.json""#,
        r#"["./a.json","./b.json"]"#,
        r#""./missing.json""#,
    ] {
        plant(
            &directory,
            "tsconfig.json",
            &format!(r#"{{"extends":{specifier},"compilerOptions":{{"noEmit":true}}}}"#),
        );

        assert!(!reads_no_emit(&[], &directory), "{specifier}");
    }
}

#[test]
fn a_base_outside_the_run_directory_gives_no_verdict() {
    let (root, directory) = project();
    plant(
        root.path(),
        "outside/base.json",
        r#"{"compilerOptions":{"noEmit":true}}"#,
    );
    plant(
        &directory,
        "tsconfig.json",
        r#"{"extends":"../outside/base.json"}"#,
    );

    assert!(!reads_no_emit(&[], &directory));
}

#[test]
fn a_project_outside_the_run_directory_gives_no_verdict() {
    let (root, directory) = project();
    plant(
        root.path(),
        "outside/tsconfig.json",
        r#"{"compilerOptions":{"noEmit":true}}"#,
    );

    assert!(!reads_no_emit(
        &["-p", "../outside/tsconfig.json"],
        &directory
    ));
    assert!(!reads_no_emit(
        &[
            "-p",
            &root.path().join("outside/tsconfig.json").to_string_lossy()
        ],
        &directory
    ));
}

#[test]
fn a_chain_longer_than_the_bound_gives_no_verdict() {
    let (_root, directory) = project();
    plant(
        &directory,
        "l4.json",
        r#"{"compilerOptions":{"noEmit":true}}"#,
    );
    for (name, base) in [
        ("l3.json", "./l4.json"),
        ("l2.json", "./l3.json"),
        ("l1.json", "./l2.json"),
    ] {
        plant(&directory, name, &format!(r#"{{"extends":"{base}"}}"#));
    }
    plant(&directory, "tsconfig.json", r#"{"extends":"./l1.json"}"#);

    // tsconfig -> l1 -> l2 -> l3 is the bound; the fifth file is one link too
    // far, so the same chain one link shorter still answers.
    assert!(!reads_no_emit(&[], &directory));
    assert!(reads_no_emit(&["-p", "l1.json"], &directory));
}

#[test]
fn a_run_with_no_directory_reads_its_command_line_alone() {
    let (_root, directory) = project();
    plant(
        &directory,
        "tsconfig.json",
        r#"{"compilerOptions":{"noEmit":true}}"#,
    );

    assert!(!declares_no_emit(&words(&["-p", "tsconfig.json"]), None));
}

#[cfg(unix)]
#[test]
fn a_config_a_symlink_moved_gives_no_verdict() {
    use std::os::unix::fs::symlink;

    let (root, directory) = project();
    plant(
        root.path(),
        "outside/tsconfig.json",
        r#"{"compilerOptions":{"noEmit":true}}"#,
    );
    symlink(
        root.path().join("outside/tsconfig.json"),
        directory.join("tsconfig.json"),
    )
    .expect("symlink");

    assert!(!reads_no_emit(&[], &directory));
}

#[cfg(unix)]
#[test]
fn a_base_a_symlink_moved_outside_gives_no_verdict() {
    use std::os::unix::fs::symlink;

    let (root, directory) = project();
    plant(
        root.path(),
        "outside/base.json",
        r#"{"compilerOptions":{"noEmit":true}}"#,
    );
    symlink(
        root.path().join("outside/base.json"),
        directory.join("base.json"),
    )
    .expect("symlink");
    plant(&directory, "tsconfig.json", r#"{"extends":"./base.json"}"#);

    assert!(!reads_no_emit(&[], &directory));
}

#[cfg(unix)]
#[test]
fn a_directory_a_symlink_moved_outside_gives_no_verdict() {
    use std::os::unix::fs::symlink;

    let (root, directory) = project();
    plant(
        root.path(),
        "outside/tsconfig.json",
        r#"{"compilerOptions":{"noEmit":true}}"#,
    );
    // The name the run gives steps through a link, not onto one: only the
    // resolved path shows that the config it reaches is outside.
    symlink(root.path().join("outside"), directory.join("config")).expect("symlink");

    assert!(!reads_no_emit(&["-p", "config/tsconfig.json"], &directory));
    assert!(!reads_no_emit(&["-p", "config"], &directory));
}
