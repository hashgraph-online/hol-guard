//! An `npx` segment whose directory the shell could not place.

use std::fs;
use std::path::Path;

use super::{
    configured_packages_for_segment, parse_package_intent, project, tokens, NpmConfiguredPackages,
};

#[test]
fn an_unresolved_directory_does_not_invent_a_package() {
    let (dir, project, environment) = project();
    fs::create_dir_all(project.join("app")).unwrap();
    fs::create_dir_all(project.join("dashboard")).unwrap();
    let home = Path::new(&environment["HOME"]);
    // `cd app` sticks, so `cd dashboard` looks inside `app` and cannot be
    // placed. That is the benign gate command, and neither launch has a
    // package setting.
    let intent = parse_package_intent(
        "{ cd app && npx vitest run; } && { cd dashboard && npx vitest run; }",
        Some(&project),
        Some(home),
        None,
        Some(&environment),
    )
    .expect("npx intent");

    assert_eq!(
        intent
            .targets
            .iter()
            .map(|target| target.package_name.as_deref())
            .collect::<Vec<_>>(),
        vec![Some("vitest"), Some("vitest")]
    );
    assert!(intent
        .targets
        .iter()
        .all(|target| target.source_invalid_reason.is_none()));
    let _ = dir;
}

#[test]
fn an_environment_package_still_names_the_install_when_the_directory_is_unresolved() {
    let (_dir, _project, mut environment) = project();
    environment.insert("npm_config_package".to_owned(), "left-pad".to_owned());

    assert_eq!(
        configured_packages_for_segment(
            &tokens(&["npx", "vitest"]),
            &tokens(&["npx", "vitest"]),
            &environment,
            None,
            Some(Path::new(&environment["HOME"])),
            true
        ),
        NpmConfiguredPackages::Named(vec!["left-pad".to_owned()])
    );
}

#[test]
fn a_config_redirect_keeps_the_package_unnamed_when_the_directory_is_unresolved() {
    let (_dir, _project, mut environment) = project();
    environment.insert(
        "npm_config_userconfig".to_owned(),
        "/elsewhere/npmrc".to_owned(),
    );

    assert_eq!(
        configured_packages_for_segment(
            &tokens(&["npx", "vitest"]),
            &tokens(&["npx", "vitest"]),
            &environment,
            None,
            Some(Path::new(&environment["HOME"])),
            true
        ),
        NpmConfiguredPackages::Unnamed
    );
}

#[test]
fn a_directory_the_shell_could_not_name_keeps_the_package_unnamed() {
    let (dir, project, environment) = project();
    let home = Path::new(&environment["HOME"]);
    // The variable is the real project, and both npmrcs name a package.
    // The model cannot place `$DIR`, so neither file is allowed to become
    // the reviewed name: the project file would win, and it was not read.
    fs::write(home.join(".npmrc"), "package=left-pad\n").unwrap();
    fs::write(project.join(".npmrc"), "package=evil\n").unwrap();
    let mut launched = environment.clone();
    launched.insert("DIR".to_owned(), project.to_string_lossy().into_owned());

    let intent = parse_package_intent(
        r#"cd "$DIR" && npx vitest run"#,
        Some(&project),
        Some(home),
        None,
        Some(&launched),
    )
    .expect("npx intent");

    assert_eq!(intent.targets.len(), 1);
    assert!(intent.targets[0].package_name.is_none());
    assert_eq!(
        intent.targets[0].source_invalid_reason.as_deref(),
        Some("npm_config_package_unidentified")
    );
    let _ = dir;
}

#[test]
fn a_cd_after_a_failed_cd_keeps_the_package_unnamed() {
    let (dir, project, environment) = project();
    let app = project.join("app");
    fs::create_dir_all(&app).unwrap();
    fs::write(app.join(".npmrc"), "package=evil\n").unwrap();
    let home = Path::new(&environment["HOME"]);
    fs::write(home.join(".npmrc"), "package=left-pad\n").unwrap();
    // The first `cd` fails. The shell stays put, so `cd app && npx` runs
    // and npm reads both npmrc files. The model copies the missing-directory
    // reason onto that second `cd`.
    let command = format!("cd /nonexistent; cd {} && npx vitest run", app.display());

    let intent = parse_package_intent(
        &command,
        Some(&project),
        Some(home),
        None,
        Some(&environment),
    )
    .expect("npx intent");

    assert_eq!(intent.targets.len(), 1);
    assert!(intent.targets[0].package_name.is_none());
    assert_eq!(
        intent.targets[0].source_invalid_reason.as_deref(),
        Some("npm_config_package_unidentified")
    );
    let _ = dir;
}

#[test]
fn a_skipped_launch_does_not_read_home_config() {
    let (_dir, _project, environment) = project();
    let home = Path::new(&environment["HOME"]);
    fs::write(home.join(".npmrc"), "package=left-pad\n").unwrap();

    assert_eq!(
        configured_packages_for_segment(
            &tokens(&["npx", "vitest"]),
            &tokens(&["npx", "vitest"]),
            &environment,
            None,
            Some(home),
            false
        ),
        NpmConfiguredPackages::Absent
    );
}
