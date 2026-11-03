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
            Some(Path::new(&environment["HOME"]))
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
            Some(Path::new(&environment["HOME"]))
        ),
        NpmConfiguredPackages::Unnamed
    );
}
