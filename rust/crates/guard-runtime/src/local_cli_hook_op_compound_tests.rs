//! A compound command that runs a changed script names the script's connector.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use super::*;

fn script(fixture: &Fixture, name: &str, body: &str) -> PathBuf {
    let path = std::path::Path::new(&fixture.workspace).join(name);
    fs::write(&path, body).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    fs::canonicalize(&path).unwrap()
}

fn review(fixture: &Fixture, command: &str) -> LocalCliHookRequestV1 {
    let mut request = fixture.request(command, "review", true);
    request
        .env
        .insert("PATH".to_owned(), "/usr/bin:/bin".to_owned());
    request
}

#[test]
fn a_compound_command_running_a_changed_script_names_its_connector() {
    let fixture = Fixture::new("compound-changed");
    let merge = script(&fixture, "approve-merge.sh", "#!/bin/sh\necho ready\n");
    let single = review(&fixture, &format!("{} --dry-run", merge.display()));
    let named = run_with_connector(&single)
        .unwrap()
        .1
        .expect("the script is named");
    let cli_id = named["cli_id"].as_str().unwrap().to_owned();
    let compound = format!(
        "cd {} && {} --dry-run | tail -5",
        fixture.workspace,
        merge.display()
    );

    // Never decided: a compound review keeps its ordinary card.
    assert_eq!(
        run_with_connector(&review(&fixture, &compound)).unwrap(),
        ("review".to_owned(), None)
    );

    // Allowed for an earlier version of the file: the card offers this version.
    fixture.grant(&cli_id, &"0".repeat(64), "allowed");
    let request = review(&fixture, &compound);
    let (action, connector) = run_with_connector(&request).unwrap();
    assert_eq!(action, "review", "naming the connector changes no action");
    let connector = connector.expect("the changed script is named");
    assert_eq!(connector["cli_id"], cli_id.as_str());
    assert_eq!(connector["identity_hash"], named["identity_hash"]);
    assert_eq!(connector["allowed_earlier_version"], true);
    assert_eq!(
        connector["queue_group_id"],
        crate::connector_setup::queue_group_id(
            connector["identity_hash"].as_str().unwrap(),
            &request.cwd,
            &compound
        )
    );
}

#[test]
fn a_compound_command_running_two_scripts_names_neither() {
    let fixture = Fixture::new("compound-two");
    let merge = script(&fixture, "approve-merge.sh", "#!/bin/sh\necho ready\n");
    let other = script(&fixture, "release.sh", "#!/bin/sh\necho release\n");
    for path in [&merge, &other] {
        let named = run_with_connector(&review(&fixture, &format!("{} go", path.display())))
            .unwrap()
            .1
            .unwrap();
        fixture.grant(
            named["cli_id"].as_str().unwrap(),
            &"0".repeat(64),
            "allowed",
        );
    }
    let compound = format!("{} go && {} go", merge.display(), other.display());
    assert_eq!(
        run_with_connector(&review(&fixture, &compound)).unwrap(),
        ("review".to_owned(), None)
    );
}

#[test]
fn a_compound_command_running_a_current_script_is_not_sent_to_setup() {
    let fixture = Fixture::new("compound-current");
    let merge = script(&fixture, "approve-merge.sh", "#!/bin/sh\necho ready\n");
    let named = run_with_connector(&review(&fixture, &format!("{} go", merge.display())))
        .unwrap()
        .1
        .unwrap();
    fixture.grant(
        named["cli_id"].as_str().unwrap(),
        named["identity_hash"].as_str().unwrap(),
        "allowed",
    );
    let compound = format!("cd {} && {} go", fixture.workspace, merge.display());
    assert_eq!(
        run_with_connector(&review(&fixture, &compound)).unwrap(),
        ("review".to_owned(), None)
    );
}

#[test]
fn changed_script_after_cd_with_relative_path_names_exact_connector() {
    let fixture = Fixture::new("compound-relative");
    let merge = script(&fixture, "approve-merge.sh", "#!/bin/sh\necho ready\n");
    let named = run_with_connector(&review(&fixture, &format!("{} --dry-run", merge.display())))
        .unwrap()
        .1
        .expect("single script is named");
    fixture.grant(named["cli_id"].as_str().unwrap(), &"0".repeat(64), "allowed");

    let relative = format!("cd {} && ./approve-merge.sh --dry-run", fixture.workspace);
    let (action, connector) = run_with_connector(&review(&fixture, &relative)).unwrap();
    assert_eq!(action, "review");
    let connector = connector.expect("relative changed script names its connector");
    assert_eq!(connector["cli_id"], named["cli_id"]);
    assert_eq!(connector["identity_hash"], named["identity_hash"]);
    assert_eq!(connector["allowed_earlier_version"], true);

    // A failed directory change, semicolon, or extra command is not proven.
    for command in [
        format!("cd {} ; ./approve-merge.sh --dry-run", fixture.workspace),
        format!("cd {} && ./approve-merge.sh --dry-run && echo done", fixture.workspace),
        "cd /this-does-not-exist && ./approve-merge.sh --dry-run".to_owned(),
    ] {
        let (action, connector) = run_with_connector(&review(&fixture, &command)).unwrap();
        assert_eq!(action, "review");
        assert!(connector.is_none(), "unexpected connector: {command}");
    }
}
