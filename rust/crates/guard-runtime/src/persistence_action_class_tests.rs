use super::action_class_writes_persistence_agent;

#[test]
fn a_label_naming_a_boot_or_login_mechanism_is_recognized() {
    for label in [
        "writes a launch agent plist",
        "adds a Login Item",
        "launchctl bootstrap",
        "installs a crontab entry",
        "enables a systemd unit",
        "launchd job registration",
        "LAUNCH AGENT INSTALL",
        // The rule reads a substring, so a longer word carrying one of the
        // mechanisms still matches. Narrowing that here would stop a label
        // the posture used to block on.
        "launch agentless collector",
    ] {
        assert!(
            action_class_writes_persistence_agent(Some(label)),
            "{label}"
        );
    }
}

#[test]
fn a_label_naming_no_such_mechanism_is_not_one() {
    for label in [
        "shell command execution",
        "package install",
        "repository code execution",
        // The table reads "launch agent" with the space the prose labels use,
        // so a run-together spelling is not one of its mechanisms. Python read
        // the same six tokens the same way; widening the table here would stop
        // actions the previous posture let through.
        "writes a LaunchAgent plist",
        "",
    ] {
        assert!(
            !action_class_writes_persistence_agent(Some(label)),
            "{label}"
        );
    }
}

#[test]
fn an_artifact_without_an_action_class_label_names_no_mechanism() {
    assert!(!action_class_writes_persistence_agent(None));
}
