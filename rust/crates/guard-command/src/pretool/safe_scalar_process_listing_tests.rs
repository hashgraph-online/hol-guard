//! Process listing and launchctl argument screens.
fn arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn pgrep_reads_the_children_of_a_parent_id() {
    for values in [
        &["-P", "4120", "-fl", "."][..],
        &["-P", "4120"],
        &["-l", "-P4120,4121"],
        &["-fl", "node"],
    ] {
        assert!(
            super::safe_pgrep_arguments(&arguments(values)),
            "{values:?}"
        );
    }
    for values in [
        &["-P"][..],
        &["-P", "$PID"],
        &["-P", "4120,"],
        &["-Pf", "node"],
        &["-F", "app.pid"],
        &["-P", "4120", "node", "-l"],
        &["node", "python"],
        &[],
    ] {
        assert!(
            !super::safe_pgrep_arguments(&arguments(values)),
            "{values:?}"
        );
    }
}

#[test]
fn launchctl_lists_the_service_table() {
    assert!(super::safe_launchctl_arguments(&arguments(&["list"])));
}

#[test]
fn launchctl_refuses_a_label_or_another_subcommand() {
    for values in [
        // A label prints that job's definition, EnvironmentVariables included.
        &["list", "com.example.agent"][..],
        &["print", "gui/501"][..],
        &["load", "-w", "/Library/LaunchDaemons/com.example.plist"][..],
        &["bootout", "gui/501/com.example.agent"][..],
        &["setenv", "TOKEN", "value"][..],
        &["getenv", "TOKEN"][..],
        &[][..],
    ] {
        assert!(
            !super::safe_launchctl_arguments(&arguments(values)),
            "{values:?}"
        );
    }
}

#[test]
fn ps_reads_a_column_width() {
    assert!(super::safe_ps_arguments(&arguments(&[
        "-o",
        "pid,etime,wchan:30,state",
        "-p",
        "4120",
    ])));
    assert!(!super::safe_ps_arguments(&arguments(&[
        "-o", "pid;id", "-p", "4120",
    ])));
}

#[test]
fn ps_reads_a_bsd_style_column_list() {
    for values in [
        &["axo", "pid=,etime=,command="][..],
        &["axo", "pid,ppid,command"][..],
        &["auxo", "pid,rss"][..],
        &["axopid,command"][..],
        &["axO", "rss"][..],
    ] {
        assert!(super::safe_ps_arguments(&arguments(values)), "{values:?}");
    }
    for values in [
        // BSD `e` prints every listed process's environment.
        &["axeo", "pid,command"][..],
        &["axoe", "pid,command"][..],
        &["axo"][..],
        &["axo", "pid;id"][..],
        &["axo", "pid", "e"][..],
    ] {
        assert!(!super::safe_ps_arguments(&arguments(values)), "{values:?}");
    }
}
