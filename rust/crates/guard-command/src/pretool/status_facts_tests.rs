use super::safe_status_fact;

fn words(command: &str) -> (String, Vec<String>) {
    let mut parts = command.split_whitespace().map(str::to_string);
    let basename = parts.next().expect("a command word");
    (basename, parts.collect())
}

fn admits(command: &str) -> bool {
    let (basename, arguments) = words(command);
    safe_status_fact(&basename, &arguments)
}

#[test]
fn a_status_reader_prints_counters_sessions_or_unit_state() {
    for command in [
        "w",
        "w -h",
        "who",
        "who -a",
        "who am i",
        "last",
        "last -5",
        "last -n 5",
        "last builder",
        "vm_stat",
        "vm_stat 1",
        "vmstat 1 5",
        "iostat -c 2",
        "iostat -w 1 -c 3",
        "mpstat -P ALL",
        "top -l 1",
        "top -l 1 -o cpu",
        "top -b -n 1",
        "systemctl status",
        "systemctl status web-api.service",
        "systemctl --user is-active timer-sync.timer",
        "systemctl list-units --all",
        "systemctl cat web-api.service",
    ] {
        assert!(admits(command), "{command} reads a host status counter");
    }
}

#[test]
fn a_spelling_that_changes_a_unit_opens_a_file_or_takes_the_terminal_stays_reviewed() {
    for command in [
        "top",
        "top -o cpu",
        "last -f /var/log/wtmp.1",
        "last -F",
        "last ../operator",
        "who /var/run/utmp",
        "w --output report.txt",
        "vm_stat -o counters.txt",
        "iostat -o /var/log/io.out",
        "systemctl start web-api.service",
        "systemctl restart web-api.service",
        "systemctl enable web-api.service",
        "systemctl mask web-api.service",
        "systemctl daemon-reload",
        "systemctl link /srv/units/web-api.service",
        "systemctl status /srv/units/web-api.service",
        "systemctl --force status web-api.service",
    ] {
        assert!(
            !admits(command),
            "{command} changes a unit, opens a file or holds the terminal"
        );
    }
}
