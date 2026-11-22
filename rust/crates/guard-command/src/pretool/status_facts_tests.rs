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
fn a_status_reader_prints_counters_samples_or_login_sessions() {
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
        "vmstat -s",
        "iostat -c 2",
        "iostat -w 1 -c 3",
        "iostat -x -d 2 3",
        "mpstat -P ALL",
        "mpstat -A",
        "pidstat -u -p ALL",
        "top -l 1",
        "top -l 1 -o cpu",
        "top -b -n 1",
    ] {
        assert!(admits(command), "{command} reads a host status counter");
    }
}

#[test]
fn a_spelling_that_opens_a_file_takes_the_terminal_or_asks_about_a_unit_stays_reviewed() {
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
        "vmstat -f ../operator/.ssh/config",
        "mpstat --outfile=report.txt",
        "systemctl status web-api.service",
        "systemctl is-active web-api.service",
        "systemctl start web-api.service",
    ] {
        assert!(
            !admits(command),
            "{command} opens a file, holds the terminal or reports on a unit"
        );
    }
}
