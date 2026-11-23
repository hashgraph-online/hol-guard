//! Host, account and terminal facts: the reading spelling of each name
//! proves, and the spelling that assigns, execs or opens a file does not.

fn arguments(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

#[test]
fn a_fact_about_the_host_prints_and_runs_nothing() {
    for (executable, values) in [
        ("nproc", vec![]),
        ("nproc", vec!["--all"]),
        ("sw_vers", vec![]),
        ("sw_vers", vec!["-productVersion"]),
        ("arch", vec![]),
        ("hostname", vec![]),
        ("hostname", vec!["-s"]),
        ("id", vec![]),
        ("id", vec!["-u"]),
        ("id", vec!["-un"]),
        ("id", vec!["builder"]),
        ("groups", vec![]),
        ("groups", vec!["builder"]),
        ("locale", vec![]),
        ("locale", vec!["-a"]),
        ("locale", vec!["LC_TIME"]),
        ("tput", vec!["cols"]),
        ("tput", vec!["lines"]),
        ("stty", vec!["size"]),
        ("seq", vec!["1", "10"]),
        ("seq", vec!["-w", "1", "2", "10"]),
        ("seq", vec!["-s", ",", "1", "5"]),
        ("expr", vec!["1", "+", "2"]),
        ("col", vec!["-b"]),
        ("cal", vec![]),
        ("cal", vec!["2026"]),
        ("cal", vec!["11", "2026"]),
        ("cal", vec!["-y"]),
        ("tty", vec![]),
        ("tty", vec!["-s"]),
        ("ulimit", vec!["-n"]),
        ("ulimit", vec!["-a"]),
        ("ulimit", vec!["-Sn"]),
        ("ulimit", vec!["-Hn"]),
        ("ulimit", vec!["-S", "-n"]),
        ("ulimit", vec!["-Ss", "-Hs"]),
        ("sysctl", vec!["-n", "hw.ncpu"]),
        ("sysctl", vec!["hw.memsize"]),
        ("sysctl", vec!["-a"]),
        ("getconf", vec!["_NPROCESSORS_ONLN"]),
        ("getconf", vec!["-a"]),
    ] {
        assert!(
            super::safe_host_fact(executable, &arguments(&values)),
            "{executable} {values:?}"
        );
    }
}

#[test]
fn a_spelling_that_assigns_execs_or_opens_a_file_stays_reviewed() {
    for (executable, values) in [
        // Sets the system name rather than printing it.
        ("hostname", vec!["build-box"]),
        // Runs the named program under a chosen architecture.
        ("arch", vec!["-x86_64", "/bin/sh"]),
        ("arch", vec!["-arch", "arm64", "node"]),
        // Reconfigures the terminal.
        ("stty", vec!["-echo"]),
        ("stty", vec!["raw"]),
        ("stty", vec!["size", "-a"]),
        // Writes control sequences that reset the terminal.
        ("tput", vec!["reset"]),
        ("tput", vec!["init"]),
        ("tput", vec![]),
        // Opens a file operand.
        ("bc", vec!["-l"]),
        ("bc", vec!["budget.bc"]),
        ("col", vec!["report.txt"]),
        // Operands that are paths rather than accounts or keywords.
        ("id", vec!["../root"]),
        ("id", vec!["one", "two"]),
        ("groups", vec!["-a"]),
        ("locale", vec!["/etc/locale.conf"]),
        // Options outside each screen.
        ("nproc", vec!["--ignore=2"]),
        ("sw_vers", vec!["-setInstallationVersion"]),
        // Bounds that are not numbers.
        ("seq", vec!["start", "10"]),
        ("seq", vec!["1", "2", "3", "4"]),
        ("seq", vec!["-s"]),
        ("seq", vec![]),
        ("expr", vec![]),
        // Names this screen does not model at all.
        ("curl", vec!["--version"]),
        // Raises or lowers the limit rather than printing it.
        ("ulimit", vec!["-n", "4096"]),
        ("ulimit", vec!["-Sn", "4096"]),
        ("ulimit", vec!["-n4096"]),
        ("ulimit", vec!["-"]),
        ("ulimit", vec!["--"]),
        ("ulimit", vec!["-Sx"]),
        ("ulimit", vec![]),
        // Sets kernel state rather than reading it.
        ("sysctl", vec!["-w", "kern.maxfiles=100"]),
        ("sysctl", vec!["kern.maxfiles=100"]),
        // Loads settings from a file.
        ("sysctl", vec!["-p", "limits.conf"]),
        // Queries a path rather than naming one configuration value.
        ("getconf", vec!["PATH_MAX", "/srv/data"]),
        // A calendar takes numbers; an operand that is not one is not a date.
        ("cal", vec!["notes.txt"]),
        ("cal", vec!["1", "2", "3"]),
        // `tty` has no operand.
        ("tty", vec!["/dev/ttys001"]),
    ] {
        assert!(
            !super::safe_host_fact(executable, &arguments(&values)),
            "{executable} {values:?}"
        );
    }
}
