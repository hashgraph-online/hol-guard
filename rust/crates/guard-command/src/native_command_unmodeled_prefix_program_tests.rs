//! Walking a launcher's own options to the program it runs.
use super::{
    command_reads_a_program_file, is_launcher, launch_only, prefix_reads_a_program_file,
    program_index,
};

fn program(command: &str) -> Option<&str> {
    let words: Vec<&str> = command.split_whitespace().collect();
    program_index(&words).map(|index| words[index])
}

fn reads(command: &str) -> bool {
    prefix_reads_a_program_file(&command.split_whitespace().collect::<Vec<&str>>())
}

/// Each launcher's documented options, counted through to the program.
#[test]
fn a_launchers_options_are_counted_past() {
    for (command, expected) in [
        ("nice cargo build", "cargo"),
        ("nice -n 10 cargo build", "cargo"),
        ("nice -n10 cargo build", "cargo"),
        ("nice --adjustment=10 cargo build", "cargo"),
        ("nice --adjustment 10 cargo build", "cargo"),
        // `nice -10 cmd` is the adjustment spelled on its own.
        ("nice -10 cargo build", "cargo"),
        ("nohup npm start", "npm"),
        ("setsid -f -w npm run dev", "npm"),
        ("stdbuf -oL npm test", "npm"),
        ("stdbuf -o L npm test", "npm"),
        ("stdbuf -i0 -o0 -e0 cargo test", "cargo"),
        ("stdbuf --output=L npm test", "npm"),
        ("timeout 30 npm test", "npm"),
        ("timeout -k 5 30 npm test", "npm"),
        ("timeout -s KILL 30 cargo build", "cargo"),
        ("timeout --preserve-status 5m npm run build", "npm"),
        ("timeout --kill-after=5 1.5h npm test", "npm"),
        ("gtimeout -v 30s npm test", "npm"),
        ("nice -- cargo build", "cargo"),
    ] {
        assert_eq!(program(command), Some(expected), "{command}");
    }
}

/// An option this grammar does not cover, a duration that is not one, and a
/// launcher with nothing after it all leave the program unknown.
#[test]
fn an_uncounted_option_leaves_no_program() {
    for command in [
        "nice --cpu-shares 512 cargo build",
        "nice -q cargo build",
        "nice - cargo build",
        "timeout --signal-name TERM 30 npm test",
        "timeout thirty npm test",
        "timeout 30",
        "nice",
        "nice -n 10",
    ] {
        assert_eq!(program(command), None, "{command}");
        assert!(reads(command), "{command}");
    }
}

/// A launcher is a bare command name. A path names a program of the user's
/// own that happens to share the name, and it does whatever it was written to
/// do.
#[test]
fn only_a_bare_launcher_name_is_a_launcher() {
    for word in ["nice", "timeout", "gtimeout", "nohup", "setsid", "stdbuf"] {
        assert!(is_launcher(word), "{word}");
        assert!(!is_launcher(&format!("./{word}")), "{word}");
        assert!(!is_launcher(&format!("/usr/local/bin/{word}")), "{word}");
        assert!(!is_launcher(&format!("../tools/{word}")), "{word}");
    }
    for word in ["sudo", "doas", "chroot", "flock", "ionice", "cargo"] {
        assert!(!is_launcher(word), "{word}");
    }
}

/// The program behind a launcher is read the way the bare command is: a path
/// or a script name is a file nothing here opened, and an interpreter takes
/// its program from one.
#[test]
fn a_program_file_behind_a_launcher_is_still_unread() {
    for command in [
        "nice ./deploy.sh",
        "nice -n 10 ../tools/build.sh",
        "nohup ./scripts/release.sh",
        "timeout 30 ./run.sh",
        "setsid /usr/local/bin/deploy",
        "nice deploy.sh",
        "stdbuf -oL release.py",
        "nice -n 10 sh -c 'npm run build'",
        "setsid node server.js",
        "stdbuf -oL python3 deploy.py",
        "nice -n 10 xargs rm -f",
    ] {
        assert!(reads(command), "{command}");
    }
    for command in [
        "nice cargo build",
        "nice -n 10 npm run build",
        "timeout -k 5 30 npm test",
        "stdbuf -oL cargo test",
        "nohup npm start",
        "nice python3 -m http.server",
    ] {
        assert!(!reads(command), "{command}");
    }
}

/// A launcher standing in front of another launcher or a shell prefix hands
/// the real program further along, and the scan follows it there.
#[test]
fn a_stacked_launcher_is_walked_to_its_own_program() {
    for command in [
        "nohup timeout 30 bash -lc 'npm run build'",
        "nohup nice -n 10 sh -c 'npm run build'",
        "timeout 30 nice ./deploy.sh",
        "nice -n 10 nohup setsid release.py",
        "nohup time node server.js",
        "nohup command ./deploy.sh",
        "timeout 30 nohup timeout 5 bash -lc 'id'",
    ] {
        assert!(reads(command), "{command}");
    }
    for command in [
        "nohup timeout 30 npm test",
        "timeout 30 nice cargo build",
        "nice -n 10 nohup npm start",
        "nohup setsid stdbuf -oL cargo test",
    ] {
        assert!(!reads(command), "{command}");
    }
}

/// `env` is an interpreter only when a program follows it. With nothing but
/// its own options it writes the environment and exits, so nothing unread
/// runs and the command stays reviewable instead of refused outright.
#[test]
fn an_env_without_a_program_launches_nothing() {
    for command in [
        "env",
        "env -0",
        "env -i",
        "env -u NODE_OPTIONS",
        "env -uNODE_OPTIONS",
        "env --unset NODE_OPTIONS",
        "env --unset=NODE_OPTIONS",
        "env --",
    ] {
        assert!(!dumps(command), "{command}");
    }
    for command in [
        "env sh -c 'id'",
        "env -i sh -c 'id'",
        "env -u NODE_OPTIONS bash -lc 'id'",
        "env -- bash -lc 'id'",
        "env ./deploy.sh",
    ] {
        assert!(dumps(command), "{command}");
    }
}

/// `-S`/`--split-string` carries its program inside its own value, so the
/// whole launch arrives as one dash-prefixed word. An option scan that skipped
/// whatever it did not recognise would read these as environment dumps and
/// offer a shell launch an approval, so every option but the ones known to run
/// nothing says a program runs.
#[test]
fn an_env_that_carries_its_program_in_an_option_launches_it() {
    for command in [
        "env -S bash",
        "env -Sbash",
        "env --split-string=sh",
        "env --split-string 'sh -c id'",
        "env -iS'sh -c id'",
        "env -C /tmp",
        "env --chdir=/tmp",
        "env -P /opt/bin",
        "env --unknown-option",
    ] {
        assert!(dumps(command), "{command}");
    }
}

fn dumps(command: &str) -> bool {
    command_reads_a_program_file(command)
}

/// An `env` that names no program is a wrapper around nothing: it writes the
/// environment and exits. No launcher grammar covers it, so the wrapper arm
/// refused it along with the shells, and `env`, `env -0` and
/// `env | grep '^PATH='` blocked with no approval to give them. The pipeline
/// behind the dump is read the same way any other text is.
#[test]
fn an_env_that_runs_no_program_is_a_launch_of_what_the_text_names() {
    for command in [
        "env",
        "env -0",
        "env | grep ^PATH=",
        "/usr/bin/env | head -5",
        "env -u NODE_OPTIONS | sort",
        "env FOO=bar",
    ] {
        assert!(launch_only(command), "{command}");
    }
    // An `env` that does name a program hands it work this scan never read,
    // and a pipeline member that does keeps its failure too.
    for command in [
        "env sh -c id",
        "env -S bash",
        "env ./deploy.sh",
        "env | xargs bash -c",
        "sudo env",
    ] {
        assert!(!launch_only(command), "{command}");
    }
}

/// An assignment ends `env`'s option parsing, so a flag standing after one is
/// the name of the program it runs. Reading the operands out of order would
/// read `env PATH=. -i` as a dump and hand a file named `-i` an approval.
#[test]
fn an_option_after_an_env_assignment_is_the_program_it_runs() {
    for command in [
        "env PATH=. -i",
        "env FOO=bar sh -c id",
        "env -u NODE_OPTIONS FOO=bar ./deploy.sh",
        "env FOO=bar -0",
    ] {
        assert!(!launch_only(command), "{command}");
    }
    for command in ["env FOO=bar BAZ=qux", "env -i FOO=bar"] {
        assert!(launch_only(command), "{command}");
    }
}

/// `--` ends option parsing the same way an assignment does, and what stands
/// after it is read the same way: `env -- FOO=bar` sets a variable for nothing
/// and prints the environment, so it is a dump rather than a launch.
#[test]
fn an_env_that_names_no_program_after_a_double_dash_is_a_dump() {
    for command in ["env -- FOO=bar", "env --", "env -i -- FOO=bar BAZ=qux"] {
        assert!(launch_only(command), "{command}");
    }
    for command in ["env -- sh -c id", "env -- FOO=bar ./deploy.sh", "env -- -i"] {
        assert!(!launch_only(command), "{command}");
    }
}
