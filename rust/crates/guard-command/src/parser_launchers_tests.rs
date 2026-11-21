use super::launcher_program;

fn words(command: &str) -> Vec<String> {
    command.split(' ').map(str::to_owned).collect()
}

/// Each prefix's documented options are walked, and the program behind them
/// is the word the command runs.
#[test]
fn a_documented_launcher_names_the_program_behind_it() {
    for (command, program) in [
        ("nice npm run build", 1),
        ("nice -n 10 npm run build", 3),
        ("nice -n -5 cargo build", 3),
        ("nice -n10 cargo build", 2),
        ("nice -10 cargo build", 2),
        ("nice --adjustment=19 pytest -q", 2),
        ("nice --adjustment 19 pytest -q", 3),
        ("nice -- npm test", 2),
        ("stdbuf -oL pytest -q", 2),
        ("stdbuf -o L pytest -q", 3),
        ("stdbuf -i0 -oL -e0 cargo test", 4),
        ("stdbuf --output=L --error=0 npm test", 3),
        ("stdbuf -o 4K npm test", 3),
    ] {
        assert_eq!(
            launcher_program(&words(command), 0),
            Some(program),
            "{command} did not name its program"
        );
    }
}

/// A prefix spelled as a path, an option no grammar documents, a value
/// outside the shape the prefix takes, a prefix running nothing at all and
/// `nohup`, which may write `nohup.out` where the program behind it only reads,
/// each leave the command as uncertain as it arrived.
#[test]
fn an_undocumented_word_leaves_the_launcher_in_place() {
    for command in [
        "./nice -n 10 npm test",
        "/tmp/tools/stdbuf -oL npm test",
        "nice",
        "nice -n 10",
        "nice --version",
        "nice --help",
        "nice -",
        "nice -x npm test",
        "nice -n 300 npm test",
        "nice -n L npm test",
        "nice --adjustment=nineteen npm test",
        "nohup npm run dev",
        "nohup git diff --stat",
        "nohup -- npm run dev",
        "nohup --version",
        "stdbuf npm test",
        "stdbuf -oL",
        "stdbuf -o /dev/null npm test",
        "stdbuf -oQ npm test",
        "stdbuf -n0 npm test",
        "stdbuf --buffer=L npm test",
        "nice -n 10 FOO=bar npm test",
        "nice -n 10 -- -q",
    ] {
        assert_eq!(
            launcher_program(&words(command), 0),
            None,
            "{command} was read as a documented launcher"
        );
    }
}

/// A program spelled as a path is handed over. What comes out is
/// `<program> <arguments>`, which the parser reads exactly as it reads those
/// words written without the launcher, and `nice` and `stdbuf` change neither
/// the user, the root nor the directory it runs in. So
/// `nice -n 10 .venv/bin/pytest -q` reaches the route `.venv/bin/pytest -q`
/// already reaches instead of being reviewed for the launcher alone.
#[test]
fn a_path_behind_the_launcher_is_read_as_the_bare_command() {
    for (command, program) in [
        ("nice -n 10 .venv/bin/pytest -q", 3),
        ("stdbuf -oL .venv/bin/pytest -q", 2),
        ("exec .venv/bin/pytest -q", 1),
        ("nice ./node_modules/.bin/eslint src", 1),
        ("stdbuf -oL /usr/local/bin/cargo test", 2),
    ] {
        assert_eq!(
            launcher_program(&words(command), 0),
            Some(program),
            "{command} was not read past its launcher"
        );
    }
}

/// A script file or an interpreter behind the prefix is a program whose own
/// text was never read, so the prefix stays and the command keeps the
/// unmodelled failure the scan already gives it.
#[test]
fn a_program_file_behind_the_launcher_leaves_it_in_place() {
    for command in [
        "nice ./deploy.sh",
        "nice -n 10 ../tools/build.sh",
        "stdbuf -oL release.py",
        "stdbuf -oL python3 deploy.py",
        "nice -n 10 sh -c build",
        "nice -n 10 nohup ./deploy.sh",
    ] {
        assert_eq!(
            launcher_program(&words(command), 0),
            None,
            "{command} was read past its program file"
        );
    }
    for (command, program) in [
        ("nice python3 -m http.server", 1),
        ("stdbuf -oL git log --oneline -5", 2),
    ] {
        assert_eq!(
            launcher_program(&words(command), 0),
            Some(program),
            "{command} did not name its program"
        );
    }
}

/// The scan starts where the caller says, so assignments and an earlier
/// prefix do not move the program this reads.
#[test]
fn the_scan_starts_at_the_word_the_caller_names() {
    assert_eq!(
        launcher_program(&words("env FOO=bar nice -n 10 npm test"), 2),
        Some(5)
    );
    assert_eq!(launcher_program(&words("npm run build"), 0), None);
}

fn parse(command: &str) -> crate::CanonicalCommandV1 {
    crate::parse_command(&crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })
    .unwrap()
}

/// Through the whole parser, a documented launcher leaves the program behind
/// it as the executable and leaves no wrapper in the chain.
#[test]
fn a_launcher_leaves_its_program_as_the_executable() {
    for (command, executable, argument) in [
        ("nice npm test", "npm", "test"),
        ("nice -n 10 cargo build", "cargo", "build"),
        ("nice -n -5 cargo build", "cargo", "build"),
        ("nice -n10 cargo build", "cargo", "build"),
        ("nice -10 cargo build", "cargo", "build"),
        ("nice --adjustment 10 cargo build", "cargo", "build"),
        ("nice --adjustment=10 cargo build", "cargo", "build"),
        ("nice -- cargo build", "cargo", "build"),
        ("stdbuf -oL pytest -q", "pytest", "-q"),
        ("stdbuf -o L pytest -q", "pytest", "-q"),
        ("stdbuf --output=L pytest -q", "pytest", "-q"),
        ("stdbuf --error 0 pytest -q", "pytest", "-q"),
        ("stdbuf -o0 -e0 pytest -q", "pytest", "-q"),
        ("stdbuf -i 4096 pytest -q", "pytest", "-q"),
    ] {
        let model = parse(command);
        assert_eq!(model.confidence, "exact", "{command}");
        assert_eq!(model.segments.len(), 1, "{command}");
        assert!(model.wrapper_chain.is_empty(), "{command}");
        assert!(model.segments[0].wrapper_chain.is_empty(), "{command}");
        assert_eq!(
            model.segments[0].executable.as_deref(),
            Some(executable),
            "{command}"
        );
        assert_eq!(model.segments[0].arguments, [argument], "{command}");
    }
}

/// Anything the launcher grammars do not read keeps the wrapper as the
/// executable, so the command is as uncertain as it was before they existed.
/// These assert the uncertainty itself, not that one program is missing.
#[test]
fn a_launcher_that_is_not_read_keeps_the_command_uncertain() {
    for command in [
        "nice",
        "nice -n 10",
        "nice --help cargo build",
        "nice -n cargo build",
        "nice -n ten cargo build",
        "nice --adjustment=ten cargo build",
        "nice -n 10 CI=1 cargo build",
        "nice -n 10 nohup npm run build",
        "stdbuf pytest -q",
        "stdbuf -oX pytest -q",
        "stdbuf --output=X pytest -q",
        "stdbuf -z L pytest -q",
        "setsid pytest -q",
        "./nice -n 10 cargo build",
        "bin/stdbuf -oL pytest -q",
        "/usr/bin/nice -n 10 cargo build",
    ] {
        let model = parse(command);
        assert_eq!(model.confidence, "uncertain", "{command}");
        assert_eq!(
            model.uncertainty_reason.as_deref(),
            Some("transparent_wrapper_not_yet_supported"),
            "{command}"
        );
    }
}

/// `nohup` appends the program's output to `nohup.out` when standard output is
/// a terminal, so the read-only proof of the program behind it would be
/// granted to a command that also writes a file.
#[test]
fn nohup_is_not_read_as_the_program_behind_it() {
    for command in [
        "nohup git diff --stat",
        "nohup npm test",
        "nohup -- npm test",
    ] {
        let model = parse(command);
        assert_eq!(model.confidence, "uncertain", "{command}");
        assert_eq!(
            model.uncertainty_reason.as_deref(),
            Some("transparent_wrapper_not_yet_supported"),
            "{command}"
        );
    }
}

/// GNU `nice` reads only `-N` as an adjustment. `+10` is the program it runs,
/// so the parser must not name the word after it.
#[test]
fn a_plus_sign_is_the_program_and_not_an_adjustment() {
    let model = parse("nice +10 cargo build");
    assert!(
        model
            .segments
            .iter()
            .all(|segment| segment.executable.as_deref() != Some("cargo")),
        "{:?}",
        model.segments.first().map(|segment| &segment.executable)
    );
    assert_eq!(parse("nice -n +10 cargo build").confidence, "exact");
}

/// A launcher is read by its spelling, as every other program is. The ways the
/// same text could make that spelling mean something else stay visible: a
/// function definition is a compound the parser refuses, and a `PATH=`
/// assignment in front of the launcher is recorded on the segment.
#[test]
fn text_that_could_shadow_a_launcher_stays_visible() {
    let model = parse("nice() { rm -rf ~; }; nice git status");
    assert_eq!(model.confidence, "uncertain");
    assert_eq!(
        model.uncertainty_reason.as_deref(),
        Some("compound_shell_not_yet_supported")
    );
    let model = parse("PATH=./bin nice git status");
    assert!(model.path_overridden);
    assert!(model.segments[0].path_overridden);
}

/// `exec npm test` runs what `npm test` runs: the shell replaces itself with
/// the program this text already names. The program behind it is the word the
/// command runs, exactly as it is behind the scheduling prefixes.
#[test]
fn exec_names_the_program_that_replaces_the_shell() {
    for (command, program) in [
        ("exec npm test", 1),
        ("exec npm run build", 1),
        ("exec cargo build", 1),
        ("exec make -j4", 1),
        ("exec codesage install codex", 1),
    ] {
        assert_eq!(
            launcher_program(&words(command), 0),
            Some(program),
            "{command} did not name its program"
        );
    }
}

/// An `exec` that carries an option of its own leaves the program unread:
/// `-a` renames the process, `-c` empties its environment and `-l` makes it a
/// login shell. A bare `exec` names no program at all, and an interpreter
/// behind one reads a file this scan never opened.
#[test]
fn an_exec_without_a_named_program_is_not_a_launcher() {
    for command in [
        "exec",
        "exec -a worker npm test",
        "exec -c npm test",
        "exec -l bash",
        "exec python3 deploy.py",
        "exec node server.js",
        "exec ./deploy.sh",
        "exec -",
    ] {
        assert_eq!(
            launcher_program(&words(command), 0),
            None,
            "{command} named a program it does not run"
        );
    }
}
