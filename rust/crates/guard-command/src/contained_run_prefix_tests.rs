use super::run_prefix_peel;

fn words(command: &[&str]) -> Vec<String> {
    command.iter().map(|word| (*word).to_string()).collect()
}

fn peel(command: &[&str]) -> (Vec<String>, Option<u64>) {
    run_prefix_peel(&words(command))
}

fn core(command: &[&str]) -> Vec<String> {
    peel(command).0
}

fn clock(command: &[&str]) -> Option<u64> {
    peel(command).1
}

#[test]
fn a_system_clock_is_peeled_to_the_program_it_bounds() {
    for (command, seconds) in [
        (["timeout", "20", "pytest", "-q"].as_slice(), 20u64),
        (["timeout", "--", "20", "pytest", "-q"].as_slice(), 20),
        (["timeout", "5m", "pytest", "-q"].as_slice(), 300),
        (["timeout", "1.5", "pytest", "-q"].as_slice(), 2),
        (["timeout", "2h", "pytest", "-q"].as_slice(), 7200),
        (["timeout", "1d", "pytest", "-q"].as_slice(), 86400),
        (["/usr/bin/timeout", "30", "pytest", "-q"].as_slice(), 30),
        (["/bin/timeout", "30", "pytest", "-q"].as_slice(), 30),
    ] {
        assert_eq!(
            peel(command),
            (words(&["pytest", "-q"]), Some(seconds)),
            "{command:?}"
        );
    }
}

#[test]
fn the_shortest_clock_bounds_a_doubled_wrapper() {
    assert_eq!(
        peel(&["timeout", "60", "timeout", "20", "pytest"]),
        (words(&["pytest"]), Some(20))
    );
    assert_eq!(
        peel(&["timeout", "20", "timeout", "60", "pytest"]),
        (words(&["pytest"]), Some(20))
    );
}

#[test]
fn anything_that_is_not_that_clock_stays_in_the_command() {
    for command in [
        // A `timeout` named by path is whatever that file holds.
        ["./timeout", "20", "pytest", "-q"].as_slice(),
        ["bin/timeout", "20", "pytest", "-q"].as_slice(),
        ["/tmp/timeout", "20", "pytest", "-q"].as_slice(),
        // An option is not a duration, so the word after it is not the program.
        ["timeout", "-k", "5", "20", "pytest"].as_slice(),
        ["timeout", "--signal=KILL", "20", "pytest"].as_slice(),
        // Durations this does not read.
        ["timeout", "20x", "pytest"].as_slice(),
        ["timeout", "1e9", "pytest"].as_slice(),
        ["timeout", "99999999999", "pytest"].as_slice(),
        ["timeout", "", "pytest"].as_slice(),
        ["timeout", "s", "pytest"].as_slice(),
        // A non-ASCII digit is not a duration either.
        ["timeout", "\u{661}\u{660}", "pytest"].as_slice(),
        // The clock has to bound a program named in the text.
        ["timeout", "20"].as_slice(),
        ["timeout", "20", "-q"].as_slice(),
        ["timeout", "20", "PYTHONPATH=/tmp"].as_slice(),
        ["pytest", "-q"].as_slice(),
    ] {
        assert_eq!(peel(command), (words(command), None), "{command:?}");
    }
}

#[test]
fn a_zero_duration_peels_without_bounding_the_run() {
    for command in [
        ["timeout", "0", "pytest", "-q"].as_slice(),
        ["timeout", "0.0", "pytest", "-q"].as_slice(),
        ["timeout", "0s", "pytest", "-q"].as_slice(),
        ["timeout", "0m", "pytest", "-q"].as_slice(),
    ] {
        assert_eq!(
            peel(command),
            (words(&["pytest", "-q"]), None),
            "{command:?}"
        );
    }
}

#[test]
fn a_fractional_clock_rounds_up_to_the_time_it_was_given() {
    assert_eq!(clock(&["timeout", "0.4", "pytest"]), Some(1));
    assert_eq!(clock(&["timeout", "2.1", "pytest"]), Some(3));
    assert_eq!(clock(&["timeout", "0.5m", "pytest"]), Some(30));
}

#[test]
fn an_unbounded_wrapper_never_loosens_the_clock_inside_it() {
    assert_eq!(
        peel(&["timeout", "0", "timeout", "20", "pytest"]),
        (words(&["pytest"]), Some(20))
    );
    assert_eq!(
        peel(&["timeout", "20", "timeout", "0", "pytest"]),
        (words(&["pytest"]), Some(20))
    );
}

#[test]
fn launchers_and_clocks_peel_in_either_order() {
    assert_eq!(
        peel(&["nice", "-n", "10", "timeout", "20", "pytest", "-q"]),
        (words(&["pytest", "-q"]), Some(20))
    );
    assert_eq!(
        peel(&["timeout", "20", "stdbuf", "-oL", "pytest", "-q"]),
        (words(&["pytest", "-q"]), Some(20))
    );
    assert_eq!(
        peel(&["stdbuf", "-oL", "env", "CI=1", "pytest", "-q"]),
        (words(&["pytest", "-q"]), None)
    );
    assert_eq!(
        peel(&["exec", "pytest", "-q"]),
        (words(&["pytest", "-q"]), None)
    );
    assert_eq!(
        peel(&["nice", "pytest", "-q"]),
        (words(&["pytest", "-q"]), None)
    );
}

#[test]
fn a_prefix_the_parser_leaves_in_place_stays_the_program() {
    // `nohup` also writes `nohup.out`, and `setsid` detaches the run, so
    // neither is read through; a launcher spelled as a path is a program of
    // the user's own that shares the name.
    for command in [
        ["nohup", "pytest", "-q"].as_slice(),
        ["setsid", "pytest", "-q"].as_slice(),
        ["./nice", "-n", "10", "pytest", "-q"].as_slice(),
        ["/usr/bin/nice", "pytest", "-q"].as_slice(),
        ["stdbuf", "pytest", "-q"].as_slice(),
        ["exec", "-a", "name", "pytest", "-q"].as_slice(),
        ["", "pytest"].as_slice(),
        ["pytest"].as_slice(),
    ] {
        assert_eq!(peel(command), (words(command), None), "{command:?}");
    }
}

#[test]
fn an_installed_entrypoint_is_planned_as_the_node_run_it_is() {
    for command in [
        ["bun", "node_modules/vite/bin/vite.js", "build"].as_slice(),
        [
            "bun",
            "dashboard/node_modules/vite/bin/vite.js",
            "build",
            "--root",
            "/work/tree",
        ]
        .as_slice(),
        [
            "/opt/bun/bin/bun",
            "/work/app/node_modules/vitest/vitest.mjs",
            "run",
        ]
        .as_slice(),
        ["bun", "./node_modules/eslint/bin/eslint.js", "src"].as_slice(),
    ] {
        let mut expected = words(command);
        expected[0] = "node".to_string();
        assert_eq!(core(command), expected, "{command:?}");
    }
}

#[test]
fn every_other_bun_command_keeps_its_spelling() {
    for command in [
        ["bun"].as_slice(),
        ["bun", "install"].as_slice(),
        ["bun", "add", "left-pad"].as_slice(),
        ["bun", "x", "vite", "build"].as_slice(),
        ["bun", "run", "build"].as_slice(),
        ["bun", "./script.mjs"].as_slice(),
        ["bun", "src/report.ts"].as_slice(),
        [
            "bun",
            "https://example.com/node_modules/vite/bin/vite.js",
            "build",
        ]
        .as_slice(),
        ["bun", "--cwd", "node_modules/vite", "build"].as_slice(),
        ["bun", "node_modules/"].as_slice(),
        ["bunx", "node_modules/vite/bin/vite.js", "build"].as_slice(),
        ["node", "node_modules/vite/bin/vite.js", "build"].as_slice(),
    ] {
        assert_eq!(core(command), words(command), "{command:?}");
    }
}

#[test]
fn the_entrypoint_behind_a_prefix_is_spelled_the_same_way() {
    assert_eq!(
        peel(&[
            "timeout",
            "30",
            "nice",
            "-n",
            "10",
            "bun",
            "node_modules/vite/bin/vite.js",
            "build"
        ]),
        (
            words(&["node", "node_modules/vite/bin/vite.js", "build"]),
            Some(30)
        ),
    );
}

#[test]
fn the_peel_stops_at_the_prefix_it_cannot_read() {
    // `env REPORT_DIR=/tmp/r` carries a setting no inert filter exports, so
    // the prefix stays in place and the planners refuse the command.
    assert_eq!(
        core(&[
            "nice",
            "-n",
            "10",
            "env",
            "REPORT_DIR=/tmp/r",
            "pytest",
            "-q"
        ]),
        words(&["env", "REPORT_DIR=/tmp/r", "pytest", "-q"]),
    );
}
