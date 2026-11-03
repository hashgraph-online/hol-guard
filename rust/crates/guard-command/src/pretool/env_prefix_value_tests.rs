//! What text a setting's value carries. A shell expands some of it before
//! the program starts and hands the rest over character for character, and
//! the projection may only read past a prefix whose value it can reproduce.

use super::project;

#[test]
fn a_heap_or_diagnostic_node_options_prefix_is_projected_away() {
    // The runtime already reads an inherited `NODE_OPTIONS` holding only
    // these flags as inert. Written in front of the command it is the same
    // setting and loads the same nothing, so the projection removes it and
    // the ordinary proofs judge the test run itself.
    for (command, expected) in [
        (
            "NODE_OPTIONS=--max-old-space-size=4096 npm test",
            "npm test",
        ),
        (
            "NODE_OPTIONS=--no-warnings npx vitest run",
            "npx vitest run",
        ),
        (
            "NODE_OPTIONS=--stack-trace-limit=50 node scripts/report.mjs",
            "node scripts/report.mjs",
        ),
        (
            "env NODE_OPTIONS=--max-semi-space-size=64 npm test",
            "npm test",
        ),
        (
            "NODE_OPTIONS=--max-old-space-size=4096 LC_ALL=C npm test",
            "npm test",
        ),
    ] {
        assert_eq!(project(command).as_deref(), Some(expected), "{command}");
    }
    // Anything that can load code, open a port or name a file keeps the
    // command unprojected, so it still fails closed.
    for command in [
        "NODE_OPTIONS=--require=./hook.js npm test",
        "NODE_OPTIONS=--import=./hook.mjs npm test",
        "NODE_OPTIONS=--inspect npm test",
        "NODE_OPTIONS=--experimental-loader npm test",
        "NODE_OPTIONS= npm test",
        "NODE_OPTIONS=--max-old-space-size=4096:--require=./hook.js npm test",
    ] {
        assert_eq!(project(command), None, "{command}");
    }
}

#[test]
fn a_screened_build_or_test_setting_is_removed_in_place() {
    // These names are spelled like loader settings, so every name test
    // refuses them and `GOFLAGS=-count=1 go test ./...` kept no reviewable
    // form at all. A value the closed list holds only chooses how the run
    // reports, how often it repeats or which lint it refuses, so the command
    // runs what its bare spelling runs.
    for (command, expected) in [
        ("GOFLAGS=-count=1 go test ./...", "go test ./..."),
        (r#"GOFLAGS="-count=1 -v" go test ./..."#, "go test ./..."),
        ("GOFLAGS=-mod=readonly go test ./...", "go test ./..."),
        (
            "PYTEST_ADDOPTS=--maxfail=1 .venv/bin/pytest -q",
            ".venv/bin/pytest -q",
        ),
        ("RUSTFLAGS=-Dwarnings cargo test", "cargo test"),
        ("RUSTDOCFLAGS=-Dwarnings cargo doc", "cargo doc"),
    ] {
        assert_eq!(project(command).as_deref(), Some(expected), "{command}");
    }
    // A value the list does not hold names a program, a plugin or a linker.
    for command in [
        "GOFLAGS=-toolexec=./x go test ./...",
        "GOFLAGS=-mod=mod go test ./...",
        "PYTEST_ADDOPTS=-pevil .venv/bin/pytest -q",
        "RUSTFLAGS=-Clinker=./ld cargo test",
    ] {
        assert_eq!(project(command), None, "{command}");
    }
}

#[test]
fn a_pattern_in_a_setting_value_is_the_text_the_program_reads() {
    for (command, expected) in [
        // The control: the same setting without a pattern already projects.
        ("DEBUG=app:main npx jest --ci", "npx jest --ci"),
        ("DEBUG=app:* npx jest --ci", "npx jest --ci"),
        ("DEBUG=app:* npm test", "npm test"),
        ("DEBUG='app:*' npm test", "npm test"),
        ("DEBUG=\"app:*,db:*\" npm test", "npm test"),
        ("DEBUG=app:{a,b} npm test", "npm test"),
        ("DEBUG=app:[ab] npm test", "npm test"),
        ("DEBUG=app:? npm test", "npm test"),
        // A value spelled like a pathname pattern is the same literal text.
        // The shell globs a command word, never an assignment prefix's value,
        // so `ls` reads the five characters `*.env` and matches no file.
        ("FOO=*.env ls", "ls"),
        ("env DEBUG='app:*' npm test", "npm test"),
        ("env DEBUG=\"app:*\" npm test", "npm test"),
        // A heap prefix beside the pattern used to leave the whole prefix
        // unprojected, which stops the command extensions evaluating at all.
        (
            "NODE_OPTIONS=--no-warnings DEBUG=app:* npm test",
            "npm test",
        ),
    ] {
        assert_eq!(project(command).as_deref(), Some(expected), "{command}");
    }
}

#[test]
fn a_setting_value_the_shell_would_expand_is_still_not_projected() {
    for command in [
        "DEBUG=$(id) npm test",
        "DEBUG=$HOME npm test",
        "DEBUG=`id` npm test",
        "DEBUG=~/app npm test",
        "DEBUG=a\\*b npm test",
        "DEBUG=app:!a npm test",
        // A pattern does not make a steering name ordinary.
        "PATH=/tmp/* npm test",
        "NODE_OPTIONS=--require=./*.js npm test",
    ] {
        assert_eq!(project(command), None, "{command}");
    }
}

#[test]
fn an_env_argument_carries_its_pattern_only_inside_quotes() {
    // `env`'s arguments are ordinary words, so the shell expands braces and
    // globs there before `env` starts. `env A={x,y} prog` hands `env` two
    // settings, not the five characters the prefix spelling would hand it.
    for command in [
        "env DEBUG=app:* npm test",
        "env DEBUG=app:{a,b} npm test",
        "env DEBUG=app:[ab] npm test",
        "env DEBUG=app:? npm test",
        "env FOO=*.env ls",
        // One quote has to cover the whole value, not part of it.
        "env DEBUG=app:'*' npm test",
    ] {
        assert_eq!(project(command), None, "{command}");
    }
}
