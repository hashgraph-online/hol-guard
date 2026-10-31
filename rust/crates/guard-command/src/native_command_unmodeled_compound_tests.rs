use super::*;

#[test]
fn only_quoted_parameters_that_root_a_path_pass() {
    for text in [
        "find \"$HOME/Downloads/x\" -type f -exec basename {} \\;",
        "find \"${HOME}/src\" -exec basename {} \\; && shasum \"$HOME/x\"/*",
        "find src -name '$x' -exec basename {} \\;",
        "find src -exec basename {} \\;",
    ] {
        assert!(parameters_only_root_paths(text), "{text}");
    }
    for text in [
        "find $HOME/x -exec basename {} \\;",
        "find \"$HOME\" -exec basename {} \\;",
        "find \"$(pwd)/x\" -exec basename {} \\;",
        "find \"$1/x\" -exec basename {} \\;",
        "find \"${HOME:-/}/x\" -exec basename {} \\;",
        "find \"$HOME/x\" -exec basename {} \\; $'\\x41'",
        "find \"$HOME/x -exec basename {} \\;",
    ] {
        assert!(!parameters_only_root_paths(text), "{text}");
    }
}

#[test]
fn only_plain_lowercase_shell_variables_are_set_aside() {
    for word in ["nodepath=/x", "dir=\"$HOME/x\"", "widgets_dir=a"] {
        assert!(binds_a_shell_variable(word), "{word}");
    }
    for word in [
        "PATH=/tmp",
        "path=/tmp",
        "fpath=/tmp",
        "NODE_OPTIONS=--require=x",
        "node_options=--require=x",
        "http_proxy=http://x",
        "api_token=x",
        "ROOT=/x",
    ] {
        assert!(!binds_a_shell_variable(word), "{word}");
    }
}

#[test]
fn a_loop_piece_is_split_outside_quotes_and_past_its_assignments() {
    assert_eq!(
        split_unquoted("do node -e 'a(1); b()' \"$f\"; done", |c| c == ';'),
        Some(vec!["do node -e 'a(1); b()' \"$f\"", " done"])
    );
    assert_eq!(split_unquoted("node -e 'open", |c| c == ';'), None);
    assert!(!changes_directory("nodepath=\"$HOME/a b\""));
    assert!(changes_directory("dir=\"a b\" cd /tmp"));
    assert!(changes_directory("pushd /tmp"));
    assert!(changes_directory("$step /tmp"));
}

#[test]
fn a_prefixed_or_computed_directory_change_is_still_seen() {
    for command in [
        "builtin cd /tmp",
        "command cd /tmp",
        "time -p cd /tmp",
        "exec pushd /tmp",
        "eval \"$step\"",
        ". ./env.sh",
        "'c'd /tmp",
    ] {
        assert!(changes_directory(command), "{command}");
    }
    for command in ["command -v node", "time node -e 'console.log(1)' x"] {
        assert!(!changes_directory(command), "{command}");
    }
}

#[test]
fn a_redirect_that_writes_a_file_the_text_runs_is_not_a_log() {
    for (text, bare) in [
        (
            "printf x > run.js && node run.js",
            "printf x && node run.js",
        ),
        (
            "printf x >./run.js; node /w/run.js",
            "printf x; node /w/run.js",
        ),
        (
            "echo x >> \"run.js\" && node ./run.js",
            "echo x && node ./run.js",
        ),
        ("echo x &>run.js; node run.js", "echo x; node run.js"),
        ("printf x > run.js && node r*.js", "printf x && node r*.js"),
        (
            "printf x > run.js && node ru?.js",
            "printf x && node ru?.js",
        ),
        (
            "printf x > run.js && node ru[n].js",
            "printf x && node ru[n].js",
        ),
        (
            "printf x > run.js && node {run,x}.js",
            "printf x && node {run,x}.js",
        ),
        (
            "printf x > run.js && node ru\"n.js\"",
            "printf x && node ru\"n.js\"",
        ),
        (
            "printf x > run.js && node r\\un.js",
            "printf x && node r\\un.js",
        ),
        (
            "printf x > run.js && node \"$f\"",
            "printf x && node \"$f\"",
        ),
        ("printf x > \"$out\" && node a.js", "printf x && node a.js"),
        ("printf x > run.js && node run", "printf x && node run"),
        (
            "printf x > lib/index.js && node ./lib",
            "printf x && node ./lib",
        ),
        ("printf x > index.js && node .", "printf x && node ."),
        (
            "printf x > run.py && python3 -m run",
            "printf x && python3 -m run",
        ),
        ("printf x > run && node run", "printf x && node run"),
        ("printf x > index.js && node ./", "printf x && node ./"),
        ("printf x >run.js&&node run.js", "printf x&&node run.js"),
        ("node server.js > >(sh) &", "node server.js &"),
        (
            "printf 'require(1)'>run.js && node run.js",
            "printf 'require(1)' && node run.js",
        ),
        (
            "printf x 2>&1>>run.js; node run.js",
            "printf x; node run.js",
        ),
        (
            "printf x > lib/index.js && node lib/",
            "printf x && node lib/",
        ),
        (
            "printf x > lib/index.js && node /w/lib//",
            "printf x && node /w/lib//",
        ),
    ] {
        assert!(writes_a_named_file(text, bare), "{text}");
    }
    for (text, bare) in [
        (
            "node server.js > /tmp/x.log 2>&1 & echo started",
            "node server.js & echo started",
        ),
        (
            "node server.js > /tmp/x.log 2>&1 & trap 'kill \"$p\" 2>/dev/null' EXIT",
            "node server.js & trap 'kill \"$p\" 2>/dev/null' EXIT",
        ),
        ("node server.js 2>/dev/null &", "node server.js &"),
        (
            "node server.js > /tmp/x.log 2>&1 & pid=$!; echo '$HOME *'",
            "node server.js & pid=$!; echo '$HOME *'",
        ),
        ("npm run dev > /tmp/dev.log 2>&1 &", "npm run dev &"),
        ("node . > /tmp/x.log 2>&1 &", "node . &"),
        (
            "echo 'a>run.js' \"b>run.js\" a\\>run.js; node run.js",
            "echo 'a>run.js' \"b>run.js\" a\\>run.js; node run.js",
        ),
    ] {
        assert!(!writes_a_named_file(text, bare), "{text}");
    }
}

#[test]
fn a_shell_variable_may_expand_only_a_quoted_path_root() {
    for word in ["x=$SECRET", "x=\"$SECRET\"", "x=${HOME}", "x=\"$1/a\""] {
        assert!(!binds_a_shell_variable(word), "{word}");
    }
    assert!(binds_a_shell_variable("x=\"${HOME}/a\""));
}
