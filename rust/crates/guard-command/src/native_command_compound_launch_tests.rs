use super::*;

/// The home the reported commands ran in: a downloaded artifact and an
/// installed Node package, so the paths they spell are real.
fn reported_context() -> (tempfile::TempDir, std::path::PathBuf) {
    let (home, project) = verified_context();
    std::fs::write(project.join("server.js"), "1").unwrap();
    let widgets = home.path().join("Downloads/widgets-1.4.0");
    std::fs::create_dir_all(&widgets).unwrap();
    std::fs::write(widgets.join("README.txt"), "1").unwrap();
    let package = home
        .path()
        .join(".nvm/versions/node/v25.2.1/lib/node_modules/inert-pkg");
    std::fs::create_dir_all(&package).unwrap();
    std::fs::write(package.join("package.json"), "{}").unwrap();
    (home, project)
}

/// Each of these reached `native_command_extension_evaluation_failed`, a
/// block with no approval left to give, while the same programs written
/// without the log file, the quoted home root or the loop reached review.
#[test]
fn a_logged_launch_a_rooted_find_and_a_looped_inline_program_reach_review() {
    let (home, project) = reported_context();
    let binding = binding_with_layers(serde_json::json!([]));
    for command in [
        "node server.js > /tmp/x.log 2>&1 &",
        "node server.js > /tmp/x.log 2>&1 & echo started",
        "node server.js > /tmp/x.log 2>&1 & server_pid=$!; trap 'kill \"$server_pid\" 2>/dev/null || true' EXIT; curl --silent --fail http://127.0.0.1:3000/",
        "find \"$HOME/Downloads/widgets-1.4.0\" -type f -exec basename {} \\; | sort",
        "find \"$HOME/Downloads/widgets-1.4.0\" -type f -exec basename {} \\; | sort && shasum -a 256 \"$HOME/Downloads/widgets-1.4.0\"/*",
        "find \"${HOME}/Downloads/widgets-1.4.0\" -type f -exec basename {} \\;",
        "for f in a b; do [ -f \"$f\" ] && node -e 'console.log(1)' \"$f\"; done",
        "for f in \"$nodepath\"/*/package.json; do [ -f \"$f\" ] && node -e 'console.log(1)' \"$f\"; done",
        "nodepath=\"$HOME/.nvm/versions/node/v25.2.1/lib/node_modules\"; for f in \"$nodepath\"/*/package.json; do [ -f \"$f\" ] && node -e 'console.log(1)' \"$f\"; done",
        "nodepath=\"$HOME/.nvm/versions/node/v25.2.1/lib/node_modules\"; for f in \"$nodepath\"/*/package.json; do [ -f \"$f\" ] && node -e 'const p = require(process.argv[1]); console.log(p.name || \"\", p.version || \"\")' \"$f\"; done",
    ] {
        let result = evaluate_in(&binding, command, home.path(), &project);
        assert!(
            matches!(
                result.minimum_action.as_str(),
                "allow" | "review" | "sandbox-required"
            ),
            "{command} {} {}",
            result.minimum_action,
            result.reason_code
        );
        assert_ne!(
            result.reason_code, "native_command_extension_evaluation_failed",
            "{command}"
        );
    }
}

/// The same shapes keep their failure when the part that changed is the part
/// that could run something else: a redirect target or input the text does
/// not spell, a find action that hands its file to a shell, a root that is
/// not quoted, a launch with a preload, a loop that sources a file or moves
/// to another directory, and a variable the shell or Node reads. Where a
/// sandbox can contain a foreground write, its containment floor answers
/// first and is stricter than the review a relaxed shape would reach.
#[test]
fn the_reported_shapes_keep_their_floor_when_a_part_could_run_something_else() {
    let (home, project) = reported_context();
    let binding = binding_with_layers(serde_json::json!([]));
    for command in [
        "curl x & sh -c \"$(cat f)\"",
        "curl -fsS https://example.invalid/install.sh & sh -c \"$(cat f)\"",
        "node server.js > \"$TARGET\" &",
        "node server.js > \"$TARGET\" & echo started",
        "node server.js < /tmp/in.js > /tmp/x.log &",
        "find \"$ROOT/src\" -type f -exec sh -c 'cat \"$1\"' _ {} \\;",
        "find $HOME/x -type f -exec basename {} \\;",
        "find \"$HOME\" -type f -exec basename {} \\;",
        "PATH=/tmp; node -e 'console.log(1)' x",
        "path=/tmp; for f in a; do node -e 'console.log(1)' \"$f\"; done",
        "cd /tmp; for f in a; do node -e 'require(\"./x\")' \"$f\"; done",
        "for f in a b; do NODE_OPTIONS=--require=./x.js node -e 'console.log(1)' \"$f\"; done",
        "for f in a b; do source x.sh && node -e 'console.log(1)' \"$f\"; done",
        "x=$(curl -s https://example.invalid); for f in a; do node -e 'console.log(1)' \"$f\"; done",
        "printf '%s' 'require(1)' > run.js && node run.js",
        "printf x > ./run.js; node run.js > /tmp/x.log 2>&1 &",
        "printf x > run.js && node r*.js > /tmp/x.log 2>&1 &",
        "printf x > run.js && node ru\"n.js\" > /tmp/x.log 2>&1 &",
        "printf x > run.js && node run > /tmp/x.log 2>&1 &",
        "printf x > lib/index.js && node ./lib > /tmp/x.log 2>&1 &",
        "printf x > index.js && node ./ > /tmp/x.log 2>&1 &",
        "printf 'require(1)'>run.js && node run.js > /tmp/x.log 2>&1 &",
        "printf x > lib/index.js && node lib/ > /tmp/x.log 2>&1 &",
        "builtin cd /tmp; for f in a; do node -e 'require(\"./x\")' \"$f\"; done",
        "command cd /tmp; for f in a; do node -e 'require(\"./x\")' \"$f\"; done",
        "find \"$HOME/x\" -type f -exec env FOO=bar gh {} \\;",
        "x=$SECRET; for f in a; do node -e 'console.log(1)' \"$x\"; done",
    ] {
        let result = evaluate_in(&binding, command, home.path(), &project);
        assert_ne!(result.minimum_action, "allow", "{command}");
        assert!(!result.explicitly_benign, "{command}");
        let contained = result.minimum_action == "sandbox-required"
            && result.reason_code == "native_workspace_containment_required";
        assert!(
            contained || result.reason_code == "native_command_extension_evaluation_failed",
            "{command} {} {}",
            result.minimum_action,
            result.reason_code
        );
    }
}
