//! Go's local verbs build and test inside the workspace sandbox; the verbs
//! that fetch keep the admission they have. A host without the sandbox, such
//! as Windows, keeps the admission for local verbs too.
use crate::pretool::workspace_contained_tests::{controls, host, workspace, CONTAINED};

const MODULE: &str = "module example.com/app\n\ngo 1.22\n";

fn outcome(harness: &str, command: &str, cwd: &std::path::Path) -> (String, String) {
    let controls = controls();
    let result = crate::pretool::evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &serde_json::json!({"tool_name": "bash", "tool_input": {"command": command}}),
        Some(&controls),
        None,
        Some("/Users/nobody"),
        cwd.to_str(),
    );
    (result.reason_code, result.minimum_action)
}

/// A checkout that is a Go module.
fn module(name: &str) -> std::path::PathBuf {
    let ws = workspace(name, true);
    std::fs::write(ws.join("go.mod"), MODULE).unwrap();
    std::fs::write(ws.join("go.sum"), "").unwrap();
    ws
}

#[test]
fn go_builds_and_tests_the_module_inside_the_sandbox() {
    let ws = module("go-local");
    for command in [
        "go build ./...",
        "go test ./... 2>&1 | tail -15",
        "go vet ./...",
        "go run ./cmd/app",
        "go list -m",
        "go env GOCACHE",
        "go version",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_eq!(reason == CONTAINED, host(), "{reason} {harness}: {command}");
            if !host() {
                assert_eq!(
                    minimum, "review",
                    "{reason}: no sandbox must require review"
                );
            }
        }
    }
}

#[test]
fn the_fetching_verbs_and_a_bare_directory_keep_their_review() {
    let ws = module("go-registry");
    for command in [
        "go get golang.org/x/text",
        "go install golang.org/x/tools/cmd/stringer@latest",
        "go mod download",
        "go mod tidy",
        "go work sync",
        "go clean -modcache",
        "go build ./... && go get golang.org/x/text",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, _) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
        }
    }
    // Outside a module the same verbs read the wider GOPATH, which the
    // workspace sandbox does not hold.
    let bare = workspace("go-bare", true);
    for harness in ["codex", "claude-code", "omp"] {
        let (reason, _) = outcome(harness, "go build ./...", &bare);
        assert_ne!(reason, CONTAINED, "{harness}");
    }
}

#[test]
fn a_verb_reaching_the_module_proxy_keeps_its_review() {
    let ws = module("go-proxy");
    for command in [
        // A version names a module the proxy resolves, whatever the verb.
        "go run golang.org/x/tools/cmd/stringer@latest",
        "go run example.com/tool@v1.2.3 ./...",
        "go list -m golang.org/x/text@latest",
        "go build golang.org/x/text@v0.14.0",
        // These ask the proxy what else a module has.
        "go list -m -u all",
        "go list -m -versions golang.org/x/text",
        "go list -m -retracted golang.org/x/text",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{harness}: {command} ({reason})");
        }
    }
}

#[test]
fn the_module_a_verb_builds_moves_with_the_command() {
    let ws = module("go-nested");
    std::fs::create_dir_all(ws.join("api")).unwrap();
    std::fs::write(ws.join("api/go.mod"), MODULE).unwrap();
    std::fs::create_dir_all(ws.join("docs")).unwrap();
    for harness in ["codex", "claude-code", "omp"] {
        let (reason, minimum) = outcome(harness, "cd api && go build ./...", &ws);
        assert_eq!(reason == CONTAINED, host(), "{reason} {harness}");
        if !host() {
            assert_eq!(
                minimum, "review",
                "{reason}: no sandbox must require review"
            );
        }
        // `docs` holds no module of its own, so go ascends to the one at the
        // workspace root and builds against the sources beside it.
        let (reason, minimum) = outcome(harness, "cd docs && go build ./...", &ws);
        assert_eq!(reason == CONTAINED, host(), "{reason} {harness}");
        if !host() {
            assert_eq!(
                minimum, "review",
                "{reason}: no sandbox must require review"
            );
        }
    }
}

#[test]
fn a_fetching_flag_keeps_its_review_however_it_is_spelled() {
    let ws = module("go-flag-spellings");
    // Go reads one dash or two alike, and a boolean's value may stand behind
    // an `=`, so every spelling of the flags that reach a module proxy keeps
    // the command out.
    for command in [
        "go list -m -u all",
        "go list -m --u all",
        "go list -m -u=true all",
        "go list -m --u=false all",
        "go list -m -versions all",
        "go list -m --versions=true all",
        // Retraction notices come from the proxy too when the latest module
        // metadata is not already cached.
        "go list -m -retracted all",
        "go list -m --retracted=true all",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, _) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
        }
    }
    // A flag whose name only starts with one of them, and an operand that is
    // not a flag at all, are still ordinary local work.
    for command in ["go test -update ./...", "go list ./versions"] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_eq!(reason == CONTAINED, host(), "{reason} {harness}: {command}");
            if !host() {
                assert_eq!(
                    minimum, "review",
                    "{reason}: no sandbox must require review"
                );
            }
        }
    }
}
