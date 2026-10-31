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

#[test]
fn the_chdir_flag_moves_the_run_the_way_a_cd_does() {
    let ws = module("go-chdir");
    std::fs::create_dir_all(ws.join("api")).unwrap();
    std::fs::write(ws.join("api/go.mod"), MODULE).unwrap();
    std::fs::create_dir_all(ws.join("docs")).unwrap();
    // `go -C <dir>` chdirs before go reads the verb, so each of these is the
    // local work `cd <dir> && go <verb>` is.
    for command in [
        "go -C api test ./...",
        "go -C api build ./...",
        "go -C=api test ./...",
        "go -C docs vet ./...",
        "go -C . test ./...",
        "go -C api test ./... 2>&1 | tail -15",
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
    // A directory the sandbox cannot follow the run to, a fetching verb behind
    // the move, and a `-C` with nothing behind it all keep their review.
    for command in [
        "go -C /etc test ./...",
        "go -C ../outside test ./...",
        "go -C api get golang.org/x/text",
        "go -C api mod tidy",
        "go -C",
        "go -C api",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, _) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
        }
    }
}

/// `go tool cover` reads the profile the admitted `go test -coverprofile` run
/// just wrote, so the step after a coverage run is contained with it. The
/// rest of the launcher's names, and a render that would open a browser
/// instead of writing a file, keep their review.
#[test]
fn the_cover_tool_renders_the_profile_the_test_run_wrote() {
    let ws = module("go-cover");
    for command in [
        "go test ./... -coverprofile=coverage.out",
        "go tool cover -func=coverage.out",
        "go tool cover -func coverage.out",
        "go tool cover -html=coverage.out -o coverage.html",
        "go tool cover -html coverage.out -o coverage.html",
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
    for command in [
        // Without `-o` this serves the report and opens a browser on it.
        "go tool cover -html=coverage.out",
        // A flag the render does not take, and a flag with no value.
        "go tool cover -func=coverage.out -mode=set",
        "go tool cover -func",
        "go tool cover -o coverage.html",
        "go tool cover",
        // The rest of the launcher's names run their own programs.
        "go tool pprof -http=:8080 cpu.prof",
        "go tool test2json ./app.test",
        "go tool compile ./main.go",
        "go tool nm ./app",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, _) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
        }
    }
}
