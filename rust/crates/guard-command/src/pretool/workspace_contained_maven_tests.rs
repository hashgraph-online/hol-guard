//! Maven's lifecycle phases build and test inside the workspace sandbox,
//! which grants the local repository read-only and runs the build offline.
//! Plugin goals, the publishing phases and the options that refresh a
//! dependency keep the package firewall's review. A host without the
//! sandbox, such as Windows, keeps the review for the phases too.
use crate::pretool::workspace_contained_tests::{controls, host, workspace, CONTAINED};

const POM: &str = concat!(
    "<project><modelVersion>4.0.0</modelVersion>",
    "<groupId>example</groupId><artifactId>app</artifactId>",
    "<version>1.0.0</version></project>\n"
);

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

/// A checkout that is a Maven project.
fn project(name: &str) -> std::path::PathBuf {
    let ws = workspace(name, true);
    std::fs::write(ws.join("pom.xml"), POM).unwrap();
    ws
}

#[test]
fn the_lifecycle_phases_build_and_test_inside_the_sandbox() {
    let ws = project("maven-local");
    for command in [
        "mvn test",
        "mvn -q test",
        "mvn clean verify",
        "mvn clean package -DskipTests",
        "mvn test-compile",
        "mvn -o -B test",
        "./mvnw test",
        "mvn -pl app -am test",
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
    let ws = project("maven-registry");
    for command in [
        // A plugin goal carries a colon; these resolve from a remote
        // repository whatever the project holds.
        "mvn dependency:copy-dependencies",
        "mvn dependency:get -Dartifact=org.example:tool:1.0",
        "mvn versions:use-latest-releases",
        // These publish what the build produced.
        "mvn install",
        "mvn clean deploy",
        // These refresh a dependency from the remote repository.
        "mvn -U test",
        "mvn --update-snapshots verify",
        "mvn test && mvn deploy",
    ] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            // Not contained is only half of it: the firewall these verbs
            // belong to must still queue the review, not let them through.
            assert_eq!(minimum, "review", "{reason} {harness}: {command}");
        }
    }
    // Without a phase Maven prints its help, and a bare option is no evidence
    // of local work either, so neither reaches the sandbox.
    for command in ["mvn", "mvn -version"] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, _) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
        }
    }
    // Outside a project Maven resolves everything it runs from a remote
    // repository, so the same phase keeps its review.
    let bare = workspace("maven-bare", true);
    for harness in ["codex", "claude-code", "omp"] {
        let (reason, _) = outcome(harness, "mvn test", &bare);
        assert_ne!(reason, CONTAINED, "{harness}");
    }
}

#[test]
fn gradle_keeps_its_review() {
    // Gradle needs a writable `GRADLE_USER_HOME` and takes file locks inside
    // its dependency cache, so the read-only grant Maven runs under does not
    // fit it. Until it has one of its own, its builds keep asking.
    let ws = project("maven-gradle");
    std::fs::write(ws.join("build.gradle"), "plugins { id 'java' }\n").unwrap();
    for command in ["gradle build", "./gradlew :app:test", "gradle test"] {
        for harness in ["codex", "claude-code", "omp"] {
            let (reason, minimum) = outcome(harness, command, &ws);
            assert_ne!(reason, CONTAINED, "{harness}: {command}");
            assert_eq!(minimum, "review", "{reason} {harness}: {command}");
        }
    }
}

#[test]
fn the_project_a_phase_builds_moves_with_the_command() {
    let ws = project("maven-nested");
    std::fs::create_dir_all(ws.join("service")).unwrap();
    std::fs::write(ws.join("service/pom.xml"), POM).unwrap();
    std::fs::create_dir_all(ws.join("docs")).unwrap();
    for harness in ["codex", "claude-code", "omp"] {
        let (reason, minimum) = outcome(harness, "cd service && mvn test", &ws);
        assert_eq!(reason == CONTAINED, host(), "{reason} {harness}");
        if !host() {
            assert_eq!(
                minimum, "review",
                "{reason}: no sandbox must require review"
            );
        }
        // `docs` holds no project, so Maven would resolve from a remote
        // repository.
        let (reason, _) = outcome(harness, "cd docs && mvn test", &ws);
        assert_ne!(reason, CONTAINED, "{harness}");
    }
}
