use super::*;

fn request(command: &str) -> CommandModelRequestV1 {
    CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    }
}

fn allowed(command: &str) -> bool {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .unwrap();
    let root = root.to_str().unwrap();
    evaluate_pre_tool_with_context(&request(command), Some(root), Some(root))
        .is_ok_and(|decision| decision.minimum_action == "allow")
}

#[test]
fn rewriting_a_path_word_needs_no_review() {
    for command in [
        "dirname /a/b/c",
        "dirname .",
        "dirname -z /a/b/c",
        "dirname -- -weird/path",
        "basename /a/b/c.txt",
        "basename /a/b/c.txt .txt",
        "basename -s .txt /a/b/c.txt",
        "basename -a /a/b /c/d",
        "basename --suffix=.rs src/main.rs",
    ] {
        assert!(allowed(command), "{command}");
    }
}

#[test]
fn resolving_a_path_word_needs_no_review_inside_the_workspace() {
    for command in [
        "realpath Cargo.toml",
        "realpath .",
        "realpath -q src",
        "readlink -f Cargo.toml",
        "readlink -f src",
    ] {
        assert!(allowed(command), "{command}");
    }
}

#[test]
fn an_unproven_path_word_still_takes_review() {
    for command in [
        // An option this proof never screened.
        "dirname --relative-to=/ /a/b",
        "dirname -X /a/b",
        "basename -X /a/b",
        "realpath --relative-to=/tmp Cargo.toml",
        "realpath --relative-base=/ Cargo.toml",
        "readlink --badoption Cargo.toml",
        // The shell runs the substitution before the rewrite ever happens.
        "basename \"$(touch marker.txt)\"",
        "dirname \"$(touch marker.txt)\"",
        "basename -s \"$(touch marker.txt)\" src/main.rs",
        "basename --suffix=\"$(touch marker.txt)\" src/main.rs",
        "basename -- \"`touch marker.txt`\"",
        // No operand to rewrite.
        "dirname",
        "basename",
        "realpath",
        // A resolved operand outside the proven read scope.
        "realpath /nonexistent-guard-fixture/secret.key",
        "readlink -f /nonexistent-guard-fixture/secret.key",
    ] {
        assert!(!allowed(command), "{command}");
    }
}
