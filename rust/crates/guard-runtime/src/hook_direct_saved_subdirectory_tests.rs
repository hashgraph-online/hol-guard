//! In a file-less subdirectory the daemon derives the exact action, and so
//! the saved decision it reads, from the subdirectory itself: a decision saved
//! for the bound root does not answer there.

use super::*;

/// A bound workspace and a file-less subdirectory of it, each holding the
/// read vector's target.
fn root_and_subdirectory(tag: &str) -> (String, String) {
    let root = workspace(tag);
    let subdirectory = Path::new(&root).join("pkg");
    std::fs::create_dir_all(subdirectory.join("src")).unwrap();
    std::fs::write(subdirectory.join("src/a.py"), b"print(1)\n").unwrap();
    let subdirectory = subdirectory.canonicalize().unwrap();
    (root, subdirectory.to_str().unwrap().to_owned())
}

/// The review in `asked_in` against an allow saved for the same read in
/// `saved_in`.
fn answer_in(tag: &str, saved_in: &str, asked_in: &str) -> Result<Value, HookDirectDefer> {
    let vectors = vectors();
    let bound = binding();
    let (_, _, saved_artifact, saved_token) = bound_request(&bound, saved_in);
    let (edge, payload, _, _) = bound_request(&bound, asked_in);
    let (path, connection) = local_store(tag);
    insert_decision(
        &connection,
        "claude-code",
        &saved_artifact,
        &saved_token,
        "allow",
        "approval-gate",
    );
    let guard_home = path.parent().unwrap().to_str().unwrap().to_owned();
    answer(
        &edge,
        &Context {
            harness: "claude-code",
            payload: &payload,
            recorded_payload: &payload,
            workspace: asked_in,
            home_dir: vectors["home_dir"].as_str().unwrap(),
            guard_home: &guard_home,
            binding: &bound,
        },
    )
}

fn accepted(answered: &Result<Value, HookDirectDefer>) -> bool {
    matches!(
        answered,
        Ok(answered)
            if answered["harness_response"]["approval_reuse_status"] == json!("accepted")
    )
}

#[test]
fn the_exact_action_is_keyed_by_the_subdirectory() {
    let (root, subdirectory) = root_and_subdirectory("subdirectory-token");
    let bound = binding();
    let (_, _, root_artifact, at_root) = bound_request(&bound, &root);
    let (_, _, artifact, in_subdirectory) = bound_request(&bound, &subdirectory);
    assert_eq!(root_artifact, artifact);
    assert_ne!(at_root, in_subdirectory);
}

#[test]
fn a_decision_saved_for_the_subdirectory_answers_there() {
    let (_root, subdirectory) = root_and_subdirectory("subdirectory-own");
    let answered = answer_in("subdirectory-own", &subdirectory, &subdirectory);
    assert!(accepted(&answered), "{answered:?}");
}

#[test]
fn a_decision_saved_for_the_root_does_not_answer_in_the_subdirectory() {
    let (root, subdirectory) = root_and_subdirectory("subdirectory-root");
    let answered = answer_in("subdirectory-root", &root, &subdirectory);
    assert!(!accepted(&answered), "{answered:?}");
    // The same decision still answers at the root it was saved for.
    let at_root = answer_in("subdirectory-root-again", &root, &root);
    assert!(accepted(&at_root), "{at_root:?}");
}
