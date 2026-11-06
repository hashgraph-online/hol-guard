//! Search-scope proofs for a repository's own feature folders, such as
//! `src/lib/auth`, which share a name with credential markers.

use super::{fixture, scope_allowed, write};

#[test]
fn a_feature_directory_document_does_not_hold_a_search() {
    let (home, project) = fixture();
    // The fixture's marker is a bare `.git` tree; the feature-directory rule
    // asks for a real work tree before it lends a repository its exemption.
    write(project.join(".git/HEAD"), "ref: refs/heads/main\n");
    write(
        project.join("console/src/lib/auth/session.ts"),
        "export const retryLimit = 3;\n",
    );
    write(
        project.join("console/src/lib/auth/README.md"),
        "# Sign-in\n",
    );
    assert!(scope_allowed(
        serde_json::json!({"pattern": "retryLimit"}),
        &home,
        &project
    ));
    assert!(super::super::omp_grep_scope_proven(
        project.to_str().unwrap(),
        home.to_str(),
        project.to_str(),
        false,
        None,
    ));

    // A store under the same folder is not the feature's own code, so the
    // walk still refuses to prove the scope.
    write(
        project.join("console/src/lib/auth/credentials.json"),
        "{\"token\": \"canary\"}\n",
    );
    assert!(!scope_allowed(
        serde_json::json!({"pattern": "retryLimit"}),
        &home,
        &project
    ));
    assert!(!super::super::omp_grep_scope_proven(
        project.to_str().unwrap(),
        home.to_str(),
        project.to_str(),
        false,
        None,
    ));
}
