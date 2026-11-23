//! A read of a credential-named file keeps its review instead of running in
//! the workspace sandbox, which does not withhold that file.
use crate::pretool::workspace_contained_tests::{host, reason, workspace, CONTAINED};

#[test]
fn a_read_of_a_credential_named_file_keeps_its_review() {
    let ws = workspace("credential-names", true);
    std::fs::create_dir_all(ws.join("docs/design")).unwrap();
    std::fs::create_dir_all(ws.join("secrets")).unwrap();
    std::fs::write(ws.join("docs/design/brand-github-token.txt"), "x\n").unwrap();
    std::fs::write(ws.join("secrets/prod.yaml"), "x\n").unwrap();
    for command in [
        "cat docs/design/brand-github-token.txt",
        "head -5 docs/design/brand-github-token.txt",
        "cat secrets/prod.yaml",
    ] {
        assert_ne!(reason("omp", command, &ws, true), CONTAINED, "{command}");
    }
    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn a_design_token_document_or_a_search_word_still_runs_contained() {
    let ws = workspace("credential-names-benign", true);
    std::fs::create_dir_all(ws.join("docs/design")).unwrap();
    std::fs::write(ws.join("docs/design/color-tokens.json"), "{}\n").unwrap();
    std::fs::write(ws.join("notes.txt"), "x\n").unwrap();
    // The control: an ordinary reviewed command the sandbox takes on this host.
    let control = "npm run build";
    let contained = reason("omp", control, &ws, true) == CONTAINED;
    assert_eq!(contained, host(), "{control}");
    if contained {
        for command in [
            "npm run build -- --config docs/design/color-tokens.json",
            "npm run build -- --grep token",
        ] {
            assert_eq!(reason("omp", command, &ws, true), CONTAINED, "{command}");
        }
    }
    let _ = std::fs::remove_dir_all(&ws);
}
