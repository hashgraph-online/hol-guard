//! A resident serves policy answers under the authority of the binary that
//! started it, so the identity check in front of `serve_managed` and
//! `supervise_managed_for_owner` is what keeps a different binary, or a
//! caller who never named one, from standing up a resident other processes
//! would then trust. Each case here asks for the refusal and for the proof
//! that nothing was created on the way to it.

use super::*;

fn scratch(label: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!(
        "hol-guard-managed-identity-{label}-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    root
}

fn is_empty(root: &Path) -> bool {
    std::fs::read_dir(root).unwrap().next().is_none()
}

const FOREIGN_DIGEST: &str = "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0";

#[test]
fn serving_refuses_an_unnamed_generation_or_owner_and_a_foreign_binary() {
    let digest = crate::resident_state::runtime_digest().unwrap();
    let owner = std::process::id();
    let cases: [(&str, u64, u32, &str); 3] = [
        ("an unnamed generation", 0, owner, digest.as_str()),
        ("an unnamed owner", 1, 0, digest.as_str()),
        ("a foreign binary", 1, owner, FOREIGN_DIGEST),
    ];

    for (label, generation, owner_process_id, expected_digest) in cases {
        let root = scratch("serve");
        assert_eq!(
            serve_managed(&root, generation, owner_process_id, expected_digest),
            Err("native_resident_runtime_identity_mismatch".to_owned()),
            "serving accepted {label}"
        );
        assert!(
            is_empty(&root),
            "serving wrote into the state directory after refusing {label}"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }
}

#[test]
fn supervising_refuses_an_unnamed_generation_and_a_foreign_binary() {
    let digest = crate::resident_state::runtime_digest().unwrap();
    let owner = std::process::id();
    let cases: [(&str, u64, &str); 2] = [
        ("an unnamed generation", 0, digest.as_str()),
        ("a foreign binary", 1, FOREIGN_DIGEST),
    ];

    for (label, generation, expected_digest) in cases {
        let root = scratch("supervise");
        assert_eq!(
            supervise_managed_for_owner(&root, generation, expected_digest, owner),
            Err("native_resident_runtime_identity_mismatch".to_owned()),
            "supervising accepted {label}"
        );
        assert!(
            is_empty(&root),
            "supervising claimed a scope after refusing {label}"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }
}
