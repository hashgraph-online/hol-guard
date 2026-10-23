use super::*;
use crate::builder_context::derive_from_bytes;

#[test]
fn build_argv_is_local_only_and_excludes_candidate_source() {
    let context = derive_from_bytes(
        &"a".repeat(64),
        "0123456789abcdef",
        include_bytes!("../../../../gauntlet/control_plane/Builder.Dockerfile"),
        include_bytes!("../../../../gauntlet/control_plane/builder_entry.py"),
        include_bytes!("../../../../gauntlet/control_plane/build_artifact.py"),
        include_bytes!("../../../../gauntlet/control_plane/Builder.apparmor"),
    )
    .unwrap();
    let plan = fixed_builder_image_plan(
        &context,
        "0123456789abcdef",
        &"b".repeat(64),
        &"c".repeat(64),
    )
    .unwrap();
    let argv = build_argv(&plan);
    assert!(argv.contains(&"--pull=never".to_owned()));
    assert!(argv.contains(&"--no-cache".to_owned()));
    assert!(!argv
        .iter()
        .any(|word| word.contains("source.tar.gz") || word == "--volume"));
    assert_eq!(
        argv.last().unwrap(),
        "/var/lib/hol-gauntlet/builds/0123456789abcdef/builder-image-context"
    );
}
