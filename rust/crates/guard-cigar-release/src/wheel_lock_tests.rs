//! Wheel-lock validation cases, sharing the parent catalog fixture.
use super::*;

#[test]
fn incomplete_dependency_locks_invalid_paths_hashes_and_duplicate_ids_are_refused() {
    let mut doc = document();
    doc.builds[0].platforms[0].dependencies.clear();
    let catalog = verify(&doc).unwrap();
    assert_eq!(
        catalog
            .prepare(build_id(&catalog), "darwin-arm64", false)
            .unwrap_err(),
        ReleaseError::DependencyLockMissing
    );
    let mut duplicate = document();
    duplicate.builds.push(duplicate.builds[0].clone());
    assert_eq!(
        verify(&duplicate).unwrap_err(),
        ReleaseError::DuplicateIdentity
    );
    for changed in ["path", "hash", "tag", "duplicate_dependency"] {
        let mut doc = document();
        let artifact = &mut doc.builds[0].platforms[0];
        match changed {
            "path" => artifact.wheel.as_mut().unwrap().filename = "../payload.whl".into(),
            "hash" => artifact.worker_sha256 = "ABC".into(),
            "tag" => {
                artifact.wheel.as_mut().unwrap().source = WheelSource::GithubCigarRelease {
                    tag: "v0.14.1/other".into(),
                }
            }
            _ => artifact.dependencies.push(artifact.dependencies[0].clone()),
        }
        assert!(verify(&doc).is_err(), "{changed}");
    }
}
