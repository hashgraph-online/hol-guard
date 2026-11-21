//! A saved approval holds while the lockfile and the install sections of the
//! manifests do, and asks again when anything an install can reach changes.

use super::*;

const LOCK: &str =
    "{\"lockfileVersion\":3,\"packages\":{\"node_modules/left-pad\":{\"version\":\"1.3.0\"}}}";
const MANIFEST: &str = "{\"name\":\"a\",\"version\":\"1.0.0\",\"scripts\":{\"dev\":\"next dev\"},\"dependencies\":{\"left-pad\":\"1.3.0\"}}";

fn manifest_vector(package_json: &str, lockfile: &str) -> Value {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    let mut vector = vectors
        .into_iter()
        .find(|vector| vector["name"] == "manifests_and_lockfiles")
        .unwrap();
    vector["workspace_files"] = json!({
        "package.json": package_json,
        "package-lock.json": lockfile,
        "sub/package.json": "{\"name\":\"b\"}",
    });
    vector
}

/// A saved approval holds while the lockfile and the install sections of the
/// manifest do: a release version bump or a new `dev` script lapsed it before.
#[test]
fn manifest_edits_outside_install_sections_keep_the_saved_approval() {
    let saved = context_token(&manifest_vector(MANIFEST, LOCK), "manifest-saved");

    let bumped = MANIFEST
        .replace("\"1.0.0\"", "\"1.1.0\"")
        .replace("\"next dev\"", "\"next dev --turbo\",\"lint\":\"eslint .\"");
    let current = context_token(&manifest_vector(&bumped, LOCK), "manifest-bumped");
    assert_eq!(
        crate::context_digest::validate_context_tokens(&saved, &current),
        None
    );

    for (name, manifest, lockfile) in [
        (
            "manifest-dependency",
            MANIFEST.replace("\"1.3.0\"", "\"1.3.1\""),
            LOCK.to_owned(),
        ),
        (
            "manifest-hook",
            MANIFEST.replace("\"next dev\"", "\"next dev\",\"postinstall\":\"node x.js\""),
            LOCK.to_owned(),
        ),
        (
            "manifest-lockfile",
            MANIFEST.to_owned(),
            LOCK.replace("1.3.0", "1.3.1"),
        ),
    ] {
        let current = context_token(&manifest_vector(&manifest, &lockfile), name);
        assert!(
            crate::context_digest::validate_context_tokens(&saved, &current).is_some(),
            "{name}"
        );
    }
}

/// An install hook can run any other script by name, so once one is present
/// every script stays bound.
#[test]
fn a_script_an_install_hook_runs_keeps_the_approval_bound() {
    let hooked = MANIFEST.replace(
        "\"next dev\"",
        "\"next dev\",\"postinstall\":\"npm run setup\",\"setup\":\"node a.js\"",
    );
    let saved = context_token(&manifest_vector(&hooked, LOCK), "hook-saved");
    let changed = hooked.replace("node a.js", "node b.js");
    let current = context_token(&manifest_vector(&changed, LOCK), "hook-changed");
    assert!(crate::context_digest::validate_context_tokens(&saved, &current).is_some());
}
