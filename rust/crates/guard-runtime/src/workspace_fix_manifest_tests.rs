use super::*;

const MANIFEST: &str = "{\n  \"name\": \"app\",\n  \"dependencies\": {\n    \"left-pad\": \"^1.0.0\",\n    \"other\": \"2.0.0\"\n  },\n  \"devDependencies\": {\"left-pad\": \"~1.1.0\"}\n}\n";

fn plan(text: &str, fix: &str) -> Result<Vec<FixEdit>, Code> {
    plan_edits(text, "left-pad", fix)
}

#[test]
fn edits_only_the_spec_text_and_keeps_the_operator() {
    let edits = plan(MANIFEST, "1.3.0").unwrap();
    assert_eq!(edits.len(), 2);
    assert_eq!(edits[0].section, "dependencies");
    assert_eq!(edits[0].to_spec, "^1.3.0");
    assert_eq!(edits[1].to_spec, "~1.3.0");
    let updated = apply_edits(MANIFEST, &edits).unwrap();
    assert_eq!(
        updated,
        MANIFEST
            .replace("^1.0.0", "^1.3.0")
            .replace("~1.1.0", "~1.3.0")
    );
}

#[test]
fn offsets_are_byte_offsets_of_the_raw_text() {
    let text = "{\"description\": \"caf\u{e9}\", \"dependencies\": {\"left-pad\": \"1.0.0\"}}";
    let edits = plan(text, "1.0.1").unwrap();
    assert_eq!(&text[edits[0].start..edits[0].end], "1.0.0");
    assert!(apply_edits(text, &edits).unwrap().contains("\"1.0.1\""));
}

#[test]
fn a_range_that_already_covers_the_fix_is_not_edited() {
    assert_eq!(plan(MANIFEST, "1.1.0").map(|e| e.len()), Ok(1));
    assert_eq!(
        plan("{\"dependencies\": {\"left-pad\": \"^2.0.0\"}}", "1.5.0"),
        Err("declared_range_already_covers_fix")
    );
}

#[test]
fn versions_compare_numerically_not_as_text() {
    assert_eq!(
        plan("{\"dependencies\": {\"left-pad\": \"1.9.0\"}}", "1.10.0")
            .map(|e| e[0].to_spec.clone()),
        Ok("1.10.0".to_owned())
    );
}

#[test]
fn unsupported_specs_report_their_reason() {
    let cases = [
        ("workspace:*", "spec_workspace_protocol"),
        ("npm:other@1.0.0", "spec_npm_alias"),
        ("file:../x", "spec_local_path"),
        ("git+https://example.test/x.git", "spec_git_or_url"),
        ("latest", "spec_dist_tag"),
        (">=1.0.0 <2", "spec_not_plain_semver"),
        ("1.0.0-beta.1", "spec_not_plain_semver"),
        ("1.0.0\\n", "spec_not_plain_semver"),
    ];
    for (spec, reason) in cases {
        let text = format!("{{\"dependencies\": {{\"left-pad\": \"{spec}\"}}}}");
        assert_eq!(plan(&text, "1.2.3"), Err(reason), "{spec}");
    }
}

#[test]
fn refuses_what_it_cannot_place_exactly() {
    assert_eq!(plan("[]", "1.2.3"), Err("manifest_invalid_json"));
    assert_eq!(plan("{\"a\": 1,}", "1.2.3"), Err("manifest_invalid_json"));
    assert_eq!(plan("{}", "1.2.3"), Err("not_declared"));
    assert_eq!(
        plan("{\"dependencies\": {\"left-pad\": 1}}", "1.2.3"),
        Err("spec_not_a_string")
    );
    assert_eq!(
        plan("{\"dependencies\": {}, \"dependencies\": {}}", "1.2.3"),
        Err("manifest_duplicate_section")
    );
    assert_eq!(
        plan(
            "{\"dependencies\": {\"left-pad\": \"1.0.0\", \"left-pad\": \"1.0.1\"}}",
            "1.2.3"
        ),
        Err("manifest_duplicate_declaration")
    );
    let deep = format!("{}{}", "[".repeat(300), "]".repeat(300));
    assert_eq!(
        plan(&format!("{{\"a\": {deep}}}"), "1.2.3"),
        Err("manifest_too_deep")
    );
}

#[test]
fn a_trailing_newline_never_counts_as_a_plain_version() {
    assert_eq!(
        plan(MANIFEST, "1.3.0\n"),
        Err("fix_version_not_plain_semver")
    );
    assert_eq!(plan(MANIFEST, "1.3"), Err("fix_version_not_plain_semver"));
    assert_eq!(
        plan(MANIFEST, "\u{661}.0.0"),
        Err("fix_version_not_plain_semver")
    );
    let mut edits = plan(MANIFEST, "1.3.0").unwrap();
    edits[0].to_spec = "^1.3.0\n".to_owned();
    assert_eq!(apply_edits(MANIFEST, &edits), Err("edit_not_plain_spec"));
    edits[0].to_spec = "\"^1.3.0".to_owned();
    assert_eq!(apply_edits(MANIFEST, &edits), Err("edit_not_plain_spec"));
}

#[test]
fn applying_to_a_changed_manifest_is_refused() {
    let edits = plan(MANIFEST, "1.3.0").unwrap();
    let moved = MANIFEST.replace("^1.0.0", "^1.0.1");
    assert_eq!(apply_edits(&moved, &edits), Err("manifest_changed"));
}
