use std::fs;
use std::path::Path;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::*;

const ENCODING: &str = if cfg!(windows) { "utf16le" } else { "os_bytes" };

fn encoded(path: &Path) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        hex::encode(path.as_os_str().as_bytes())
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let bytes: Vec<u8> = path
            .as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect();
        hex::encode(bytes)
    }
}

fn skill(root: &Path, name: &str, frontmatter: &str) -> std::path::PathBuf {
    let directory = root.join(name);
    fs::create_dir_all(&directory).unwrap();
    let document = directory.join("SKILL.md");
    fs::write(
        &document,
        format!("---\nname: {name}\ndescription: Prepare a report.\n{frontmatter}---\nPRIVATE INSTRUCTIONS\n"),
    )
    .unwrap();
    document
}

fn run(request: Value) -> Result<Value, String> {
    let bytes = serde_json::to_vec(&request).unwrap();
    run_command(bytes.as_slice()).map(|answer| serde_json::from_slice(&answer).unwrap())
}

fn index_request(home: &Path, roots: &[(&str, &std::path::PathBuf)]) -> Value {
    json!({
        "schema": SCHEMA,
        "op": "index",
        "path_encoding": ENCODING,
        "home_hex": encoded(home),
        "roots": roots
            .iter()
            .map(|(root_id, root)| json!({ "root_id": root_id, "root_hex": encoded(root) }))
            .collect::<Vec<_>>(),
    })
}

fn inspect_request(home: &Path, root: &Path, document: &Path, digest: &str) -> Value {
    json!({
        "schema": SCHEMA,
        "op": "inspect",
        "path_encoding": ENCODING,
        "home_hex": encoded(home),
        "root_hex": encoded(root),
        "document_hex": encoded(document),
        "metadata_digest": digest,
    })
}

#[test]
fn index_reads_only_bounded_metadata_from_every_root() {
    let home = tempfile::tempdir().unwrap();
    let first = home.path().join(".agents/skills");
    let second = home.path().join(".codex/skills");
    skill(&first, "report", "allowed-tools: '*'\n");
    skill(&second, "report", "compatibility: claude\n");

    let answer = run(index_request(home.path(), &[("a", &first), ("b", &second)])).unwrap();

    assert_eq!(answer["issues"], json!([]));
    let records = answer["records"].as_array().unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["root_id"], "a");
    assert_eq!(records[1]["root_id"], "b");
    assert_eq!(
        records[0]["document_hex"],
        hex::encode("report/SKILL.md".as_bytes())
    );
    let metadata = &records[0]["metadata"];
    let header = "name: report\ndescription: Prepare a report.\nallowed-tools: '*'\n";
    assert_eq!(metadata["name"], "report");
    assert_eq!(metadata["description"], "Prepare a report.");
    assert_eq!(metadata["compatibility"], "");
    assert_eq!(metadata["requested_tools"], "*");
    assert_eq!(
        metadata["metadata_digest"],
        hex::encode(Sha256::digest(header.as_bytes()))
    );
    assert_eq!(metadata["requirements_complete"], false);
    assert_eq!(metadata["instruction_content_loaded"], false);
    assert_eq!(metadata["dependencies"], parse_dependencies(false, None));
    assert_eq!(records[1]["metadata"]["compatibility"], "claude");
    assert!(!answer.to_string().contains("PRIVATE INSTRUCTIONS"));
}

#[test]
fn malformed_or_over_limit_metadata_is_an_issue_code() {
    let cases: Vec<(String, &str)> = vec![
        (
            "name: replaced\n".to_owned(),
            "metadata-invalid-frontmatter",
        ),
        (
            "compatibility: !!python/object/apply:os.system ['echo unsafe']\n".to_owned(),
            "metadata-invalid-frontmatter",
        ),
        (
            "description: duplicate\n".to_owned(),
            "metadata-invalid-frontmatter",
        ),
        (
            "compatibility: null\n".to_owned(),
            "metadata-invalid-compatibility",
        ),
        (
            format!("compatibility: {}\n", "x".repeat(501)),
            "metadata-invalid-compatibility",
        ),
        (
            format!("allowed-tools: {}\n", "x".repeat(2049)),
            "metadata-invalid-tool-request",
        ),
        (
            "allowed-tools: [a]\n".to_owned(),
            "metadata-invalid-tool-request",
        ),
        (
            format!("# {}\n", "x".repeat(20_000)),
            "metadata-frontmatter-limit",
        ),
    ];
    for (frontmatter, reason) in cases {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("skills");
        skill(&root, "report", &frontmatter);
        let answer = run(index_request(home.path(), &[("root", &root)])).unwrap();
        assert_eq!(answer["records"], json!([]), "{reason}");
        assert_eq!(
            answer["issues"],
            json!([{ "root_id": "root", "reason": reason }])
        );
    }
}

#[test]
fn names_must_match_their_directory_and_descriptions_must_be_text() {
    for (name, body, reason) in [
        (
            "report",
            "name: other\ndescription: d\n",
            "metadata-invalid-name-or-description",
        ),
        (
            "Report",
            "name: Report\ndescription: d\n",
            "metadata-invalid-name-or-description",
        ),
        (
            "report",
            "name: report\ndescription: '  '\n",
            "metadata-invalid-name-or-description",
        ),
        (
            "report",
            "name: report\ndescription: 7\n",
            "metadata-invalid-name-or-description",
        ),
        (
            "report",
            "name: report\n",
            "metadata-invalid-name-or-description",
        ),
    ] {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("skills");
        fs::create_dir_all(root.join(name)).unwrap();
        fs::write(
            root.join(name).join("SKILL.md"),
            format!("---\n{body}---\n"),
        )
        .unwrap();
        let answer = run(index_request(home.path(), &[("root", &root)])).unwrap();
        assert_eq!(
            answer["issues"],
            json!([{ "root_id": "root", "reason": reason }]),
            "{body}"
        );
    }
}

#[test]
fn frontmatter_needs_both_fences_and_utf8() {
    for (content, reason) in [
        (b"name: report\n".as_slice(), "metadata-frontmatter-missing"),
        (
            b"---\nname: report\n".as_slice(),
            "metadata-frontmatter-limit",
        ),
        (
            b"---\nname: \xff\n---\n".as_slice(),
            "metadata-invalid-utf8",
        ),
    ] {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("skills");
        fs::create_dir_all(root.join("report")).unwrap();
        fs::write(root.join("report/SKILL.md"), content).unwrap();
        let answer = run(index_request(home.path(), &[("root", &root)])).unwrap();
        assert_eq!(
            answer["issues"],
            json!([{ "root_id": "root", "reason": reason }])
        );
    }
}

#[test]
fn fences_follow_python_line_splitting() {
    assert_eq!(
        split_lines(b"a\r\nb\rc\nd"),
        vec![&b"a\r\n"[..], &b"b\r"[..], &b"c\n"[..], &b"d"[..]]
    );
    assert_eq!(strip_ascii(b"\x0b --- \x0c\r\n"), b"---");
    assert_eq!(
        frontmatter(b" ---\r\nname: x\r--- \nbody").unwrap(),
        b"name: x\r"
    );
}

#[test]
fn declared_dependencies_reach_the_manifest_reader() {
    let home = tempfile::tempdir().unwrap();
    let root = home.path().join("skills");
    skill(&root, "report", "metadata:\n  hol-guard.dependencies: 7\n");
    let answer = run(index_request(home.path(), &[("root", &root)])).unwrap();
    assert_eq!(
        answer["records"][0]["metadata"]["dependencies"],
        parse_dependencies(true, None)
    );

    let entries = vec![(
        "metadata".to_owned(),
        PyVal::Dict(vec![(
            "hol-guard.dependencies".to_owned(),
            PyVal::Str("{}".to_owned()),
        )]),
    )];
    assert_eq!(dependency_manifest(&entries), (true, Some("{}")));
    let null = vec![(
        "metadata".to_owned(),
        PyVal::Dict(vec![("hol-guard.dependencies".to_owned(), PyVal::Null)]),
    )];
    assert_eq!(dependency_manifest(&null), (false, None));
}

#[test]
fn the_index_stops_at_its_ceiling() {
    let home = tempfile::tempdir().unwrap();
    let root = home.path().join("skills");
    for index in 0..=INDEX_LIMIT {
        skill(&root, &format!("report-{index}"), "");
    }
    let other = home.path().join("other");
    skill(&other, "report", "");
    let answer = run(index_request(
        home.path(),
        &[("root", &root), ("other", &other)],
    ))
    .unwrap();
    assert_eq!(answer["records"].as_array().unwrap().len(), INDEX_LIMIT);
    assert_eq!(
        answer["issues"],
        json!([{ "root_id": "root", "reason": "skill-index-limit" }])
    );
}

#[cfg(unix)]
#[test]
fn linked_roots_and_documents_are_never_read() {
    let home = tempfile::tempdir().unwrap();
    let outside = home.path().join("outside");
    let document = skill(&outside, "report", "");
    let linked = home.path().join("linked");
    std::os::unix::fs::symlink(&outside, &linked).unwrap();
    let answer = run(index_request(home.path(), &[("linked", &linked)])).unwrap();
    assert_eq!(answer["records"], json!([]));
    assert_eq!(
        answer["issues"],
        json!([{ "root_id": "linked", "reason": "linked-root-not-indexed" }])
    );

    let safe = home.path().join("safe");
    fs::create_dir_all(safe.join("report")).unwrap();
    std::os::unix::fs::symlink(&document, safe.join("report/SKILL.md")).unwrap();
    let answer = run(index_request(home.path(), &[("safe", &safe)])).unwrap();
    assert_eq!(answer["records"], json!([]));
    assert_eq!(
        answer["issues"],
        json!([{ "root_id": "safe", "reason": "linked-skill-not-indexed" }])
    );
}

#[test]
fn inspection_hashes_the_directory_and_refuses_changed_metadata() {
    let home = tempfile::tempdir().unwrap();
    let root = home.path().join("skills");
    let document = skill(&root, "report", "");
    fs::write(document.parent().unwrap().join("reference.md"), "first").unwrap();
    let indexed = run(index_request(home.path(), &[("root", &root)])).unwrap();
    let digest = indexed["records"][0]["metadata"]["metadata_digest"]
        .as_str()
        .unwrap()
        .to_owned();

    let first = run(inspect_request(home.path(), &root, &document, &digest)).unwrap();
    fs::write(document.parent().unwrap().join("reference.md"), "changed").unwrap();
    let second = run(inspect_request(home.path(), &root, &document, &digest)).unwrap();
    assert_eq!(first["identity"]["status"], "complete");
    assert_eq!(second["identity"]["status"], "complete");
    assert_eq!(first["identity"]["reason"], Value::Null);
    assert_ne!(
        first["identity"]["manifest_digest"],
        second["identity"]["manifest_digest"]
    );

    let text = fs::read_to_string(&document).unwrap();
    fs::write(&document, text.replace("Prepare a report.", "Changed.")).unwrap();
    assert_eq!(
        run(inspect_request(home.path(), &root, &document, &digest)).unwrap(),
        json!({ "error": "skill-metadata-changed" })
    );
}

#[test]
fn malformed_requests_are_refused() {
    let home = tempfile::tempdir().unwrap();
    let root = home.path().join("skills");
    let mut wrong_schema = index_request(home.path(), &[("root", &root)]);
    wrong_schema["schema"] = json!("local-skill-index.v0");
    let mut extra = index_request(home.path(), &[("root", &root)]);
    extra["metadata_digest"] = json!("x");
    let mut unknown = index_request(home.path(), &[("root", &root)]);
    unknown["cancel"] = json!(true);
    let mut missing_digest = inspect_request(home.path(), &root, &root, "x");
    missing_digest
        .as_object_mut()
        .unwrap()
        .remove("metadata_digest");
    for request in [
        wrong_schema,
        extra,
        unknown,
        index_request(home.path(), &[]),
        index_request(home.path(), &[("", &root)]),
        missing_digest,
        json!({ "schema": SCHEMA, "op": "index", "path_encoding": ENCODING, "home_hex": "zz", "roots": [] }),
    ] {
        assert_eq!(
            run(request).unwrap_err(),
            "local_skill_index_request_invalid"
        );
    }
}
