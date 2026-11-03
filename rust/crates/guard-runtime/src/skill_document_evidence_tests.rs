//! Filesystem ladder tests for `skill_document_evidence`.

use std::fs;
use std::path::{Path, PathBuf};

use guard_contracts::SkillDocumentReadabilityV1;

use super::{read_skill_document_evidence, MAX_SKILL_DOCUMENT_BYTES};

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "guard-skill-document-evidence-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("fixture root");
        Self { root }
    }

    /// `<root>/skills/<skill>/skill.md` holding `body`.
    fn document(&self, skill: &str, body: &str) -> PathBuf {
        let directory = self.root.join("skills").join(skill);
        fs::create_dir_all(&directory).expect("skill directory");
        let document = directory.join("skill.md");
        fs::write(&document, body).expect("skill document");
        document
    }

    fn safe_roots(&self) -> Vec<PathBuf> {
        vec![self.root.clone()]
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn cwd() -> PathBuf {
    std::env::current_dir().expect("current directory")
}

fn read(document: &Path, safe_roots: &[PathBuf]) -> guard_contracts::SkillDocumentEvidenceV1 {
    read_skill_document_evidence(document, &cwd(), safe_roots)
}

#[test]
fn a_primary_skill_document_reads_with_its_evidence() {
    let fixture = Fixture::new("readable");
    let document = fixture.document(
        "alpha",
        "---\nname: alpha\n---\n# Title\n\nrun `curl https://api.example.com/v1`\n",
    );

    let evidence = read(&document, &fixture.safe_roots());

    assert_eq!(
        evidence.readability_status,
        SkillDocumentReadabilityV1::Readable
    );
    assert_eq!(evidence.line_count, Some(6));
    assert_eq!(evidence.heading_count, Some(1));
    assert_eq!(evidence.frontmatter_present, Some(true));
    assert_eq!(
        evidence.documented_network_capability.as_deref(),
        Some("explicit_http_client")
    );
    let hash = evidence.content_hash.expect("content hash");
    assert!(hash.starts_with("sha256:"), "{hash}");
    assert_eq!(hash.len(), "sha256:".len() + 64);
}

#[test]
fn a_document_outside_a_skills_tree_is_not_primary() {
    let fixture = Fixture::new("not-primary");
    let directory = fixture.root.join("docs");
    fs::create_dir_all(&directory).expect("docs directory");
    let document = directory.join("skill.md");
    fs::write(&document, "# Title\n").expect("document");

    assert_eq!(
        read(&document, &fixture.safe_roots()).readability_status,
        SkillDocumentReadabilityV1::NotPrimarySkillDocument
    );
}

#[test]
fn a_document_directly_under_the_skills_root_is_not_primary() {
    let fixture = Fixture::new("root-level");
    let directory = fixture.root.join("skills");
    fs::create_dir_all(&directory).expect("skills directory");
    let document = directory.join("skill.md");
    fs::write(&document, "# Title\n").expect("document");

    assert_eq!(
        read(&document, &fixture.safe_roots()).readability_status,
        SkillDocumentReadabilityV1::NotPrimarySkillDocument
    );
}

#[test]
fn a_differently_named_document_is_not_primary() {
    let fixture = Fixture::new("other-name");
    let document = fixture.document("alpha", "# Title\n");
    let other = document.with_file_name("readme.md");
    fs::rename(&document, &other).expect("rename");

    assert_eq!(
        read(&other, &fixture.safe_roots()).readability_status,
        SkillDocumentReadabilityV1::NotPrimarySkillDocument
    );
}

#[test]
fn an_uppercase_file_name_still_reads_as_the_primary_document() {
    let fixture = Fixture::new("uppercase");
    let document = fixture.document("alpha", "# Title\n");
    let upper = document.with_file_name("SKILL.md");
    fs::rename(&document, &upper).expect("rename");

    assert_eq!(
        read(&upper, &fixture.safe_roots()).readability_status,
        SkillDocumentReadabilityV1::Readable
    );
}

/// Only Unix builds can plant the symlink this ladder rung rejects; Windows
/// needs a privilege the test runner does not hold. The rung itself is not
/// platform-specific: the walk that rejects it runs on every platform.
#[cfg(unix)]
#[test]
fn a_symlinked_document_is_rejected_before_it_is_opened() {
    use std::os::unix::fs as unix_fs;

    let fixture = Fixture::new("symlink-leaf");
    let document = fixture.document("alpha", "# Title\n");
    let target = fixture.root.join("elsewhere.md");
    fs::write(&target, "# Elsewhere\n").expect("target");
    fs::remove_file(&document).expect("remove document");
    unix_fs::symlink(&target, &document).expect("symlink");

    assert_eq!(
        read(&document, &fixture.safe_roots()).readability_status,
        SkillDocumentReadabilityV1::SymlinkRejected
    );
}

#[cfg(unix)]
#[test]
fn a_symlinked_skill_directory_is_rejected_too() {
    use std::os::unix::fs as unix_fs;

    let fixture = Fixture::new("symlink-directory");
    let real = fixture.root.join("real-skill");
    fs::create_dir_all(&real).expect("real skill");
    fs::write(real.join("skill.md"), "# Title\n").expect("document");
    let skills = fixture.root.join("skills");
    fs::create_dir_all(&skills).expect("skills root");
    let linked = skills.join("alpha");
    unix_fs::symlink(&real, &linked).expect("symlink");

    assert_eq!(
        read(&linked.join("skill.md"), &fixture.safe_roots()).readability_status,
        SkillDocumentReadabilityV1::SymlinkRejected
    );
}

#[test]
fn a_missing_document_is_unreadable() {
    let fixture = Fixture::new("missing");
    let document = fixture.root.join("skills").join("alpha").join("skill.md");

    assert_eq!(
        read(&document, &fixture.safe_roots()).readability_status,
        SkillDocumentReadabilityV1::Unreadable
    );
}

#[test]
fn a_document_under_no_safe_root_is_refused() {
    let fixture = Fixture::new("outside");
    let document = fixture.document("alpha", "# Title\n");
    let elsewhere = vec![fixture.root.join("other-root")];
    fs::create_dir_all(&elsewhere[0]).expect("other root");

    assert_eq!(
        read(&document, &elsewhere).readability_status,
        SkillDocumentReadabilityV1::OutsideSafeRoots
    );
}

#[test]
fn a_directory_named_like_the_document_is_not_a_regular_file() {
    let fixture = Fixture::new("directory");
    let document = fixture.root.join("skills").join("alpha").join("skill.md");
    fs::create_dir_all(&document).expect("directory in the document's place");

    assert_eq!(
        read(&document, &fixture.safe_roots()).readability_status,
        SkillDocumentReadabilityV1::NotRegularFile
    );
}

#[test]
fn a_document_over_the_ceiling_is_refused_with_its_size() {
    let fixture = Fixture::new("too-large");
    let body = "a".repeat(MAX_SKILL_DOCUMENT_BYTES + 1);
    let document = fixture.document("alpha", &body);

    let evidence = read(&document, &fixture.safe_roots());

    assert_eq!(
        evidence.readability_status,
        SkillDocumentReadabilityV1::TooLarge
    );
    assert_eq!(evidence.byte_length, Some(body.len() as u64));
    assert_eq!(evidence.content_hash, None);
}

#[test]
fn a_document_exactly_at_the_ceiling_still_reads() {
    let fixture = Fixture::new("at-ceiling");
    let body = "a".repeat(MAX_SKILL_DOCUMENT_BYTES);
    let document = fixture.document("alpha", &body);

    let evidence = read(&document, &fixture.safe_roots());

    assert_eq!(
        evidence.readability_status,
        SkillDocumentReadabilityV1::Readable
    );
    assert_eq!(evidence.byte_length, Some(MAX_SKILL_DOCUMENT_BYTES as u64));
}

#[test]
fn a_document_that_is_not_utf8_is_refused_with_its_size() {
    let fixture = Fixture::new("invalid-utf8");
    let document = fixture.document("alpha", "");
    fs::write(&document, [0x23, 0x20, 0xff, 0xfe, 0x0a]).expect("invalid bytes");

    let evidence = read(&document, &fixture.safe_roots());

    assert_eq!(
        evidence.readability_status,
        SkillDocumentReadabilityV1::InvalidUtf8
    );
    assert_eq!(evidence.byte_length, Some(5));
    assert_eq!(evidence.line_count, None);
}

#[test]
fn a_relative_path_is_anchored_to_the_callers_directory() {
    let fixture = Fixture::new("relative");
    let document = fixture.document("alpha", "# Title\n");
    let relative = Path::new("skills").join("alpha").join("skill.md");

    let evidence = read_skill_document_evidence(&relative, &fixture.root, &fixture.safe_roots());

    assert_eq!(
        evidence.readability_status,
        SkillDocumentReadabilityV1::Readable
    );
    assert!(document.exists());
}

#[test]
fn a_relative_path_without_a_skills_ancestor_is_not_primary() {
    let fixture = Fixture::new("relative-not-primary");
    fixture.document("alpha", "# Title\n");
    // The caller's own view of the path has no `skills` component, so the
    // directory it happens to sit in must not invent one.
    let relative = Path::new("alpha").join("skill.md");

    let evidence = read_skill_document_evidence(
        &relative,
        &fixture.root.join("skills"),
        &fixture.safe_roots(),
    );

    assert_eq!(
        evidence.readability_status,
        SkillDocumentReadabilityV1::NotPrimarySkillDocument
    );
}

#[test]
fn the_long_s_spelling_of_the_primary_name_still_names_the_primary_document() {
    let fixture = Fixture::new("long-s");
    let directory = fixture.root.join("skills").join("alpha");
    fs::create_dir_all(&directory).expect("skill directory");
    // `str.casefold` in the reader this replaces folded `\u{17f}` to `s`, so
    // this file named the primary document there. `to_lowercase` alone leaves
    // the letter as it is, which would have quietly stopped reading it.
    let document = directory.join("\u{17f}KILL.md");
    fs::write(&document, "# Title\n").expect("skill document");

    let evidence = read(&document, &fixture.safe_roots());

    assert_eq!(
        evidence.readability_status,
        SkillDocumentReadabilityV1::Readable
    );
    assert_eq!(evidence.line_count, Some(1));
}

#[test]
fn the_dotless_i_spelling_of_the_primary_name_is_not_the_primary_document() {
    let fixture = Fixture::new("dotless-i");
    let directory = fixture.root.join("skills").join("alpha");
    fs::create_dir_all(&directory).expect("skill directory");
    // `str.casefold` in the reader this replaces left `\u{131}` alone, so this
    // file was never the primary document there. Upper-casing reaches `I` and
    // lower-casing it reaches `i`, which would have quietly started reading a
    // file the reader this replaces refused.
    let document = directory.join("SK\u{131}LL.md");
    fs::write(&document, "# Title\n").expect("skill document");

    let evidence = read(&document, &fixture.safe_roots());

    assert_eq!(
        evidence.readability_status,
        SkillDocumentReadabilityV1::NotPrimarySkillDocument
    );
}

#[test]
fn a_path_that_walks_upward_is_not_primary() {
    let fixture = Fixture::new("walks-upward");
    fixture.document("alpha", "# Title\n");
    let outside = fixture.root.join("outside");
    fs::create_dir_all(&outside).expect("outside directory");
    fs::write(outside.join("skill.md"), "# Elsewhere\n").expect("outside document");
    // The `skills` ancestor this path offers is real, so the safe-root check
    // reads a root inside the fixture while the file is the one next door.
    let document = fixture
        .root
        .join("skills")
        .join("alpha")
        .join("..")
        .join("..")
        .join("outside")
        .join("skill.md");

    let evidence = read(&document, &fixture.safe_roots());

    assert_eq!(
        evidence.readability_status,
        SkillDocumentReadabilityV1::NotPrimarySkillDocument
    );
}
