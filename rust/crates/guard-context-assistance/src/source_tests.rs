use super::*;
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(1);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "guard-cigar-sources-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn protected_reads_preserve_lines_and_exact_revision_and_bound_chunks() {
    let fixture = Fixture::new();
    let text = format!("{}tail\n", "A line with Unicode é.\r\n".repeat(300));
    fs::write(fixture.0.join("README.md"), &text).unwrap();
    let root = SourceRoot::inspect(&fixture.0).unwrap();
    let source = root.read("README.md").unwrap();
    assert_eq!(
        source.sha256,
        format!("{:x}", Sha256::digest(text.as_bytes()))
    );
    assert_eq!(
        source
            .documents
            .iter()
            .map(|doc| doc.text.as_str())
            .collect::<String>(),
        text
    );
    assert!(source.documents.len() > 1);
    let mut line = 1;
    for doc in source.documents {
        assert!(doc.text.len() <= CHUNK_BYTES);
        assert_eq!(doc.start_line, line);
        line += doc.text.bytes().filter(|c| *c == b'\n').count() as u32;
    }
    fs::write(fixture.0.join("README.md"), "Changed source\n").unwrap();
    assert_ne!(source.sha256, root.read("README.md").unwrap().sha256);
}

#[test]
fn secret_names_traversal_binary_encoding_and_limits_never_admit_documents() {
    let fixture = Fixture::new();
    let root = SourceRoot::inspect(&fixture.0).unwrap();
    for path in [
        ".env",
        "../escape.md",
        "/etc/passwd",
        "secrets/data.ts",
        "a\\..\\data.md",
        "README.md:stream",
    ] {
        assert!(root.read(path).is_err(), "{path}");
    }
    for bytes in [
        vec![255, 254],
        b"binary\0data".to_vec(),
        vec![b'x'; MAX_FILE_BYTES + 1],
        vec![b'x'; CHUNK_BYTES + 1],
    ] {
        fs::write(fixture.0.join("notes.md"), bytes).unwrap();
        assert!(root.read("notes.md").is_err());
    }
    fs::write(
        fixture.0.join("notes.md"),
        "-----BEGIN PRIVATE KEY-----\nprivate test material\n-----END PRIVATE KEY-----",
    )
    .unwrap();
    assert!(matches!(
        root.read("notes.md"),
        Err(RuntimeError::ScopeDenied)
    ));
}

#[cfg(unix)]
#[test]
fn link_and_directory_replacement_do_not_reuse_admitted_roots() {
    let fixture = Fixture::new();
    let root = SourceRoot::inspect(&fixture.0).unwrap();
    fs::write(
        fixture.0.join("normal.md"),
        "Public project documentation\n",
    )
    .unwrap();
    std::os::unix::fs::symlink("normal.md", fixture.0.join("link.md")).unwrap();
    assert!(root.read("link.md").is_err());
    fs::hard_link(fixture.0.join("normal.md"), fixture.0.join("hard.md")).unwrap();
    assert!(root.read("hard.md").is_err());
    fs::remove_file(fixture.0.join("hard.md")).unwrap();
    let old = fixture.0.with_extension("old");
    fs::rename(&fixture.0, &old).unwrap();
    fs::create_dir(&fixture.0).unwrap();
    fs::write(fixture.0.join("normal.md"), "Replacement directory\n").unwrap();
    assert!(matches!(
        root.read("normal.md"),
        Err(RuntimeError::ContextStale)
    ));
    fs::remove_dir_all(old).unwrap();
}
