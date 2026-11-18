use super::{missing_header_reason, missing_unplain_header};

struct Workspace(std::path::PathBuf);

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn workspace(name: &str) -> Workspace {
    let root = std::env::temp_dir().join(format!(
        "guard-omp-recovery-{}-{}-{name}",
        std::process::id(),
        crate::unique_nanos::unique_nanos()
    ));
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::write(root.join("src/a.py"), "a = 1\n").unwrap();
    Workspace(root)
}

fn missing_path(input: &str, root: &Workspace) -> Option<String> {
    missing_unplain_header(input, root.0.to_str()).map(|header| header.path)
}

// Edits Oh My Pi models sent with their reasoning leaked into the header
// line. Oh My Pi reads each as a tagged path to a file that does not exist.
#[test]
fn leaked_reasoning_headers_read_as_missing_files() {
    let root = workspace("leaked");
    for (input, path) in [
        (
            "*** Begin Patch\n[tool/analysis code] JSImport to=functions.edit commentary  { \"input\": \"[src/a.py#D5E8]\nPUT 247.=247:\n+        return False\n*** End Patch\n",
            "tool/analysis code] JSImport to=functions.edit commentary  { \"input\": \"[src/a.py",
        ),
        (
            "*** Begin Patch\n[7C0C? no] WAIT invalid tool namespace? Use [src/a.py#038E]\nPUT 76.=76:\n+    p.append(x)\n*** End Patch\n",
            "7C0C? no] WAIT invalid tool namespace? Use [src/a.py",
        ),
        (
            "*** Begin Patch\n[** Begin Patch]*** Update File: src/a.py (2C82) replace 60-62 with [filename#FC1D]\nPUT 61.=61:\n+...\n*** End Patch\n",
            "Begin Patch]*** Update File: src/a.py (2C82) replace 60-62 with [filename",
        ),
        (
            "*** Begin Patch\n[*** Begin Patch] [src/a.py#0AC4]\nPUT 1.=1:\n+x\n*** End Patch\n",
            "Begin Patch] [src/a.py",
        ),
        ("[FILE: src/a.py#0AC4]\nPUT 1.=1:\n+x\n", "FILE: src/a.py"),
        // Noise is stripped and quotes dropped, as Oh My Pi does, before the
        // path is looked up.
        ("[*** Update File: src/b.py#0AC4]\nPUT 1.=1:\n+x\n", "src/b.py"),
        ("[\"src/b.py\"#0AC4]\nPUT 1.=1:\n+x\n", "src/b.py"),
    ] {
        assert_eq!(missing_path(input, &root).as_deref(), Some(path), "{input}");
    }
}

#[test]
fn other_headers_keep_their_review() {
    let root = workspace("kept");
    for input in [
        // Plain headers are judged by the hashline write proof.
        "[src/missing.py#0AC4]\nPUT 1.=1:\n+x\n",
        // Oh My Pi opens these, so a person decides.
        "[*** Update File: src/a.py#0AC4]\nPUT 1.=1:\n+x\n",
        "['src/a.py'#0AC4]\nPUT 1.=1:\n+x\n",
        // Without a tag the edit may create a new file.
        "[FILE: src/new.py]\nPUT >$:\n+x\n",
        // Oh My Pi refuses a header with `#` left in its path, so it never
        // reads the later one.
        "[src/a.py#NOPE]\nPUT 1.=1:\n+x\n[FILE: src/a.py#0AC4]\nPUT 1.=1:\n+x\n",
        "[FILE: src/a.py#0AC4]\nPUT 1.=1:\n+x\n[src/a#b.py#0AC4]\nPUT 1.=1:\n+x\n",
        // Protected names, `~` and scheme spellings keep their review.
        "[*** Update File: .git/hooks/pre-commit#0AC4]\nPUT >$:\n+exit 0\n",
        "[*** Update File: AGENTS.md#0AC4]\nPUT >$:\n+rules\n",
        "[*** Update File: ~/missing.py#0AC4]\nPUT >$:\n+x\n",
        "[*** Update File: local://notes.md#0AC4]\nPUT >$:\n+x\n",
        // Oh My Pi stops reading at the end marker.
        "[src/a.py#0AC4]\nPUT 1.=1:\n+x\n*** End Patch\n[FILE: src/a.py#0AC4]\n",
        // An indented bracket row is body text to Oh My Pi.
        "[src/a.py#0AC4]\nPUT 1.=1:\n  [FILE: src/a.py#0AC4]\n",
    ] {
        assert_eq!(missing_path(input, &root), None, "{input}");
    }
    assert_eq!(
        missing_unplain_header("[FILE: src/a.py#0AC4]\nPUT 1.=1:\n+x\n", None),
        None
    );
}

#[test]
fn the_reason_shows_the_header_and_how_to_write_it() {
    let root = workspace("reason");
    let header =
        missing_unplain_header("[FILE: src/a.py#0AC4]\nPUT 1.=1:\n+x\n", root.0.to_str()).unwrap();
    let reason = missing_header_reason(&header);
    assert!(reason.contains("`[FILE: src/a.py#0AC4]`"), "{reason}");
    assert!(
        reason.contains("as the file `FILE: src/a.py`, which does not exist"),
        "{reason}"
    );
    assert!(reason.contains("[src/app.py#1A2B]"), "{reason}");
    let long = format!("[gone/{} [src/a.py#0AC4]\nPUT 1.=1:\n+x\n", "x".repeat(300));
    let header = missing_unplain_header(&long, root.0.to_str()).unwrap();
    let reason = missing_header_reason(&header);
    assert!(reason.contains("...`"), "{reason}");
    assert!(reason.contains("as a file that does not exist"), "{reason}");
}
