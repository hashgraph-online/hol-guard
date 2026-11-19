use super::{
    missing_header_reason, missing_tagged_header, unparseable_first_header,
    unparseable_header_reason,
};

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
    missing_tagged_header(input, root.0.to_str()).map(|header| header.path)
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
        ("[FILE: src/a.py#0AC4]\nPUT 1.=1:\n+x\n", "FILE: src/a.py"),
        // Noise is stripped and quotes dropped, as Oh My Pi does, before the
        // path is looked up.
        ("[*** Update File: src/b.py#0AC4]\nPUT 1.=1:\n+x\n", "src/b.py"),
        ("[\"src/b.py\"#0AC4]\nPUT 1.=1:\n+x\n", "src/b.py"),
        // A plain missing path is read the same way.
        ("[src/missing.py#0AC4]\nPUT 1.=1:\n+x\n", "src/missing.py"),
    ] {
        assert_eq!(missing_path(input, &root).as_deref(), Some(path), "{input}");
    }
}

#[test]
fn other_headers_keep_their_review() {
    let root = workspace("kept");
    for input in [
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
        // Newer Oh My Pi unwraps a bracketed patch sentinel in a header row.
        "*** Begin Patch\n[*** Begin Patch] [src/a.py#0AC4]\nPUT 1.=1:\n+x\n*** End Patch\n",
        "*** Begin Patch\n[** Begin Patch]*** Update File: src/a.py (2C82) replace 60-62 with [filename#FC1D]\nPUT 61.=61:\n+...\n*** End Patch\n",
        "[src/a.py#0AC4] [*** End Patch]\nPUT 1.=1:\n+x\n",
        // Oh My Pi resolves `..` first, so a missing folder before it proves
        // nothing.
        "[ghost/../src/a.py#0AC4]\nPUT 1.=1:\n+x\n",
        "[*** Update File: ghost/../src/a.py#0AC4]\nPUT 1.=1:\n+x\n",
        // An indented bracket row is body text to Oh My Pi.
        "[src/a.py#0AC4]\nPUT 1.=1:\n  [FILE: src/a.py#0AC4]\n",
    ] {
        assert_eq!(missing_path(input, &root), None, "{input}");
    }
    assert_eq!(
        missing_tagged_header("[FILE: src/a.py#0AC4]\nPUT 1.=1:\n+x\n", None),
        None
    );
}

#[test]
fn the_reason_shows_the_header_and_how_to_write_it() {
    let root = workspace("reason");
    let header =
        missing_tagged_header("[FILE: src/a.py#0AC4]\nPUT 1.=1:\n+x\n", root.0.to_str()).unwrap();
    let reason = missing_header_reason(&header);
    assert!(reason.contains("`[FILE: src/a.py#0AC4]`"), "{reason}");
    assert!(
        reason.contains("as the file `FILE: src/a.py`, which does not exist"),
        "{reason}"
    );
    assert!(reason.contains("[src/app.py#1A2B]"), "{reason}");
    let long = format!("[gone/{} [src/a.py#0AC4]\nPUT 1.=1:\n+x\n", "x".repeat(300));
    let header = missing_tagged_header(&long, root.0.to_str()).unwrap();
    let reason = missing_header_reason(&header);
    assert!(reason.contains("...`"), "{reason}");
    assert!(reason.contains("as a file that does not exist"), "{reason}");
}

// First header lines from Oh My Pi edits that Oh My Pi 18.22 rejects with
// "Input header must be [PATH#TAG]", writing nothing.
#[test]
fn first_headers_oh_my_pi_cannot_read_are_named() {
    for line in [
        "[assistant/analysis code] *** Begin Patch [tool_error] Invalid input: expected header line, got: '[src/jinja2/environment.py#D7FC]",
        "[{\"?\":\"\"}*** End Patch?]We need proper tool syntax. [path#8A65]",
        "[tool_error] Tool input must be provided as a plain string, not JSON.",
        "[{\"path\":\"src/tomli/_parser.py\",\"content\":\"x\"}] lower: [PATH#0A4F]",
        "[x] [src/a.py#1A2B]",
        "[src/a.py#1A2B] trailing",
        "[src/a.py#1A2B]]",
        "[a]b#1A2B]",
        "[]",
        "[ ]",
        "[src/a.py#1A2B",
    ] {
        let input = format!("*** Begin Patch\n{line}\nPUT 1.=1:\n+x\n*** End Patch\n");
        assert!(unparseable_first_header(&input).is_some(), "{line}");
        assert!(unparseable_first_header(&format!("\n{line}\nPUT 1.=1:\n+x\n")).is_some(), "{line}");
    }
}

// Headers Oh My Pi reads, rightly or as a missing file, and lines it treats
// some other way, stay with the other checks.
#[test]
fn first_headers_oh_my_pi_reads_are_left_alone() {
    for line in [
        "[src/a.py#1A2B]",
        "[src/a.py#1A2B]   ",
        "[src/a.py#1A2B]\r",
        "[src/a.py]",
        "[src/[a].py#1A2B]",
        "[[src/a.py#1A2B]",
        "[{\"path\":\"src/a.py\"}]",
        "[Update File: src/a.py#1A2B]",
        "[*** Begin Patch][src/a.py#1A2B]",
        "[ *** End Patch ][src/a.py#1A2B]",
        "[*** Begin Patch]",
        "*** Update File: src/a.py",
        "\t[x] [src/a.py#1A2B]",
        "[x\u{7}] [src/a.py#1A2B]",
    ] {
        let input = format!("*** Begin Patch\n{line}\nPUT 1.=1:\n+x\n*** End Patch\n");
        assert_eq!(unparseable_first_header(&input), None, "{line:?}");
    }
    // Only the first header counts; a later one is left to the other checks.
    assert_eq!(
        unparseable_first_header("*** Begin Patch\n[src/a.py#1A2B]\nPUT 1.=1:\n+x\n[x] y\n"),
        None
    );
    assert_eq!(unparseable_first_header("*** Begin Patch\n"), None);
}

#[test]
fn unreadable_header_reason_shows_the_line() {
    let input = "*** Begin Patch\n[tool_error] `bad` input\nPUT 1.=1:\n+x\n";
    let line = unparseable_first_header(input).unwrap();
    let reason = unparseable_header_reason(&line);
    assert!(reason.contains("`[tool_error] bad input`"), "{reason}");
    assert!(reason.contains("[src/app.py#1A2B]"), "{reason}");
}
