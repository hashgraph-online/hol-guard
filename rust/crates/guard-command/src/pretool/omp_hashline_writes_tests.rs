use super::hashline_targets;

fn targets(input: &str) -> Option<Vec<String>> {
    hashline_targets(input).map(|targets| targets.into_iter().map(|(path, _)| path).collect())
}

#[test]
fn plain_hashline_patches_report_each_file_once() {
    assert_eq!(
        targets("*** Begin Patch\n[src/a.ts#0AC4]\nPUT 1.=1:\n+  // a\n*** End Patch\n"),
        Some(vec!["src/a.ts".to_owned()])
    );
    assert_eq!(
        targets(concat!(
            "*** Begin Patch\n",
            "[src/a.ts#0ac4]\nCUT 2.=3 @moved\n",
            "[src/b.ts]\nPUT >$ @moved\nPUT <4:\n+\n+import { a } from './a';\n",
            "[src/a.ts#0AC4]\nPUT 5*:\n+export const a = 1;\n",
            "*** End Patch",
        )),
        Some(vec!["src/a.ts".to_owned(), "src/b.ts".to_owned()])
    );
    assert_eq!(
        hashline_targets(
            "[src/a.ts]\nPUT >$:\n+x\n[src/b.ts]\nPUT >$:\n+y\n[src/a.ts#0AC4]\nPUT 1.=1:\n+z\n"
        ),
        Some(vec![
            ("src/a.ts".to_owned(), true),
            ("src/b.ts".to_owned(), false)
        ])
    );
    // Oh My Pi trims spaces around the path, as models often write them.
    assert_eq!(
        targets("*** Begin Patch\n[ src/a.ts#0AC4]\nPUT 1.=1:\n+x\n[  src/b.ts ]\nPUT >$:\n+y\n[src/a.ts]\nPUT 2.=2:\n+z\n*** End Patch\n"),
        Some(vec!["src/a.ts".to_owned(), "src/b.ts".to_owned()])
    );
    // Oh My Pi trims the whole header body before it cuts the tag, so a
    // space before the closing bracket still leaves a plain tagged header.
    assert_eq!(
        hashline_targets(
            "[ /home/u/other-project/notes.md#FB48 ]\nPUT 1.=1:\n+Verified settings change.\n"
        ),
        Some(vec![("/home/u/other-project/notes.md".to_owned(), true)])
    );
    assert_eq!(
        super::header_paths("[ src/a.ts #0AC4 ]\nPUT 1.=1:\n+x\n[src/b.ts\t]\nPUT 1.=1:\n+y\n"),
        None
    );
    assert_eq!(
        super::header_paths("[ src/a.ts #0AC4 ]\nPUT 1.=1:\n+x\n"),
        Some(vec!["src/a.ts"])
    );
    // Oh My Pi opens a leading `~/` under the home folder, padded or not.
    assert_eq!(
        targets("*** Begin Patch\n[~/project/src/a.ts#0AC4]\nPUT 1.=1:\n+x\n[ ~/src/b.ts]\nPUT >$:\n+y\n*** End Patch\n"),
        Some(vec!["~/project/src/a.ts".to_owned(), "~/src/b.ts".to_owned()])
    );
    // Windows drive paths name host files. A forward slash works anywhere;
    // a backslash separates only on Windows.
    assert_eq!(
        targets("[C:/Users/x/p/a.md]\nPUT >$:\n+y\n"),
        Some(vec!["C:/Users/x/p/a.md".to_owned()])
    );
    assert_eq!(
        targets("[C:\\Users\\x\\other-project\\notes.md#FB48]\nPUT 1.=1:\n+x\n"),
        cfg!(windows).then(|| vec!["C:\\Users\\x\\other-project\\notes.md".to_owned()])
    );
    // Oh My Pi drops unified-diff `-old` rows under a `PUT`, or keeps
    // bullet-shaped ones as text; either way they are body, not headers.
    assert_eq!(
        targets("*** Begin Patch\n[package.json#0AC4]\nPUT 3.=3:\n-    \"test\": \"echo none\"\n+    \"test\": \"node --test\"\n*** End Patch\n"),
        Some(vec!["package.json".to_owned()])
    );
    assert_eq!(
        targets("[README.md#0AC4]\nPUT >$:\n- [ ] add\n-[src/b.ts#0AC4]\n+- [x] list\n"),
        Some(vec!["README.md".to_owned()])
    );
    // The envelope is optional, as in Oh My Pi.
    assert_eq!(
        targets("[app/[id]/page.tsx#BEEF]\r\nPUT 1.=1:\r\n+x\r\n"),
        Some(vec!["app/[id]/page.tsx".to_owned()])
    );
}

#[test]
fn deletes_moves_and_rewritten_paths_stay_unproven() {
    for input in [
        "*** Begin Patch\n[src/a.ts#0AC4]\nREM\n*** End Patch\n",
        "*** Begin Patch\n[src/a.ts#0AC4]\nMV src/b.ts\n*** End Patch\n",
        "*** Begin Patch\n[\"src/a.ts\"#0AC4]\nPUT 1.=1:\n+x\n*** End Patch\n",
        "*** Begin Patch\n[local:/notes.md#0AC4]\nPUT 1.=1:\n+x\n*** End Patch\n",
        "[C:notes.md#0AC4]\nPUT 1.=1:\n+x\n",
        "[C:\\x\\a.md:stream#0AC4]\nPUT 1.=1:\n+x\n",
        "[\\\\?\\C:\\x\\a.md#0AC4]\nPUT 1.=1:\n+x\n",
        "[ab:/notes.md#0AC4]\nPUT 1.=1:\n+x\n",
        "*** Begin Patch\n[~user/src/a.ts#0AC4]\nPUT 1.=1:\n+x\n*** End Patch\n",
        "*** Begin Patch\n[~#0AC4]\nPUT 1.=1:\n+x\n*** End Patch\n",
        "*** Begin Patch\n[\tsrc/a.ts#0AC4]\nPUT 1.=1:\n+x\n*** End Patch\n",
        "*** Begin Patch\n[\u{feff}src/a.ts#0AC4]\nPUT 1.=1:\n+x\n*** End Patch\n",
        "*** Begin Patch\n[  #0AC4]\nPUT 1.=1:\n+x\n*** End Patch\n",
        "*** Begin Patch\n[src/a.ts#0AC]\nPUT 1.=1:\n+x\n*** End Patch\n",
        "*** Begin Patch\n[src/a#b.ts#0AC4]\nPUT 1.=1:\n+x\n*** End Patch\n",
        "*** Begin Patch\n[#0AC4]\nPUT 1.=1:\n+x\n*** End Patch\n",
        "*** Begin Patch\nPUT 1.=1:\n+x\n[src/a.ts#0AC4]\n*** End Patch\n",
        // A `-` row outside a `PUT` body.
        "*** Begin Patch\n[src/a.ts#0AC4]\n-x\nPUT 1.=1:\n+y\n*** End Patch\n",
        "*** Begin Patch\n[src/a.ts#0AC4]\nCUT 1.=1\n-x\n*** End Patch\n",
        "*** Begin Patch\n[src/a.ts#0AC4]\nPUT 1.=1:\n+y\n[src/b.ts#0AC4]\n-x\n*** End Patch\n",
        "*** Begin Patch\n[src/a.ts#0AC4]\n  [src/b.ts#0AC4]\n*** End Patch\n",
        "*** Begin Patch\n[src/a.ts#0AC4]\nPUT 1.=1:\n+x\n*** End Patch\n[src/b.ts]\n",
        "*** Begin Patch\n*** Update File: src/a.ts\n@@\n-x\n+y\n*** End Patch\n",
        "*** Begin Patch\n*** End Patch\n",
        // Oh My Pi unquotes before it strips the noise, so the quotes stay.
        "*** Begin Patch\n[*** Update File: \"src/a.ts\"#0AC4]\nPUT 1.=1:\n+x\n*** End Patch\n",
        "*** Begin Patch\n[*** Update File: local:/notes.md#0AC4]\nPUT 1.=1:\n+x\n*** End Patch\n",
        "*** Begin Patch\n[*** Update File:#0AC4]\nPUT 1.=1:\n+x\n*** End Patch\n",
        "*** Begin Patch\n[*******src/a.ts#0AC4]\nPUT 1.=1:\n+x\n*** End Patch\n",
        // A bracketed marker on its own row after a header is not a header.
        "*** Begin Patch\n[src/a.ts#0AC4]\nPUT 1.=1:\n+x\n[*** End Patch]\n",
        "[src/a.ts#0AC4]\nPUT 1.=1:\n+x\n[*** Begin Patch]\n[src/b.ts#0AC4]\nPUT 1.=1:\n+y\n",
    ] {
        assert_eq!(targets(input), None, "{input:?}");
    }
}

/// Oh My Pi 18.8 and later unwrap bracketed patch markers and delete
/// `***`/`Update File:` noise from a header path before opening the file,
/// so the proof reports the file Oh My Pi edits. The first two are headers
/// Oh My Pi models sent in benchmark sessions.
#[test]
fn decorated_headers_report_the_file_oh_my_pi_opens() {
    for (input, want) in [
        (
            "*** Begin Patch\n[*** Update File: src/cachetools/__init__.py#BC69]\nPUT 76.=82:\n+        if key in self.__data:\n*** End Patch\n",
            "src/cachetools/__init__.py",
        ),
        (
            "*** Begin Patch\n[*** Begin Patch [src/tomli/_parser.py#8B5B]\nPUT 287.=287:\n+            if access_lists:\n*** End Patch\n",
            "src/tomli/_parser.py",
        ),
        ("[*** Begin Patch] [src/a.ts#0AC4]\nPUT 1.=1:\n+x\n", "src/a.ts"),
        ("[*** Begin Patch]\n[src/a.ts#0AC4]\nPUT 1.=1:\n+x\n*** End Patch\n", "src/a.ts"),
        ("[ *** Begin Patch [ *** Begin Patch] [src/a.ts#0AC4]\nPUT 1.=1:\n+x\n", "src/a.ts"),
        ("[update file: src/a.ts#0AC4]\nPUT 1.=1:\n+x\n", "src/a.ts"),
        ("[** Add File: src/a.ts]\nPUT >$:\n+x\n", "src/a.ts"),
        ("[Move to: src/a.ts#0AC4]\nPUT 1.=1:\n+x\n", "src/a.ts"),
        ("[*** src/a.ts#0AC4]\nPUT 1.=1:\n+x\n", "src/a.ts"),
        // The `*** Abort` marker is unwrapped too, so the header names the
        // file after it, which the write proof then judges on its own.
        ("[*** Abort [.git/hooks/pre-commit#0AC4]\nPUT 1.=1:\n+x\n", ".git/hooks/pre-commit"),
    ] {
        assert_eq!(targets(input), Some(vec![want.to_owned()]), "{input:?}");
        assert_eq!(super::header_paths(input).unwrap_or_default().first().copied(), Some(want), "{input:?}");
    }
}

#[test]
fn bare_rows_under_a_put_are_body_text() {
    // Oh My Pi keeps a row without the `+` as body text under a `PUT`.
    assert_eq!(
        targets("*** Begin Patch\n[src/a.ts#0AC4]\nPUT 1.=1:\nexport const a = 3;\n  return a;\n*** End Patch\n"),
        Some(vec!["src/a.ts".to_owned()])
    );
    assert_eq!(
        targets("[src/a.ts#0AC4]\nPUT >$:\n+// end\nexport const b = 4;\n// MVP notes\n"),
        Some(vec!["src/a.ts".to_owned()])
    );
    assert_eq!(
        targets("[src/a.ts#0AC4]\nPUT 1.=1:\nPUTTY();\nREMOVE_ME();\n"),
        Some(vec!["src/a.ts".to_owned()])
    );
}

#[test]
fn bare_rows_that_read_as_something_else_stay_unproven() {
    for input in [
        // Outside a `PUT` body a bare row has no meaning.
        "[src/a.ts#0AC4]\nexport const a = 3;\n",
        "[src/a.ts#0AC4]\nCUT 1.=1\nexport const a = 3;\n",
        "[src/a.ts#0AC4]\nPUT 1.=1:\n+x\n[src/b.ts#0AC4]\nexport const a = 3;\n",
        // Operations and envelope lines are never body text.
        "[src/a.ts#0AC4]\nPUT 1.=1:\nREM\n",
        "[src/a.ts#0AC4]\nPUT 1.=1:\nMV src/b.ts\n",
        "[src/a.ts#0AC4]\nPUT 1.=1:\n  REM\n",
        "[src/a.ts#0AC4]\nPUT 1.=1:\n\tMV: src/b.ts\n",
        "[src/a.ts#0AC4]\nPUT 1.=1:\nCUT 2.=2\nexport const a = 3;\n",
        "[src/a.ts#0AC4]\nPUT 1.=1:\n*** Update File: src/b.ts\n",
        "[src/a.ts#0AC4]\nPUT 1.=1:\n  *** Delete File: src/b.ts\n",
        "[src/a.ts#0AC4]\nPUT 1.=1:\n¶src/b.ts\n",
        "[src/a.ts#0AC4]\nPUT 1.=1:\n  ¶src/b.ts\n",
        // Anything bracketed might be a header, however it is decorated.
        "[src/a.ts#0AC4]\nPUT 1.=1:\n  [src/b.ts#0AC4]\n",
        "[src/a.ts#0AC4]\nPUT 1.=1:\n\t[~/.zshrc#0AC4]\n",
        "[src/a.ts#0AC4]\nPUT 1.=1:\n[~/.zshrc#0AC4] note\n",
        "[src/a.ts#0AC4]\nPUT 1.=1:\n[1, 2],\n",
        // After the envelope closes nothing may follow.
        "[src/a.ts#0AC4]\nPUT 1.=1:\nx\n*** End Patch\nexport const a = 3;\n",
    ] {
        assert_eq!(targets(input), None, "{input:?}");
    }
}
