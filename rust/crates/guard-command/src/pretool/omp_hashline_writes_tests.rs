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
        "*** Begin Patch\n[*** Update File: src/a.ts#0AC4]\nPUT 1.=1:\n+x\n*** End Patch\n",
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
        "*** Begin Patch\n[src/a.ts#0AC4]\nPUT 1.=1:\n-x\n+y\n*** End Patch\n",
        "*** Begin Patch\n[src/a.ts#0AC4]\n  [src/b.ts#0AC4]\n*** End Patch\n",
        "*** Begin Patch\n[src/a.ts#0AC4]\nPUT 1.=1:\n+x\n*** End Patch\n[src/b.ts]\n",
        "*** Begin Patch\n*** Update File: src/a.ts\n@@\n-x\n+y\n*** End Patch\n",
        "*** Begin Patch\n*** End Patch\n",
    ] {
        assert_eq!(targets(input), None, "{input:?}");
    }
}
