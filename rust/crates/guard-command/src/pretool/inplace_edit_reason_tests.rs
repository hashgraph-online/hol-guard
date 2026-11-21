use super::super::evaluate_pre_tool_with_context;
use crate::CommandModelRequestV1;

fn decision(command: &str) -> (String, String, String) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .unwrap();
    let root = root.to_str().unwrap();
    let request = CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    };
    let decision = evaluate_pre_tool_with_context(&request, Some(root), Some(root)).unwrap();
    (
        decision.minimum_action,
        decision.reason_code,
        decision.reason,
    )
}

#[test]
fn an_in_place_edit_points_the_agent_at_its_file_edit_tool() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .unwrap();
    let root = root.to_str().unwrap();
    let chained = format!(
        "cd {root} && perl -pi -e 's/old_name/new_name/g' src/lib.rs && python -m pytest -q"
    );
    let cases = [
        (chained.as_str(), "perl", true),
        ("perl -i.bak -pe 's/a/b/' src/lib.rs", "perl", false),
        ("sed -i 's/a/b/g' src/lib.rs", "sed", false),
        (
            "sed -Ei.orig 's/a+/b/' src/lib.rs && cargo test",
            "sed",
            true,
        ),
        ("sed --in-place -e 's/a/b/' src/lib.rs", "sed", false),
        ("sed 's/a/b/' -i src/lib.rs", "sed", false),
        ("perl -0pi -e 's/a/b/g' src/lib.rs", "perl", false),
        ("perl -0777 -lpi -e 's/a/b/g' src/lib.rs", "perl", false),
        ("perl -I lib -pi -e 's/a/b/' src/lib.rs", "perl", false),
        ("perl -e 's/a/b/' -i src/lib.rs", "perl", false),
    ];
    for (command, editor, chain) in cases {
        let (action, code, reason) = decision(command);
        assert_eq!(action, "review", "{command}");
        assert_eq!(code, "native_command_review_required", "{command}");
        assert!(
            reason.contains(&format!("because `{editor} -i` rewrites files in place")),
            "{command}: {reason}"
        );
        assert!(
            reason.contains("your file edit tool"),
            "{command}: {reason}"
        );
        assert_eq!(
            reason.contains("run the other steps as separate commands"),
            chain,
            "{command}: {reason}"
        );
    }
}

#[test]
fn other_sed_and_perl_runs_keep_their_reason() {
    for command in [
        "perl -e 'print 1' && make build",
        "sed -e 's/i/j/' src/lib.rs > out.txt",
        "perl -I lib script.pl",
        "perl tools/rename.pl -i src/lib.rs",
        "sed -f -i src/lib.rs",
        "sed --file -i src/lib.rs",
        "perl -e 'print 1' src/lib.rs -i",
        "perl -0777 -ne 'print' src/lib.rs",
    ] {
        let (_, _, reason) = decision(command);
        assert!(
            !reason.contains("rewrites files in place"),
            "{command}: {reason}"
        );
    }
}
