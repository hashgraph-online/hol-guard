use super::safe_property_list_read;

fn words(arguments: &[&str]) -> Vec<String> {
    arguments.iter().map(|word| (*word).to_owned()).collect()
}

fn proven(arguments: &[&str]) -> bool {
    safe_property_list_read(
        "plutil",
        &words(arguments),
        crate::pretool::PathContext::default(),
    )
}

#[test]
fn a_question_about_a_named_plist_is_admitted() {
    for arguments in [
        vec!["-p", "Info.plist"],
        vec!["-lint", "Info.plist"],
        vec!["-lint", "-s", "Info.plist"],
        vec!["-p", "Info.plist", "Settings.plist"],
        vec!["-extract", "CFBundleVersion", "raw", "Info.plist"],
        vec!["-extract", "items.0.name", "json", "-o", "-", "Info.plist"],
        vec![
            "-extract",
            "flags",
            "json",
            "-expect",
            "array",
            "-o",
            "-",
            "Info.plist",
        ],
        vec!["-type", "CFBundleVersion", "Info.plist"],
        vec![
            "-type",
            "CFBundleVersion",
            "-expect",
            "string",
            "Info.plist",
        ],
        vec!["-p", "--", "Info.plist"],
    ] {
        assert!(proven(&arguments), "{arguments:?}");
    }
}

#[test]
fn a_verb_that_rewrites_the_document_keeps_its_review() {
    for arguments in [
        vec!["-convert", "xml1", "Info.plist"],
        vec!["-insert", "Enabled", "-bool", "YES", "Info.plist"],
        vec!["-replace", "Enabled", "-bool", "NO", "Info.plist"],
        vec!["-remove", "Enabled", "Info.plist"],
        vec!["-create", "xml1", "Info.plist"],
        vec!["Info.plist"],
    ] {
        assert!(!proven(&arguments), "{arguments:?}");
    }
}

/// `-o` says where the result is written, so only standard output is read
/// this way. Without `-o`, only `raw` prints the extracted value: every other
/// format writes it back over the document it came from, which is a rewrite
/// rather than a question about the file.
#[test]
fn writing_the_result_somewhere_keeps_its_review() {
    for arguments in [
        vec!["-extract", "flags", "json", "-o", "out.json", "Info.plist"],
        vec!["-p", "-o", "copy.txt", "Info.plist"],
        vec!["-extract", "flags", "json", "-o"],
        vec!["-extract", "flags", "json", "Info.plist"],
        vec!["-extract", "flags", "xml1", "Info.plist"],
        vec!["-extract", "flags", "binary1", "Info.plist"],
        vec![
            "-extract",
            "flags",
            "json",
            "-expect",
            "array",
            "Info.plist",
        ],
    ] {
        assert!(!proven(&arguments), "{arguments:?}");
    }
}

/// Standard input is content this screen cannot see, and a document with no
/// file to read is not a question about one.
#[test]
fn standard_input_or_a_missing_operand_proves_nothing() {
    for arguments in [
        vec!["-p", "-"],
        vec!["-p", "--", "-"],
        vec!["-lint", "Info.plist", "-"],
        vec!["-p"],
        vec!["-lint"],
        vec!["-extract", "flags", "json"],
        vec!["-type", "flags"],
    ] {
        assert!(!proven(&arguments), "{arguments:?}");
    }
}

/// A key path names a place inside the document; a format and an expected
/// type are each one of a closed set. A word outside those shapes leaves the
/// line under review rather than being read as an operand.
#[test]
fn an_operand_this_screen_does_not_know_proves_nothing() {
    for arguments in [
        vec!["-extract", "../other.plist", "raw", "Info.plist"],
        vec!["-extract", "flags", "objc", "Info.plist"],
        vec![
            "-extract",
            "flags",
            "json",
            "-expect",
            "anything",
            "Info.plist",
        ],
        vec!["-type", "/etc/hosts", "Info.plist"],
        vec!["-p", "-x", "Info.plist"],
    ] {
        assert!(!proven(&arguments), "{arguments:?}");
    }
}

#[test]
fn only_plutil_is_read_this_way() {
    assert!(!safe_property_list_read(
        "defaults",
        &words(&["-p", "Info.plist"]),
        crate::pretool::PathContext::default()
    ));
}

/// Coverage reads the same screen through the context-free public route, where
/// nothing proves which file a named path resolves to. `plutil` therefore
/// takes the session proof `cat` takes: a document is covered only when the
/// home and working directory it is read against are real directories.
mod coverage {
    use crate::pretool::PathContext;

    struct Session {
        root: std::path::PathBuf,
    }

    impl Session {
        fn new() -> Self {
            let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("target")
                .join("property-list-reads")
                .join(format!("session-{}", std::process::id()));
            std::fs::create_dir_all(root.join("project")).unwrap();
            std::fs::write(root.join("project").join("Info.plist"), "<plist/>").unwrap();
            Self {
                root: std::fs::canonicalize(&root).unwrap(),
            }
        }

        fn home(&self) -> String {
            self.root.to_string_lossy().into_owned()
        }

        fn project(&self) -> String {
            self.root.join("project").to_string_lossy().into_owned()
        }
    }

    fn covered(command: &str, home: Option<&str>, cwd: Option<&str>) -> Vec<usize> {
        let model = crate::parse_command(&crate::CommandModelRequestV1 {
            command: command.to_owned(),
            dialect: "posix".to_owned(),
            transport: "shell_string".to_owned(),
            extraction_provenance: "guard-shell".to_owned(),
        })
        .unwrap();
        let context = PathContext {
            home_dir: home,
            cwd,
            ..PathContext::default()
        };
        crate::pretool::segments_safe_alone(&model, context, None)
    }

    #[test]
    fn a_named_document_is_covered_against_a_real_session() {
        let session = Session::new();
        let command = format!("plutil -p {}/Info.plist", session.project());
        assert!(
            covered(&command, Some(&session.home()), Some(&session.project())).contains(&0),
            "{command}"
        );
    }

    #[test]
    fn a_document_read_is_not_covered_without_a_verified_directory() {
        let session = Session::new();
        let command = format!("plutil -p {}/Info.plist", session.project());
        assert!(!covered(&command, None, None).contains(&0), "{command}");
    }
}
