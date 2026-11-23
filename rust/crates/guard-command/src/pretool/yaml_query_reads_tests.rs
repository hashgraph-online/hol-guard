use super::{safe_yaml_query_file_arguments, safe_yaml_query_piped_arguments};

fn arguments(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| (*word).to_owned()).collect()
}

fn context() -> super::super::PathContext<'static> {
    super::super::PathContext {
        home_dir: Some("/home/dev"),
        cwd: Some("/home/dev/project"),
        ..Default::default()
    }
}

#[test]
fn a_field_read_out_of_a_named_document_is_admitted() {
    for words in [
        vec![".version", "chart.yaml"],
        vec![".metadata.name", "deploy/service.yaml"],
        vec!["-r", ".version", "chart.yaml"],
        vec!["-P", "-o", "json", ".spec", "chart.yaml"],
        vec!["--output-format=json", ".spec", "chart.yaml"],
        vec!["-I", "4", ".spec", "chart.yaml"],
        vec!["-p", "json", ".name", "package.json"],
        vec!["eval", ".version", "chart.yaml"],
        vec!["eval-all", ".version", "chart.yaml", "values.yaml"],
        vec!["-n", ".a"],
        vec![".items | length", "list.yaml"],
    ] {
        let list = arguments(&words);
        assert!(
            safe_yaml_query_file_arguments(&list, context()),
            "{words:?}"
        );
    }
}

#[test]
fn a_piped_document_is_read_through_the_same_grammar() {
    for words in [
        vec![".version"],
        vec!["-r", ".metadata.name"],
        vec!["e", ".spec.replicas"],
        vec!["-p", "xml", "."],
    ] {
        let list = arguments(&words);
        assert!(
            safe_yaml_query_piped_arguments(&list, context()),
            "{words:?}"
        );
    }
}

#[test]
fn an_option_that_writes_a_file_is_no_longer_a_read() {
    for words in [
        vec!["-i", ".version = \"2\"", "chart.yaml"],
        vec!["--inplace", ".version = \"2\"", "chart.yaml"],
        vec!["-i", "-r", ".version", "chart.yaml"],
        vec!["-s", ".name", "chart.yaml"],
        vec!["--split-exp", ".name", "chart.yaml"],
        vec!["--split-exp-file", "names.txt", "chart.yaml"],
    ] {
        let list = arguments(&words);
        assert!(
            !safe_yaml_query_file_arguments(&list, context()),
            "{words:?}"
        );
    }
}

#[test]
fn an_expression_this_screen_never_reads_keeps_its_review() {
    for words in [
        vec!["--from-file", "program.yq", "chart.yaml"],
        vec!["--expression", ".version", "chart.yaml"],
        vec!["-f", "extract", ".version", "chart.yaml"],
        vec!["--front-matter", "process", ".version", "chart.yaml"],
    ] {
        let list = arguments(&words);
        assert!(
            !safe_yaml_query_file_arguments(&list, context()),
            "{words:?}"
        );
    }
}

#[test]
fn an_expression_that_reaches_outside_the_document_keeps_its_review() {
    for words in [
        vec!["load(\"/etc/passwd\")"],
        vec!["env(HOME)"],
        vec![".a = strenv(TOKEN)"],
        vec!["eval(.cmd)"],
        vec!["$__loaded"],
    ] {
        let list = arguments(&words);
        assert!(
            !safe_yaml_query_piped_arguments(&list, context()),
            "{words:?}"
        );
    }
}

#[test]
fn an_unknown_option_or_a_missing_expression_proves_nothing() {
    for words in [
        vec![],
        vec!["-o"],
        vec!["--lua-prefix", "x", ".a", "chart.yaml"],
        vec!["--csv-separator", ";", ".a", "chart.yaml"],
        vec!["-o", "pickle", ".a", "chart.yaml"],
        vec!["-I", "sixteen", ".a", "chart.yaml"],
        vec!["-Z", ".a", "chart.yaml"],
        vec![".a"],
    ] {
        let list = arguments(&words);
        assert!(
            !safe_yaml_query_file_arguments(&list, context()),
            "{words:?}"
        );
    }
}

#[test]
fn a_document_outside_the_session_keeps_its_review() {
    for words in [
        vec![".a", "/etc/shadow"],
        vec![".a", "../../../etc/passwd"],
        vec![".a", "~/.ssh/config"],
    ] {
        let list = arguments(&words);
        assert!(
            !safe_yaml_query_file_arguments(&list, context()),
            "{words:?}"
        );
    }
}

/// A real directory the proofs below can canonicalize, holding the document
/// each command reads.
fn session_root() -> std::path::PathBuf {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/yaml-query-reads")
        .join(format!("session-{}", std::process::id()));
    std::fs::create_dir_all(root.join("project")).unwrap();
    std::fs::write(root.join("project/compose.yaml"), "services: {}\n").unwrap();
    std::fs::canonicalize(root).unwrap()
}

fn covered(command: &str, home: Option<&str>, cwd: Option<&str>) -> Vec<usize> {
    let request = crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    };
    let model = crate::parse_command(&request).unwrap();
    super::super::segments_safe_alone(
        &model,
        super::super::PathContext {
            home_dir: home,
            cwd,
            ..Default::default()
        },
        None,
    )
}

/// A file operand is a name on this machine, and a wrapper with no home or
/// working directory cannot tell which file it reaches. Beside a step the
/// user allowed, the lexical proof behind `yq` must not stand in for a path
/// proof, exactly as it must not for `jq`.
#[test]
fn a_document_read_is_not_covered_without_a_verified_directory() {
    let root = session_root();
    let home = root.to_str().unwrap();
    let cwd = root.join("project");
    let cwd = cwd.to_str().unwrap();
    let command = "git push && yq '.services' compose.yaml";
    assert!(covered(command, Some(home), Some(cwd)).contains(&1));
    assert!(!covered(command, None, None).contains(&1));
}

/// A field whose name reads like a private file -- `.environment` inside a
/// service definition -- selects a key in the document, not a path. The
/// sensitive-text screen skips the expression, as it does a `jq` filter.
#[test]
fn a_field_named_like_a_private_file_is_still_a_read() {
    for words in [
        vec![".services.app.environment", "compose.yaml"],
        vec!["-r", ".spec.template.spec.containers[0].env", "deploy.yaml"],
    ] {
        let list = arguments(&words);
        assert!(
            safe_yaml_query_file_arguments(&list, context()),
            "{words:?}"
        );
        assert_eq!(super::expression_position(&list), Some(words.len() - 2));
    }
    let root = session_root();
    let home = root.to_str().unwrap();
    let cwd = root.join("project");
    let cwd = cwd.to_str().unwrap();
    assert!(covered(
        "yq '.services.app.environment' compose.yaml",
        Some(home),
        Some(cwd)
    )
    .contains(&0));
}

/// `yq` reads its first word as a file wherever one of that name is there:
/// an existing `*.yq` becomes the program it runs, and any other existing
/// file becomes the document it prints. Neither is the expression this
/// screen read, so both keep their review.
#[test]
fn a_first_word_naming_a_file_is_not_an_expression() {
    let root = session_root();
    let cwd = root.join("project");
    let context = super::super::PathContext {
        home_dir: root.to_str(),
        cwd: cwd.to_str(),
        ..Default::default()
    };
    std::fs::write(cwd.join(".env"), "TOKEN=x\n").unwrap();
    std::fs::write(cwd.join("report.yq"), ".a\n").unwrap();

    for words in [
        vec![".env", "compose.yaml"],
        vec!["-r", ".env", "compose.yaml"],
        vec!["report.yq", "compose.yaml"],
    ] {
        let list = arguments(&words);
        assert!(!safe_yaml_query_file_arguments(&list, context), "{words:?}");
    }
    for words in [vec![".env"], vec!["report.yq"], vec!["-n", "missing.yq"]] {
        let list = arguments(&words);
        assert!(
            !safe_yaml_query_piped_arguments(&list, context),
            "{words:?}"
        );
    }
    // A field of the same name that is not a file on this machine is still
    // the expression it reads as.
    let list = arguments(&[".environment", "compose.yaml"]);
    assert!(safe_yaml_query_file_arguments(&list, context));
}

/// `yq` decides at run time whether its first word is an expression or a file
/// it should open. With no working directory nothing here can say which names
/// exist, and the piped and `-n` forms name no file whose path proof would
/// catch it, so a relative first word keeps its review.
#[test]
fn a_relative_expression_keeps_its_review_without_a_working_directory() {
    let blind = super::super::PathContext::default();
    for words in [vec![".env"], vec![".version"], vec![".items | length"]] {
        let list = arguments(&words);
        assert!(!safe_yaml_query_piped_arguments(&list, blind), "{words:?}");
    }
    for words in [vec!["-n", ".env"], vec!["-n", ".a"]] {
        let list = arguments(&words);
        assert!(!safe_yaml_query_file_arguments(&list, blind), "{words:?}");
    }
}
