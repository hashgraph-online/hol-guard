use super::super::peel;
use super::{log_redirect, log_target};
use std::path::{Path, PathBuf};

fn workspace(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("guard-sinklog-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    root.canonicalize().unwrap()
}

/// A scratch log name in the system temporary directory, unique to this
/// test run, with nothing at it yet.
fn scratch(name: &str) -> (String, PathBuf) {
    let spelled = format!("/tmp/guard-sinklog-{}-{name}.log", std::process::id());
    let _ = std::fs::remove_file(&spelled);
    let resolved = std::fs::canonicalize("/tmp")
        .unwrap()
        .join(Path::new(&spelled).file_name().unwrap());
    (spelled, resolved)
}

fn chars(text: &str) -> Vec<char> {
    text.chars().collect()
}

#[cfg(unix)]
#[test]
fn a_typecheck_saved_to_a_scratch_log_is_peeled_with_its_report() {
    let root = workspace("typecheck");
    let (log, resolved) = scratch("typecheck");
    let command = format!(
        "node ./node_modules/typescript/bin/tsc --noEmit --pretty false > {log} 2>&1 && echo TYPES_CLEAN || echo TYPES_FAILED"
    );
    let core = peel(&command, root.to_str().unwrap(), None, None, false)
        .unwrap()
        .expect("the scratch log is peeled");
    assert_eq!(
        core.core,
        "node ./node_modules/typescript/bin/tsc --noEmit --pretty false"
    );
    assert_eq!(core.directory, root);
    let output = core.output.expect("the sink shapes the output");
    assert_eq!(output.kind, "all");
    assert!(output.merge_stderr);
    assert_eq!(output.file, Some(resolved));
    assert_eq!(output.success_label.as_deref(), Some("TYPES_CLEAN"));
    assert_eq!(output.failure_label.as_deref(), Some("TYPES_FAILED"));
}

#[cfg(unix)]
#[test]
fn standard_output_alone_and_the_combined_form_are_both_read() {
    let (log, resolved) = scratch("forms");
    for (command, merge) in [
        (format!("cargo check > {log}"), false),
        (format!("cargo check >{log} 2>&1"), true),
        (format!("cargo check &> {log}"), true),
        (format!("cargo check > {log}  2>&1  "), true),
    ] {
        let (start, file, merged) = log_redirect(&chars(&command)).expect(&command);
        assert_eq!(&command[..start], "cargo check", "{command}");
        assert_eq!(file, resolved, "{command}");
        assert_eq!(merged, merge, "{command}");
    }
}

#[cfg(unix)]
#[test]
fn other_redirect_spellings_are_never_read_as_a_scratch_log() {
    let (log, _) = scratch("spellings");
    for command in [
        // A digit touching `>` names a descriptor the sink does not model.
        format!("cargo check 1> {log}"),
        format!("cargo check 2> {log}"),
        // Appending keeps what the file held.
        format!("cargo check >> {log}"),
        format!("cargo check >| {log}"),
        // The redirect is only text inside a quote.
        format!("echo '> {log}'"),
        format!("echo \\> {log}"),
        // Nothing runs before it.
        format!("> {log}"),
    ] {
        assert_eq!(log_redirect(&chars(&command)), None, "{command}");
    }
}

#[cfg(unix)]
#[test]
fn only_a_plain_log_name_directly_in_the_temporary_directory_is_a_target() {
    let (log, resolved) = scratch("target");
    assert_eq!(log_target(&log), Some(resolved));
    let pid = std::process::id();
    for spelled in [
        format!("guard-sinklog-{pid}.log"),
        format!("/tmp/.guard-sinklog-{pid}.log"),
        format!("/tmp/guard-sinklog-{pid}.sh"),
        format!("/tmp/guard-sinklog-{pid}"),
        "/tmp/.log".to_owned(),
        format!("/tmp/missing-{pid}/x.log"),
        format!("{}/x.log", workspace("nested").display()),
        format!("/tmp/{}.log", "a".repeat(200)),
    ] {
        assert_eq!(log_target(&spelled), None, "{spelled}");
    }
}

#[cfg(unix)]
#[test]
fn a_link_already_at_the_log_name_is_never_written_through() {
    let (log, _) = scratch("link");
    let elsewhere = workspace("link-target").join("kept.log");
    std::fs::write(&elsewhere, "kept").unwrap();
    std::os::unix::fs::symlink(&elsewhere, &log).unwrap();
    assert_eq!(log_target(&log), None);
    std::fs::remove_file(&log).unwrap();

    std::fs::hard_link(&elsewhere, &log).unwrap();
    assert_eq!(log_target(&log), None);
    std::fs::remove_file(&log).unwrap();

    std::fs::write(&log, "old run").unwrap();
    assert!(log_target(&log).is_some());
    std::fs::remove_file(&log).unwrap();
}

#[cfg(unix)]
#[test]
fn a_scratch_log_after_a_list_or_a_pipe_is_refused() {
    let root = workspace("refused");
    let (log, _) = scratch("refused");
    for command in [
        // The shell writes only the last command's output to the file.
        format!("npm run lint && npm test > {log} 2>&1"),
        format!("npm test | tee notes > {log}"),
        format!("npm test < input.txt > {log}"),
        // Standard error goes to the terminal here, not to the file.
        format!("npm test 2>&1 > {log}"),
    ] {
        assert!(
            peel(&command, root.to_str().unwrap(), None, None, false).is_err(),
            "{command}"
        );
    }
}

#[cfg(unix)]
#[test]
fn a_write_into_the_workspace_is_left_to_the_redirect_review() {
    let root = workspace("inside");
    let command = format!("npm test > {}/out.log 2>&1", root.display());
    assert_eq!(log_redirect(&chars(&command)), None);
}
