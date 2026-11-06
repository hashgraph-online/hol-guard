use super::super::safe_git_arguments;
use super::pathspec_start;
use crate::pretool::PathContext;

fn arguments(text: &str) -> Vec<String> {
    text.split_whitespace().map(str::to_owned).collect()
}

fn proven(text: &str) -> bool {
    safe_git_arguments(&arguments(text), true, PathContext::default())
}

#[test]
fn names_only_log_accepts_glob_pathspecs() {
    for text in [
        "log --oneline HEAD~1..HEAD --name-only --diff-filter=A -- src/* *migration*",
        "log -1 -- src/*",
        "log -n5 --name-status origin/main -- *migration*",
        "log --format=%h%x20%s --date=iso -- docs/*",
        "log --stat --no-merges -- src/**/*.sql",
        "log --pretty=oneline -- src/*",
        "log --pretty=tformat:%h -- src/*",
    ] {
        assert!(proven(text), "{text}");
    }
}

#[test]
fn pathspec_start_points_after_the_separator() {
    let listed = arguments("log --oneline -- src/* *migration*");
    assert_eq!(pathspec_start(&listed, PathContext::default()), Some(3));
    let unseparated = arguments("log --oneline src/*");
    assert_eq!(pathspec_start(&unseparated, PathContext::default()), None);
}

#[test]
fn content_options_keep_glob_pathspecs_reviewed() {
    for text in [
        "log -p -- src/*",
        "log --patch -1 -- *migration*",
        "log -U3 -- src/*",
        "log --word-diff -- src/*",
        "log -L1,5:src/app.ts -- src/*",
        "log --show-signature -- src/*",
        "log --format=%G? -- src/*",
        "log --pretty=format:%GS -- src/*",
        "log --pretty=audit -- src/*",
        "log --format=audit -- src/*",
        "log --output=out.txt -- src/*",
        "log --ext-diff -- src/*",
    ] {
        assert!(!proven(text), "{text}");
    }
}

#[test]
fn other_reads_keep_glob_pathspecs_reviewed() {
    for text in [
        "diff -- src/*",
        "show HEAD -- src/*",
        "status -- src/*",
        "ls-files -- src/*",
        "log src/*",
    ] {
        assert!(!proven(text), "{text}");
    }
}

#[test]
fn credential_and_escaping_pathspecs_stay_reviewed() {
    for text in [
        "log --oneline -- .env",
        "log --oneline -- *.key",
        "log --name-only -- secrets/*",
        "log --oneline -- .ssh/*",
        "log --oneline -- :(glob)src/*",
        "log --oneline -- ../other/*",
        "log --oneline -- /etc/*",
        "log --oneline -- ~/.aws/*",
        "log --oneline -- src/* .env",
    ] {
        assert!(!proven(text), "{text}");
    }
}

#[test]
fn literal_pathspecs_keep_their_existing_verdict() {
    assert!(proven("log --oneline -- src"));
    assert!(proven("log -1 -- src/app.ts"));
}
