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
        "log --name-only -- .env*",
        "log --name-only -- **/id_rsa*",
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
fn ls_files_accepts_glob_pathspecs() {
    for text in [
        "ls-files **/deploy.sh",
        "ls-files scripts/deploy.sh **/deploy.sh",
        "ls-files -- src/*",
        "ls-files src/*/index.ts",
        "ls-files -z --others --exclude-standard -- src/**/*.sql",
        "ls-files --error-unmatch **/deploy.sh",
    ] {
        assert!(proven(text), "{text}");
    }
}

#[test]
fn ls_files_pathspec_start_skips_the_options() {
    let listed = arguments("ls-files -z **/deploy.sh");
    assert_eq!(pathspec_start(&listed, PathContext::default()), Some(2));
    let separated = arguments("ls-files -z -- **/deploy.sh");
    assert_eq!(pathspec_start(&separated, PathContext::default()), Some(3));
    let bare = arguments("ls-files -z");
    assert_eq!(pathspec_start(&bare, PathContext::default()), None);
}

#[test]
fn ls_files_keeps_credential_escaping_and_option_pathspecs_reviewed() {
    for text in [
        "ls-files -- .env*",
        "ls-files config/.env.*",
        "ls-files **/id_rsa?",
        "ls-files **/*.key",
        "ls-files secrets/*",
        "ls-files .ssh/*",
        "ls-files :(glob)**/deploy.sh",
        "ls-files ../other/*",
        "ls-files /etc/*",
        "ls-files src/* .env",
        "ls-files src/* --exclude-from=list.txt",
        "ls-files src/* -- **/deploy.sh",
        // Options that open a file: the value is not a pathspec.
        "ls-files -X list.txt **/deploy.sh",
        "ls-files --exclude-from=list.txt **/deploy.sh",
        "ls-files --exclude-from list.txt **/deploy.sh",
        "ls-files --exclude-per-directory=.ignore src/*/index.ts",
        "ls-files -X list.txt -- **/deploy.sh",
    ] {
        assert!(!proven(text), "{text}");
    }
}

#[test]
fn literal_pathspecs_keep_their_existing_verdict() {
    assert!(proven("log --oneline -- src"));
    assert!(proven("log -1 -- src/app.ts"));
}
