use super::project;
use crate::pretool::PathContext;

/// A setting whose value names a location inside the working directory is
/// still a value the command reads for itself. The separator alone said
/// nothing about what the command reaches, so a workspace output or data
/// directory is projected away like any other ordinary setting.
#[test]
fn a_workspace_path_setting_is_projected_away() {
    let context = PathContext {
        cwd: Some("/work/site"),
        ..PathContext::default()
    };
    for (command, expected) in [
        ("OUT_DIR=build/out ls -la .", "ls -la ."),
        ("DATA_DIR=./data ls", "ls"),
        ("ARTIFACT_DIR=target/report ls -la .", "ls -la ."),
        ("OUT_DIR=/work/site/build ls", "ls"),
        ("OUT_DIR=/work/site ls", "ls"),
    ] {
        assert_eq!(
            project(command, context).as_deref(),
            Some(expected),
            "{command}"
        );
    }
    // Without a working directory there is nothing to measure the value
    // against, so the prefix keeps the command unprojected.
    assert_eq!(
        project("OUT_DIR=/work/site/build ls", PathContext::default()),
        None
    );
}

/// A path value that leaves the working directory, or names a key store
/// wherever it sits, keeps the command unprojected.
#[test]
fn a_setting_path_outside_the_workspace_is_not_projected() {
    let context = PathContext {
        cwd: Some("/work/site"),
        ..PathContext::default()
    };
    for command in [
        "OUT_DIR=../sibling/out ls -la .",
        "OUT_DIR=build/../../sibling ls",
        "OUT_DIR=/etc/ssl/certs ls",
        "DATA_DIR=vendor/.ssh/id_rsa ls",
        "DATA_DIR=vendor/.env ls",
        // A sibling whose name merely starts with the working directory's is
        // not inside it.
        "OUT_DIR=/work/site-sibling/out ls",
    ] {
        assert_eq!(project(command, context), None, "{command}");
    }
}

/// A key store written without a leading separator names the same files as
/// one written with it. The screen reads the location the value resolves to,
/// so `.aws/credentials` is refused next to `/work/site/.aws/credentials`.
#[test]
fn a_relative_key_store_is_refused_like_an_absolute_one() {
    let context = PathContext {
        cwd: Some("/work/site"),
        ..PathContext::default()
    };
    for command in [
        "DATA_DIR=.aws/credentials ls",
        "DATA_DIR=.ssh/id_rsa ls",
        "DATA_DIR=.kube/config ls",
        "DATA_DIR=.docker/config.json ls",
        "DATA_DIR=.secrets/token ls",
        "DATA_DIR=.git-credentials/store ls",
        "DATA_DIR=./.aws/credentials ls",
        "env DATA_DIR=.aws/credentials ls",
    ] {
        assert_eq!(project(command, context), None, "{command}");
    }
}

/// A relative value names a location only once the directory it is read from
/// is known. The caller's working directory answers for the first simple
/// command alone, so a setting behind a separator keeps its command
/// unprojected while an absolute value, which names the same location
/// wherever it is read, still projects.
#[test]
fn a_relative_value_is_read_only_in_the_first_simple_command() {
    let context = PathContext {
        cwd: Some("/work/site"),
        ..PathContext::default()
    };
    for command in [
        "cd /etc && DATA_DIR=ssl/private ls",
        // A simple command this projection cannot read -- one that starts
        // with a redirection -- still moves the shell, so the command after
        // the separator is not the first one either.
        ">/dev/null cd /etc && DATA_DIR=ssl/private ls",
        "</dev/null cd .. && OUT_DIR=sibling/out ls",
        "2>/dev/null cd /etc && DATA_DIR=ssl/private ls",
        "ls && OUT_DIR=build/out ls",
        "ls; OUT_DIR=build/out ls",
        "ls | OUT_DIR=build/out cat",
        "cd .. && OUT_DIR=sibling/out ls",
        "cd /etc && env DATA_DIR=ssl/private ls",
    ] {
        assert_eq!(project(command, context), None, "{command}");
    }
    assert_eq!(
        project("ls && OUT_DIR=/work/site/build ls", context).as_deref(),
        Some("ls && ls"),
    );
    assert_eq!(
        project("OUT_DIR=build/out ls && ls", context).as_deref(),
        Some("ls && ls"),
    );
    // Only a relative path value turns on the working directory. A setting
    // behind a separator whose value names no location at all is read the
    // same wherever the shell stands.
    for (command, expected) in [
        ("ls && NODE_ENV=test ls", "ls && ls"),
        (
            "date -u +%Y-%m-%dT%H:%M:%SZ && TZ=America/Los_Angeles date +%H:%M",
            "date -u +%Y-%m-%dT%H:%M:%SZ && date +%H:%M",
        ),
    ] {
        assert_eq!(
            project(command, context).as_deref(),
            Some(expected),
            "{command}"
        );
    }
}

/// The marker screen reads a credential's spelling inside the text, so it
/// answers for `vendor/.ssh/id_rsa` but not for a value that stops at the
/// store itself or names a key by a spelling the markers do not carry. The
/// name screen reads the value's own last component and the directories
/// above it, so neither shape is projected away.
#[test]
fn a_credential_store_or_key_name_the_markers_miss_is_refused() {
    let context = PathContext {
        cwd: Some("/work/site"),
        ..PathContext::default()
    };
    for command in [
        "DATA_DIR=vendor/.ssh ls",
        "DATA_DIR=vendor/.gnupg ls",
        "DATA_DIR=vendor/.aws ls",
        "DATA_DIR=vendor/secrets ls",
        "DATA_DIR=vendor/id_ecdsa ls",
        "DATA_DIR=vendor/credentials.json ls",
        "DATA_DIR=/work/site/vendor/.ssh ls",
    ] {
        assert_eq!(project(command, context), None, "{command}");
    }
    // The screens read credential names, not every directory a command is
    // pointed at, so an ordinary workspace path is still projected away.
    for (command, expected) in [
        ("DATA_DIR=vendor/assets ls", "ls"),
        ("DATA_DIR=vendor/report.json ls", "ls"),
    ] {
        assert_eq!(
            project(command, context).as_deref(),
            Some(expected),
            "{command}"
        );
    }
}
