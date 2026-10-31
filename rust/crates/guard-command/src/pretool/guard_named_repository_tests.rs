use super::guard_names::Moved;
use super::{github_api_path_after_repository, names_guard_outside_message};
use crate::github_command_capabilities::api_endpoint_index;

fn arguments(text: &str) -> Vec<String> {
    text.split_whitespace().map(str::to_owned).collect()
}

#[test]
fn the_repository_in_an_endpoint_is_set_apart_from_the_rest_of_the_path() {
    for (endpoint, rest) in [
        (
            "repos/example-org/hol-guard/actions/runs/123/approve",
            "/actions/runs/123/approve",
        ),
        (
            "/repos/example-org/hol-guard/actions/runs/123",
            "/actions/runs/123",
        ),
        ("repos/example-org/hol-guard", ""),
        ("repos/example-org/hol-guard?per_page=5", "?per_page=5"),
        (
            "repos/example-org/app/contents/.hol-guard/config",
            "/contents/.hol-guard/config",
        ),
    ] {
        assert_eq!(
            github_api_path_after_repository(endpoint),
            Some(rest),
            "{endpoint}"
        );
    }
}

#[test]
fn an_endpoint_without_a_plain_repository_gets_no_exemption() {
    for endpoint in [
        "repos/example-org/../.hol-guard/approve",
        "repos/../hol-guard/actions",
        "repos/example-org",
        "repos//hol-guard/actions",
        "repos/example-org/hol guard/actions",
        "orgs/hol-guard/repos",
        "graphql",
        "~/.hol-guard/config",
    ] {
        assert_eq!(
            github_api_path_after_repository(endpoint),
            None,
            "{endpoint}"
        );
    }
}

#[test]
fn the_endpoint_is_found_by_the_api_argument_parser() {
    for (text, index) in [
        (
            "--method POST repos/example-org/hol-guard/actions/runs/1/approve",
            Some(2),
        ),
        ("-X POST /repos/example-org/hol-guard/dispatches", Some(2)),
        ("repos/example-org/hol-guard/issues -f title=x", Some(0)),
        (
            "-H Accept:application/json -- repos/example-org/hol-guard",
            Some(3),
        ),
    ] {
        assert_eq!(api_endpoint_index(&arguments(text)), index, "{text}");
    }
}

fn segment(command: &str) -> crate::CommandSegmentV1 {
    crate::parse_command(&crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })
    .unwrap()
    .segments
    .remove(0)
}

#[test]
fn global_options_before_api_keep_the_repository_exemption() {
    for command in [
        "gh api --method POST repos/example-org/hol-guard/actions/runs/1/approve",
        "gh --hostname github.com api --method POST repos/example-org/hol-guard/actions/runs/1/approve",
        "gh --hostname=github.com api repos/example-org/hol-guard/dispatches",
        "gh -R example-org/app api repos/example-org/hol-guard/actions/runs/1",
        // A raw field is a string in the request body; a check or workflow
        // name that mentions the project reaches nothing on this host.
        "gh --hostname github.com api repos/example-org/app/actions/runs/1 -f name=hol-guard",
        "gh api repos/example-org/app/actions/runs/1 -fname=hol-guard",
        "gh api repos/example-org/app/actions/runs/1 -f=name=hol-guard",
    ] {
        assert!(!names_guard_outside_message(&segment(command), &Moved::default()), "{command}");
    }
    for command in [
        "gh --hostname github.com api repos/example-org/app/contents/.hol-guard/config",
        "gh --hostname github.com api repos/example-org/app/actions/runs/1 -f name=.hol-guard/config",
        "gh api repos/example-org/app/actions/runs/1 -fname=.hol-guard/config",
        "gh --hostname api repos/example-org/hol-guard/actions/runs/1",
    ] {
        assert!(names_guard_outside_message(&segment(command), &Moved::default()), "{command}");
    }
}
