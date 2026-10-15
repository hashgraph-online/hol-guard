use super::*;

fn words(command: &str) -> Vec<String> {
    command.split_whitespace().map(str::to_owned).collect()
}

#[test]
fn comment_write_accepts_one_body_for_one_issue_or_pull_request() {
    for command in [
        "pr comment 12 --body text",
        "pr comment --body text",
        "issue comment 7 -b text",
        "pr comment 12 --body=text",
        "pr comment 12 -F .tmp/body.md",
        "pr comment 12 --body-file=.tmp/body.md",
        "-R example-org/app-portal pr comment 12 --body text",
        "pr comment 12 --body text --repo example-org/app-portal",
    ] {
        assert!(comment_write(&words(command)).is_some(), "{command}");
    }
    for command in [
        "pr comment 12",
        "pr comment 12 --body a --body b",
        "pr comment 12 --body a --body-file b",
        "pr comment 12 --edit-last --body text",
        "pr comment 12 --delete-last",
        "pr comment 12 --web",
        "pr comment 12 --editor",
        "pr comment 12 --create-if-none --body text",
        "pr comment https://github.com/other/repo/pull/12 --body text",
        "pr comment feature-branch --body text",
        "pr comment 0 --body text",
        "pr comment 12 13 --body text",
        "--body text pr comment 12",
        "pr --body text comment 12",
        "pr review 12 --approve --body text",
        "pr merge 12 --body text",
        "pr close 12 --comment text",
        "issue close 7 --comment text",
        "pr comment 12 --body text -R a/b -R a/b",
        "pr comment 12 --body",
    ] {
        assert!(comment_write(&words(command)).is_none(), "{command}");
    }
}

#[test]
fn api_write_accepts_only_comment_and_reply_posts() {
    for command in [
        "repos/example-org/app-portal/pulls/12/comments/345/replies -f body=text",
        "/repos/example-org/app-portal/issues/12/comments -f body=text",
        "-X POST repos/example-org/app-portal/issues/12/comments --raw-field body=text",
        "--method=post repos/example-org/app-portal/issues/12/comments -F body=text",
        "repos/example-org/app-portal/issues/12/comments -fbody=text --jq .id --silent",
        "-XPOST repos/example-org/app-portal/issues/12/comments --field=body=text",
    ] {
        let args = words(command);
        let parsed = api_write(&args);
        assert_eq!(
            parsed.map(|(owner, repository, _)| (owner, repository)),
            Some(("example-org", "app-portal")),
            "{command}"
        );
    }
    for command in [
        "repos/example-org/app-portal/issues/12/comments",
        "-X PATCH repos/example-org/app-portal/issues/comments/9 -f body=text",
        "-X DELETE repos/example-org/app-portal/pulls/comments/9",
        "-X PUT repos/example-org/app-portal/pulls/12/merge -f body=text",
        "repos/example-org/app-portal/pulls/12/reviews -f body=text -f event=APPROVE",
        "repos/example-org/app-portal/issues/12/comments -f body=a -f body=b",
        "repos/example-org/app-portal/issues/12/comments -f body=a -f title=b",
        "repos/example-org/app-portal/issues/12/comments -F body=@notes.md",
        "repos/example-org/app-portal/issues/12/comments -F=body=@notes.md",
        "repos/example-org/app-portal/issues/12/comments --input notes.json",
        "repos/example-org/app-portal/issues/12/comments -f body=text --hostname example.com",
        "repos/example-org/app-portal/issues/12/comments -f body=text -H Accept:raw",
        "repos/example-org/app-portal/issues/12/comments repos/a/b/issues/1/comments -f body=x",
        "repos/example-org/app-portal/git/refs -f body=text",
        "repos/example-org/app-portal/issues/12 -f body=text",
        "repos/example-org/app-portal/pulls/12/comments -f body=text",
        "repos/example-org/../issues/12/comments -f body=text",
        "graphql -f body=text",
    ] {
        assert!(api_write(&words(command)).is_none(), "{command}");
    }
}

#[test]
fn selectors_and_origin_urls_name_one_github_repository() {
    assert_eq!(
        repository_selector("example-org/app-portal"),
        Some(("example-org", "app-portal"))
    );
    assert_eq!(
        repository_selector("GitHub.com/example-org/app-portal"),
        Some(("example-org", "app-portal"))
    );
    for selector in [
        "app-portal",
        "example.com/example-org/app-portal",
        "example-org/app-portal/extra",
        "example-org/..",
        "https://github.com/example-org/app-portal",
    ] {
        assert_eq!(repository_selector(selector), None, "{selector}");
    }
    let expected = Some(("example-org".to_owned(), "app-portal".to_owned()));
    for url in [
        "https://github.com/example-org/app-portal.git",
        "https://github.com/Example-Org/App-Portal",
        "git@github.com:example-org/app-portal.git",
        "ssh://git@github.com/example-org/app-portal/",
    ] {
        assert_eq!(github_repository(url), expected, "{url}");
    }
    for url in [
        "https://example.com/example-org/app-portal.git",
        "https://github.com.example.com/example-org/app-portal",
        "https://github.com/example-org/app-portal/extra",
        "/srv/mirror/app-portal.git",
    ] {
        assert_eq!(github_repository(url), None, "{url}");
    }
}
#[test]
fn listed_remotes_name_origin_and_flag_every_other_remote() {
    let origin = Some(("example-org".to_owned(), "app-portal".to_owned()));
    let https = "https://github.com/example-org/app-portal.git";
    let ssh = "git@github.com:Example-Org/app-portal.git";
    assert_eq!(remotes::listed(""), Some((None, false)));
    assert_eq!(
        remotes::listed(&format!("origin\t{https} (fetch)\norigin\t{ssh} (push)\n")),
        Some((origin.clone(), false))
    );
    assert_eq!(
        remotes::listed(&format!(
            "origin\t{https} (fetch)\nupstream\thttps://gitlab.com/a/b (fetch)\n"
        )),
        Some((origin, true))
    );
    for listing in [
        format!(
            "origin\t{https} (fetch)\norigin\thttps://github.com/other-org/app-portal (push)\n"
        ),
        "origin\thttps://gitlab.com/example-org/app-portal.git (fetch)\n".to_owned(),
        format!("origin\t{https} (fetch) [blob:none]\n"),
        format!("origin {https} (fetch)\n"),
    ] {
        assert_eq!(remotes::listed(&listing), None, "{listing}");
    }
}
