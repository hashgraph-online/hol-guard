use super::classify;

#[test]
fn encoded_read_paths_and_queries_keep_read_capability() {
    for arguments in [
        vec!["repos/example/repo/contents/app/%28group%29/file.ts?ref=main"],
        vec![
            "-H",
            "Accept: application/vnd.github.raw",
            "repos/example/repo/contents/a%20b.ts",
        ],
        vec!["-X", "HEAD", "repos/example/repo/contents/%E2%9C%93.ts"],
        vec!["repos/example/repo/commits?path=app/%28group%29/file.ts&per_page=3"],
    ] {
        let arguments: Vec<String> = arguments.into_iter().map(String::from).collect();
        assert_eq!(classify(&arguments), Some(vec!["read_remote"]));
    }
}

#[test]
fn short_jq_and_template_aliases_match_their_long_forms() {
    let endpoint = "repos/example-org/service-api/git/ref/tags/v3.45.0";
    for (option, value) in [
        ("-q", ".object.sha"),
        ("--jq", ".object.sha"),
        ("-t", "{{.object.sha}}"),
        ("--template", "{{.object.sha}}"),
    ] {
        for arguments in [
            vec![endpoint.to_owned(), option.to_owned(), value.to_owned()],
            vec![endpoint.to_owned(), format!("{option}={value}")],
        ] {
            assert_eq!(
                classify(&arguments),
                Some(vec!["read_remote"]),
                "{arguments:?}"
            );
        }
    }
    for attached in [
        "-q.object.sha",
        "-q=.object.sha",
        "-q.a | select(.b == \"c\")",
    ] {
        let arguments = vec![endpoint.to_owned(), attached.to_owned()];
        assert_eq!(
            classify(&arguments),
            Some(vec!["read_remote"]),
            "{attached}"
        );
    }
    for format in [
        ".workflow_runs[] | [.id, .name] | @tsv",
        ".[] | @base64",
        ".[] | select(.email | endswith(\"@example.com\")) | .login",
        ".workflow_runs[] | (.conclusion // \"\") as $c | select($c != \"success\") | .id",
        // An `@` in a string's text is text, interpolated or not.
        ".[] | \"\\(.number) \\(.author.login)@\\(.head.repo)\"",
        ".[] | \"\\(.number)@\\(.ref | @base64) \\(\"a@b\")\"",
    ] {
        let arguments = vec![endpoint.to_owned(), "--jq".to_owned(), format.to_owned()];
        assert_eq!(classify(&arguments), Some(vec!["read_remote"]), "{format}");
    }
    for unsafe_filter in [
        vec!["-q", "env"],
        vec!["-qenv.HOME"],
        vec!["-q", "$x"],
        vec!["-q", "@text \"\\($ENV)\""],
        vec!["-q", "@sh \"`id`\""],
        vec!["-q", ".a\n| env"],
        vec!["-q", ". as $c | $c # \"\n| $ENV"],
        vec!["-q", ".[] | @sh"],
        vec!["-q", "@text \"id\""],
        vec!["--jq", "@json2"],
        vec!["-q", ".[] | \"\\(@sh \"x\")\""],
        vec!["-q", ".[] | \"\\(.a)@x \\(. | @sh)\""],
        vec!["-q", ".[] | \"\\(\"q\" | @text \"\\(.a)\")\""],
        // A comment's `)` or quote is text to jq, so it cannot hide a format.
        vec!["-q", ".[] | \"\\(.title # )\n | @sh)\""],
        vec!["-q", ".a # \"\n| @sh \"x\""],
    ] {
        let mut arguments = vec![endpoint.to_owned()];
        arguments.extend(unsafe_filter.iter().map(|value| (*value).to_owned()));
        assert_eq!(classify(&arguments), None, "{arguments:?}");
    }
    let write: Vec<String> = ["-X", "DELETE", endpoint, "-q", ".ref"]
        .into_iter()
        .map(String::from)
        .collect();
    assert_eq!(classify(&write), Some(vec!["delete_remote"]));
    // A bare format given as the whole filter passes the `gh` argument
    // screen, which otherwise refuses an argument opening with `@`.
    for (filter, read) in [("@tsv", true), ("@sh", false)] {
        let arguments: Vec<String> = ["api", endpoint, "--jq", filter]
            .into_iter()
            .map(String::from)
            .collect();
        let text = format!("gh api {endpoint} --jq {filter}");
        assert_eq!(
            super::super::classify(&arguments, &text).is_some(),
            read,
            "{filter}"
        );
    }
    // `gh pr list --jq` takes the same screen.
    for (filter, read) in [
        (".[] | \"\\(.number)@\\(.author.login)\"", true),
        (".[] | \"\\(.number)@\\(. | @sh)\"", false),
        (".[] | \"\\(. # )\n| @sh )\"", false),
    ] {
        let arguments: Vec<String> = ["pr", "list", "--json", "number,author", "--jq", filter]
            .into_iter()
            .map(String::from)
            .collect();
        let text = format!("gh pr list --json number,author --jq '{filter}'");
        assert_eq!(
            super::super::classify(&arguments, &text).is_some(),
            read,
            "{filter}"
        );
    }
    let field: Vec<String> = ["-fname=value", endpoint]
        .into_iter()
        .map(String::from)
        .collect();
    assert_eq!(classify(&field), Some(vec!["mutate_remote"]));
}

#[test]
fn malformed_encodings_and_encoded_mutations_stay_unproven() {
    for arguments in [
        vec!["repos/example/repo/contents/%2"],
        vec!["repos/example/repo/contents/%GG"],
        vec!["repos/example/repo/contents/%00"],
        vec!["graph%71l"],
        vec!["graph%71l?query=synthetic"],
        vec!["%2fgraphql"],
        vec![
            "-X",
            "DELETE",
            "repos/example/repo/contents/%28group%29/file.ts",
        ],
        vec![
            "repos/example/repo/contents/%28group%29/file.ts",
            "-f",
            "content=synthetic",
        ],
    ] {
        let arguments: Vec<String> = arguments.into_iter().map(String::from).collect();
        assert_eq!(classify(&arguments), None);
    }
}
