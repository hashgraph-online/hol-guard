use super::*;

/// A literal token value, built at run time so no credential-shaped string
/// sits in the source.
const SAMPLE: &str = concat!("Kq7xY2mN", "9pL4vR8tW3sZ");

fn npm_token_flagged(text: &str) -> bool {
    scan_text(text, true, true, MAX_SCAN_BYTES, None)
        .matches
        .iter()
        .any(|matched| matched.classifier == "npm-auth-token")
}

/// The publish workflow the Gauntlet fixture writes.
const PUBLISH_WORKFLOW: &str = "\
name: Publish
on:
  release:
    types: [published]
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          registry-url: https://registry.npmjs.org
      - run: npm ci
      - run: echo \"//registry.npmjs.org/:_authToken=${NPM_TOKEN}\" > ~/.npmrc
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
      - run: npm publish --access public
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
";

#[test]
fn an_npm_token_named_by_reference_is_not_a_leak() {
    for line in [
        "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n",
        "//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}\n",
        "          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}\n",
        "echo \"//registry.npmjs.org/:_authToken=${NPM_TOKEN}\" > ~/.npmrc\n",
        "npmToken: process.env.NPM_TOKEN,\n",
        "export NPM_TOKEN=$NPM_TOKEN\n",
    ] {
        assert!(!npm_token_flagged(line), "{line}");
    }
}

#[test]
fn an_npm_token_written_as_a_value_stays_flagged() {
    for line in [
        format!("//registry.npmjs.org/:_authToken={SAMPLE}\n"),
        format!("NPM_TOKEN={SAMPLE}\n"),
        format!("NPM_TOKEN: \"{SAMPLE}\"\n"),
        format!("NPM_TOKEN=test-{SAMPLE}\n"),
        format!("//registry.npmjs.org/:_authToken=${{NPM_TOKEN}}{SAMPLE}\n"),
        format!("NPM_TOKEN=${{NPM_TOKEN:-{SAMPLE}}}\n"),
        format!("npmToken: process.env.NPM_TOKEN || \"{SAMPLE}\",\n"),
    ] {
        assert!(npm_token_flagged(&line), "{line}");
    }
}

#[test]
fn a_publish_workflow_that_names_its_npm_secret_reads_clean() {
    let result = scan_text(PUBLISH_WORKFLOW, true, true, MAX_SCAN_BYTES, None);
    assert!(result.matches.is_empty(), "{:?}", result.matches);
}

fn credential_assignment(text: &str) -> bool {
    scan_text(text, true, true, MAX_SCAN_BYTES, None)
        .matches
        .iter()
        .any(|matched| matched.classifier == "credential-assignment")
}

#[test]
fn a_shell_parameter_inside_a_quoted_echo_is_a_reference() {
    for line in [
        "echo \"API_TOKEN=${API_TOKEN}\" > .env\n",
        "echo \"NPM_TOKEN=${NPM_TOKEN}\" >> \"$GITHUB_ENV\"\n",
        "echo \"API_TOKEN=$API_TOKEN\" >> .env\n",
    ] {
        assert!(!credential_assignment(line), "{line}");
    }
}

#[test]
fn text_joined_to_a_shell_parameter_stays_flagged() {
    for line in [
        format!("API_TOKEN=${{API_TOKEN}}{SAMPLE}\n"),
        format!("echo \"API_TOKEN=${{API_TOKEN}}{SAMPLE}\" > .env\n"),
        format!("API_TOKEN=${{API_TOKEN:-\"{SAMPLE}\"}}\n"),
        format!("API_TOKEN=${{API_TOKEN}}\"{SAMPLE}\"\n"),
    ] {
        assert!(credential_assignment(&line), "{line}");
    }
}
