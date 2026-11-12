use super::reads_a_named_url;

fn arguments(text: &str) -> Vec<String> {
    text.split_whitespace().map(str::to_owned).collect()
}

fn reads(text: &str) -> bool {
    reads_a_named_url(
        &arguments(text),
        super::super::PathContext {
            home_dir: Some("/home/dev"),
            cwd: Some("/home/dev/project"),
            ..Default::default()
        },
    )
}

/// A readiness check names where the response goes, in any of the spellings
/// that keep it out of the working directory.
#[test]
fn a_loopback_read_that_names_its_output_is_proven() {
    for text in [
        "-qO- http://127.0.0.1:8080/health",
        "-q -O - http://127.0.0.1:8080/health",
        "--quiet --output-document=- http://localhost:3000/api/health",
        "-nv -O /dev/null http://127.0.0.1:8080/",
        "--spider http://127.0.0.1:8080/health",
        "-qS --timeout=2 --tries=1 -O- http://127.0.0.1:8080/health",
        "-t 3 -T 2 -O- localhost:3000/health",
        "-O- -U probe http://127.0.0.1:8080/health",
        "--compression=auto -qO- http://127.0.0.1:8080/health",
    ] {
        assert!(reads(text), "{text}");
    }
}

/// Saying nothing about the output means `wget` writes a file the command
/// never named, so the bare form keeps its review whatever else it carries.
#[test]
fn a_run_that_writes_a_file_it_never_named_keeps_its_review() {
    for text in [
        "http://127.0.0.1:8080/health",
        "-q http://127.0.0.1:8080/health",
        "-O health.json http://127.0.0.1:8080/health",
        "-O ../health.json http://127.0.0.1:8080/health",
        "-O- -o wget.log http://127.0.0.1:8080/health",
        "-r -O- http://127.0.0.1:8080/",
        "-P /tmp -O- http://127.0.0.1:8080/",
        "-i urls.txt -O-",
        "-e robots=off -O- http://127.0.0.1:8080/",
        "--post-data=a=1 -O- http://127.0.0.1:8080/",
        "--load-cookies cookies.txt -O- http://127.0.0.1:8080/",
        "--no-check-certificate -O- http://127.0.0.1:8080/",
        "-c -O- http://127.0.0.1:8080/",
        "-O-",
    ] {
        assert!(!reads(text), "{text}");
    }
}

/// A public host answers for itself where it sends the request next, so the
/// read is proven only while the request stays with the host that was named.
#[test]
fn a_public_read_is_proven_only_with_its_redirects_held() {
    assert!(reads(
        "--max-redirect=0 -qO- https://example.com/release.json"
    ));
    assert!(reads("--max-redirect 0 -qO- example.com/release.json"));
    for text in [
        "-qO- https://example.com/release.json",
        "--max-redirect=5 -qO- https://example.com/release.json",
        "--max-redirect=0 -qO- http://169.254.169.254/latest/meta-data/",
        "--max-redirect=0 -qO- http://10.0.0.5/",
        "--max-redirect=0 -qO- https://example.com/x?token=abcdefghijklmnopqrst",
    ] {
        assert!(!reads(text), "{text}");
    }
}

/// wget reads its options in order and the last `--max-redirect` decides, so
/// an earlier zero proves nothing about the request that is actually sent.
#[test]
fn the_last_redirect_bound_is_the_one_the_request_carries() {
    assert!(reads(
        "--max-redirect=20 --max-redirect=0 -qO- https://example.com/release.json"
    ));
    for text in [
        "--max-redirect=0 --max-redirect=20 -qO- https://example.com/release.json",
        "--max-redirect 0 --max-redirect 1 -qO- https://example.com/release.json",
    ] {
        assert!(!reads(text), "{text}");
    }
}

/// A loopback port a local admin service answers on is not a dev server, and
/// a word the shell would still expand proves nothing about what is fetched.
#[test]
fn an_admin_port_or_an_unexpanded_word_keeps_its_review() {
    for text in [
        "-qO- http://127.0.0.1:9229/json",
        "-qO- http://127.0.0.1:2375/version",
        "-qO- $URL",
        "-qO- http://127.0.0.1:8080/$PATH",
    ] {
        assert!(!reads(text), "{text}");
    }
}
