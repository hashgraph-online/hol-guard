use super::*;

fn destinations(arguments: &[&str]) -> Option<BTreeSet<SocketAddrV4>> {
    bound_curl_read_destinations(
        &std::iter::once("/usr/bin/curl")
            .chain(arguments.iter().copied())
            .map(str::to_owned)
            .collect::<Vec<_>>(),
        PathContext::default(),
    )
}

#[test]
fn bound_curl_read_reuses_existing_url_and_option_proofs() {
    for disabled in ["-q", "--disable"] {
        let peers = destinations(&[
            disabled,
            "-fsS",
            "--max-time",
            "5",
            "http://127.0.0.1:3001/alpha/list",
        ])
        .unwrap();
        assert_eq!(peers, BTreeSet::from(["127.0.0.1:3001".parse().unwrap()]));
        assert_eq!(
            destinations(&[
                disabled,
                "--url=http://127.0.0.1:4173/a",
                "http://127.0.0.1:4173/b"
            ])
            .unwrap()
            .len(),
            1
        );
    }
}

#[test]
fn bound_curl_read_refuses_unbound_transport_and_file_effects() {
    for args in [
        vec!["http://127.0.0.1:3001/"],
        vec!["-s", "-q", "http://127.0.0.1:3001/"],
        vec!["-q", "-L", "http://127.0.0.1:3001/"],
        vec!["-q", "-X", "DELETE", "http://127.0.0.1:3001/"],
        vec!["-q", "-d", "@.env", "http://127.0.0.1:3001/"],
        vec!["-q", "--config", "settings", "http://127.0.0.1:3001/"],
        vec![
            "-q",
            "--resolve",
            "example.com:80:127.0.0.1",
            "http://example.com/",
        ],
        vec!["-q", "--url", "http://example.com/"],
        vec!["-q", "https://127.0.0.1:3001/"],
        vec!["-q", "--ssl-reqd", "http://127.0.0.1:3001/"],
        vec!["-q", "http://localhost:3001/"],
        vec!["-q", "http://2130706433:3001/"],
        vec!["-q", "http://127.0.0.1:03001/"],
        vec!["-q", "http://127.0.0.1:4781/v1/requests"],
        vec!["-q", "http://127.0.0.1:9222/json"],
        vec!["-q", "http://169.254.169.254/latest/meta-data/"],
        vec!["-q", "http://127.0.0.1:3001/?token=secret"],
        vec!["-q", "-o", "/dev/null", "http://127.0.0.1:3001/"],
        vec!["-q", "-D", "-", "http://127.0.0.1:3001/"],
        vec![
            "-q",
            "--header",
            "Accept: text/plain",
            "http://127.0.0.1:3001/",
        ],
    ] {
        assert!(destinations(&args).is_none(), "{args:?}");
    }
}
