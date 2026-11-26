use super::*;

#[test]
fn public_hosts_and_origins_are_shareable() {
    for host in [
        "shop.example.com",
        "Shop.Example.COM",
        "a.b.example.org",
        "example.co.uk",
        "xn--bcher-kva.example.com",
        "shop.example.com.",
        "123.example.com",
        "test.example.com",
        "local.example.com",
    ] {
        assert!(provider_host_is_shareable(host), "{host}");
    }
    for origin in [
        "https://shop.example.com",
        "https://shop.example.com/",
        "HTTPS://shop.example.com:8443",
        "http://shop.example.com:80",
    ] {
        assert!(provider_origin_is_shareable(origin), "{origin}");
    }
}

#[test]
fn loopback_private_and_link_local_addresses_never_leave() {
    for host in [
        "127.0.0.1",
        "10.0.0.8",
        "172.16.4.2",
        "192.168.1.20",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "8.8.8.8",
        "::1",
        "fe80::1",
        "fd00::1",
        "2001:db8::1",
        "[::1]",
    ] {
        assert!(!provider_host_is_shareable(host), "{host}");
    }
    for origin in [
        "http://127.0.0.1:3000",
        "http://[::1]:8080",
        "http://[fe80::1]",
        "https://10.1.2.3",
    ] {
        assert!(!provider_origin_is_shareable(origin), "{origin}");
    }
}

#[test]
fn every_ipv4_spelling_is_an_ip_literal() {
    for host in [
        "127.1",
        "127.0.1",
        "0x7f.0.0.1",
        "0x7F000001",
        "0177.0.0.1",
        "2130706433",
        "1.2.3.4.",
        "a.0x10",
        "example.123",
    ] {
        assert!(!provider_host_is_shareable(host), "{host}");
    }
}

#[test]
fn single_label_and_reserved_suffixes_never_leave() {
    for host in [
        "localhost",
        "intranet",
        "build-server",
        "app.localhost",
        "printer.local",
        "db.internal",
        "shop.example.test",
        "test",
        "router.lan",
        "nas.home.arpa",
        "wiki.corp",
        "files.private",
        "www.example",
        "x.invalid",
        "hidden.onion",
        "1.0.0.127.in-addr.arpa",
        "dev.localdomain",
        "PRINTER.LOCAL",
        "printer.local.",
    ] {
        assert!(!provider_host_is_shareable(host), "{host}");
    }
}

#[test]
fn anything_that_is_not_a_bare_origin_is_refused() {
    for origin in [
        "",
        "shop.example.com",
        "ftp://shop.example.com",
        "file:///etc/hosts",
        "ws://shop.example.com",
        "https://",
        "https://shop.example.com/path",
        "https://shop.example.com?q=1",
        "https://shop.example.com#top",
        "https://user@shop.example.com",
        "https://user:pass@shop.example.com",
        "https://shop.example.com:",
        "https://shop.example.com:0",
        "https://shop.example.com:65536",
        "https://shop.example.com:443443",
        "https://shop.example.com:http",
        "https://shop.example.com\\@evil.example.com",
        "https://shop_example.com",
        "https://-shop.example.com",
        "https://shop..example.com",
        "https://bücher.example.com",
        "https://shop.example.com:443:443",
    ] {
        assert!(!provider_origin_is_shareable(origin), "{origin:?}");
    }
    let long_label = format!("{}.example.com", "a".repeat(64));
    assert!(!provider_host_is_shareable(&long_label));
    let long_host = format!("{}.com", ["abc"; 70].join("."));
    assert!(!provider_host_is_shareable(&long_host));
}
