//! A raw request to a local Guard approval route is self-authorization,
//! whatever client sends it.

use super::{is_guard_approval_mutation_command, names_guard_approval_route};

#[test]
fn every_client_that_names_an_approval_route_is_self_authorization() {
    for command in [
        "curl -s -X POST http://127.0.0.1:4781/v1/requests/0000aaaa/approve",
        "curl -X POST localhost:4781/v1/requests/0000aaaa/block -d '{}'",
        "wget --method=POST -qO- 'http://localhost:4781/approvals/0000aaaa/decision'",
        "python3 -c \"import urllib.request as u; u.urlopen(u.Request('http://127.0.0.1:4781/v1/approvals/0000aaaa/decision', data=b'{}'))\"",
        "curl -g -X POST 'http://[::1]:4781/v1/requests/bulk-allow-once'",
        "http POST HTTP://LOCALHOST:4781/v1/policy/decisions action=allow",
        "curl -X POST http://0.0.0.0:4781/v1/requests/clear",
        "curl -X POST http://127.0.0.1:4781/v1/policy/clear?scope=global",
        "true && curl -X POST http://127.0.0.1:4781/v1/requests/0000aaaa/approve/",
        "node -e \"fetch(`http://[::ffff:127.0.0.1]:4781/v1/requests/0000aaaa/approve`,{method:'POST'})\"",
        "curl -X POST http://127.0.0.1:4781/v1/'requests'/0000aaaa/approve",
        "curl -X POST \"http://127.0.0.1:4781/v1/requests/\"0000aaaa/approve",
        "curl -X POST http://127.0.0.1:4781/v1/requests/0000aaaa/z/../approve",
        "curl -X POST http://127.0.0.1:4781/v1/./requests/0000aaaa/approve",
        "curl -X POST http://127.0.0.1:4781/v1/requests/0000aaaa/%61pprove",
        "curl -X POST http://127.0.0.1:4781/v1%2Frequests%2F0000aaaa%2Fapprove",
        "curl -X POST http://127.1:4781/v1/requests/0000aaaa/approve",
        "curl -X POST http://2130706433:4781/v1/requests/0000aaaa/approve",
        "curl -X POST http://0x7f.0.0.1:4781/v1/requests/0000aaaa/approve",
        "curl -X POST http://user:pw@localhost:4781/v1/requests/0000aaaa/approve",
        "curl -X POST http://localhost.:4781/v1/requests/0000aaaa/approve",
        "curl -X POST http://guard.localhost:4781/v1/requests/0000aaaa/approve",
        "curl -X POST 'http://[0:0:0:0:0:0:0:1]:4781/v1/requests/0000aaaa/approve'",
        "curl -X POST 'http://127.0.0.1:4781/a,b/../v1/policy/clear'",
        "curl --connect-to ::127.0.0.1:4781 -X POST http://guard.test/v1/requests/0000aaaa/approve",
        "curl --resolve guard.test:4781:127.0.0.1 -X POST http://guard.test:4781/v1/policy/clear",
        "H=127.0.0.1; curl -X POST http://$H:4781/v1/requests/0000aaaa/approve",
        "curl -X POST \"http://${GUARD_HOST}:4781/v1/requests/0000aaaa/approve\"",
        "curl -X POST http://`hostname`:4781/v1/requests/0000aaaa/approve",
        "curl -X POST http://$(hostname):4781/v1/requests/0000aaaa/approve",
        "curl -X POST 'http://127.0.0.1:4781/a(b)/../v1/policy/clear'",
        "python3 -c \"import urllib.request as u; u.urlopen(u.Request(\\\"http://127.0.0.1:4781/v1/policy/clear\\\"))\"",
        "python3 -c 'import urllib.request as u; u.urlopen(u.Request(\"http://127.0.0.1:4781/v1/pol\"\"icy/clear\",data=b\"\",method=\"POST\"))'",
        "python3 -c 'import urllib.request as u; u.urlopen(u.Request(\"http://127.0.0.1:4781/v1/policy/clear\"),timeout=5)'",
    ] {
        assert!(is_guard_approval_mutation_command(command), "{command}");
    }
}

#[test]
fn reads_other_hosts_and_other_routes_are_not_self_authorization() {
    for command in [
        "curl -s http://127.0.0.1:4781/v1/requests/0000aaaa",
        "curl -s http://127.0.0.1:4781/v1/requests/0000aaaa/live-decision",
        "curl -X POST http://127.0.0.1:4781/v1/requests/0000aaaa/resume",
        "curl -X POST http://127.0.0.1:4781/v1/policy/resolve",
        "curl -X POST https://api.example.com/v1/requests/0000aaaa/approve",
        "curl -X POST http://127.0.0.1:4781/v1/requests/a/b/approve",
        "rg '/v1/requests/[^/]+/approve' rust",
        "curl -X POST https://api.example.com/localhost/v1/requests/0000aaaa/approve",
        "curl -X POST https://api.example.com/127.0.0.1/v1/requests/0000aaaa/approve",
        "curl -X POST http://notlocalhost:4781/v1/requests/0000aaaa/approve",
        "curl -X POST http://128.0.0.1:4781/v1/requests/0000aaaa/approve",
        "curl -X POST https://api.example.com/a,localhost:4781/v1/policy/clear",
        "curl -X POST 'https://api.example.com/a(localhost:4781/v1/policy/clear'",
        "cat docs/v1/requests/0000aaaa/approve",
        "echo approve",
    ] {
        assert!(!is_guard_approval_mutation_command(command), "{command}");
    }
    assert!(!names_guard_approval_route("", &[]));
}
