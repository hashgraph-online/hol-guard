use super::*;

fn input(command: &str) -> Input {
    Input {
        profile_version: WORKSPACE_CONTAINED_PROFILE.into(),
        workspace: PathBuf::from("/w/proj"),
        cwd: PathBuf::from("/w/proj"),
        private_root: PathBuf::from("/private/tmp/guard-private"),
        command: vec!["/bin/sh".into(), "-c".into(), command.into()],
        ..Input::default()
    }
}

fn network_lines(command: &str) -> Vec<String> {
    workspace_profile::compose(&input(command), &[], &[])
        .unwrap()
        .lines()
        .filter(|line| line.contains("network"))
        .map(str::to_owned)
        .collect()
}

#[test]
fn each_loopback_port_may_be_bound_accepted_and_reached() {
    assert_eq!(
        workspace_profile::loopback_rules(&[4173]),
        [
            "(allow network-bind (local ip \"localhost:4173\"))",
            "(allow network-inbound (local ip \"localhost:4173\"))",
            "(allow network-outbound (remote ip \"localhost:4173\"))",
        ]
    );
    assert!(workspace_profile::loopback_rules(&[]).is_empty());
}

#[test]
fn the_profile_grants_the_ports_the_command_serves_on() {
    let server = "node --test && node -e \"const http=require('node:http');http.createServer((q,r)=>r.end('ok')).listen(4173,'127.0.0.1')\"";
    assert_eq!(
        network_lines(server),
        workspace_profile::loopback_rules(&[4173])
    );
    let check = "node --input-type=module -e 'const response = await fetch(\"http://127.0.0.1:3000/\"); console.log(response.status)'";
    assert_eq!(
        network_lines(check),
        workspace_profile::loopback_rules(&[3000])
    );
    let profile = workspace_profile::compose(&input(server), &[], &[]).unwrap();
    let lines: Vec<&str> = profile.lines().collect();
    // The credential denials still close the profile.
    assert!(lines
        .last()
        .unwrap()
        .starts_with("(deny file-read* file-write* (regex"));
}

#[test]
fn other_network_use_grants_nothing() {
    for command in [
        "node --test",
        "node -e \"fetch('https://example.com/')\"",
        "node -e \"fetch('http://127.0.0.1:2375/containers/json')\"",
        "node -e \"require('node:http').createServer().listen(0,'127.0.0.1')\"",
        "node -e \"fetch('http://127.0.0.1:3000/')\" && node -e \"fetch('https://example.com/')\"",
        "node -e \"fetch('http://127.0.0.1:3000/')\" && python3 -c 'import socket'",
    ] {
        assert!(network_lines(command).is_empty(), "{command}");
    }
}
