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

#[test]
fn a_workspace_script_earns_its_ports_again_at_launch() {
    let project = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/profile-loopback-tests")
        .join(format!("script-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&project);
    std::fs::create_dir_all(&project).unwrap();
    for (name, text) in [
        ("server.js", "const PORT = 3000;\nrequire('node:http').createServer((q, r) => r.end('ok')).listen(PORT, '127.0.0.1');\n"),
        ("open.js", "require('node:http').createServer().listen(process.env.PORT || 4173);\n"),
        ("lan.js", "require('node:http').createServer().listen(3000, '192.168.1.5');\n"),
        ("remote.js", "require('node:http').createServer().listen(3000, '127.0.0.1');\nfetch('https://example.com/');\n"),
    ] {
        std::fs::write(project.join(name), text).unwrap();
    }
    let project = project.canonicalize().unwrap();
    let lines = |command: &str| {
        let launch = Input {
            workspace: project.clone(),
            cwd: project.clone(),
            ..input(command)
        };
        workspace_profile::compose(&launch, &[], &[])
            .unwrap()
            .lines()
            .filter(|line| line.contains("network"))
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        lines("node server.js"),
        workspace_profile::loopback_rules(&[3000])
    );
    assert_eq!(
        lines("node open.js"),
        workspace_profile::loopback_rules(&[4173])
    );
    for command in ["node lan.js", "node remote.js", "cd .. && node server.js"] {
        assert!(lines(command).is_empty(), "{command}");
    }
    // The ports are read from the file as it is at launch, not as it was reviewed.
    std::fs::write(
        project.join("server.js"),
        "require('node:http').createServer().listen(3000, '192.168.1.5');\n",
    )
    .unwrap();
    assert!(lines("node server.js").is_empty());
}
