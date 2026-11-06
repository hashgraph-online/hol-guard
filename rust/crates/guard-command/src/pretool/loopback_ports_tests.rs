use super::{chosen_server_port, dev_server_port};

const ADMIN: [u16; 2] = [2375, 8001];

struct Home(std::path::PathBuf);

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn home(name: &str, state: Option<&str>) -> Home {
    let root = std::env::temp_dir().join(format!("loopback-ports-{name}-{}", std::process::id()));
    let guard = root.join(".hol-guard");
    std::fs::create_dir_all(&guard).unwrap();
    if let Some(state) = state {
        std::fs::write(guard.join("daemon-state.json"), state).unwrap();
    }
    Home(root)
}

#[test]
fn conventional_dev_ports_are_reachable() {
    let home = home("dev", None);
    for port in [
        80, 443, 3000, 3010, 4173, 4200, 6006, 8000, 8080, 8443, 8765, 8787,
    ] {
        assert!(dev_server_port(port, &ADMIN, home.0.to_str()), "{port}");
    }
}

#[test]
fn other_ports_admin_ports_and_the_daemon_range_are_not() {
    let home = home("other", None);
    for port in [
        22, 2375, 4001, 7392, 8001, 8086, 9000, 9200, 10249, 54321, 4781, 5173, 5780,
    ] {
        assert!(!dev_server_port(port, &ADMIN, home.0.to_str()), "{port}");
    }
}

#[test]
fn the_daemon_state_decides_a_dev_port_inside_its_range() {
    let elsewhere = home("elsewhere", Some(r#"{"port": 4781, "pid": 1}"#));
    assert!(dev_server_port(5173, &ADMIN, elsewhere.0.to_str()));
    assert!(dev_server_port(5000, &ADMIN, elsewhere.0.to_str()));
    assert!(dev_server_port(5500, &ADMIN, elsewhere.0.to_str()));
    let here = home("here", Some(r#"{"port": 5173}"#));
    assert!(!dev_server_port(5173, &ADMIN, here.0.to_str()));
    let ephemeral = home("ephemeral", Some(r#"{"port": 3000}"#));
    assert!(!dev_server_port(3000, &ADMIN, ephemeral.0.to_str()));
    assert!(dev_server_port(5174, &ADMIN, ephemeral.0.to_str()));
}

#[test]
fn an_unreadable_state_falls_back_to_the_whole_range() {
    for (name, state) in [("garbage", "not json"), ("portless", r#"{"pid": 1}"#)] {
        let home = home(name, Some(state));
        assert!(!dev_server_port(5173, &ADMIN, home.0.to_str()), "{name}");
        assert!(dev_server_port(4173, &ADMIN, home.0.to_str()), "{name}");
    }
}

#[test]
fn a_chosen_port_opens_only_while_the_daemon_records_another() {
    let recorded = home("chosen", Some(r#"{"port": 4781}"#));
    for port in [1024, 3147, 4782, 7392, 32767] {
        assert!(
            chosen_server_port(port, &ADMIN, recorded.0.to_str()),
            "{port}"
        );
    }
    // Privileged and ephemeral ports, listed services and the daemon's own.
    for port in [80, 1023, 2375, 8001, 4781, 32768, 49152, 54321] {
        assert!(
            !chosen_server_port(port, &ADMIN, recorded.0.to_str()),
            "{port}"
        );
    }
    // With no readable record the daemon may hold any fixed port.
    for (name, state) in [("chosen-none", None), ("chosen-garbage", Some("not json"))] {
        let home = home(name, state);
        assert!(!chosen_server_port(3147, &ADMIN, home.0.to_str()), "{name}");
    }
    assert!(!chosen_server_port(3147, &ADMIN, None));
}
