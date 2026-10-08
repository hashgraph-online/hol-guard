use super::is_orphaned_foreign_resident;
use crate::resident_state::{process_start_marker, runtime_digest, ResidentState};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

fn test_root(label: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!(
        "hol-guard-handoff-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    root
}

fn state(runtime_sha256: &str, owner_process_id: u32, owner_start_marker: &str) -> ResidentState {
    ResidentState {
        schema: "hol-guard-resident-state.v3".to_owned(),
        generation: 1,
        process_id: u32::MAX,
        process_start_marker: "resident".to_owned(),
        owner_process_id,
        owner_process_start_marker: owner_start_marker.to_owned(),
        runtime_sha256: runtime_sha256.to_owned(),
        transport: "loopback".to_owned(),
        endpoint: "127.0.0.1:9".to_owned(),
        unix_endpoint_identity: None,
        token_hex: String::new(),
        created_ms: 1,
        state_mac: String::new(),
    }
}

#[test]
fn only_an_ownerless_foreign_resident_without_its_own_clients_is_orphaned() {
    let root = test_root("orphaned");
    let digest = runtime_digest().unwrap();
    let foreign_digest = "f".repeat(64);
    let pid = std::process::id();
    let marker = process_start_marker(pid).unwrap();
    // Newer clients' leases do not make an older resident in use.
    let current_lease = super::lease::acquire(&root).unwrap();

    assert!(is_orphaned_foreign_resident(
        &root,
        &state(&foreign_digest, u32::MAX, "dead"),
        &digest
    ));
    assert!(!is_orphaned_foreign_resident(
        &root,
        &state(&digest, u32::MAX, "dead"),
        &digest
    ));
    assert!(!is_orphaned_foreign_resident(
        &root,
        &state(&foreign_digest, pid, &marker),
        &digest
    ));

    let foreign_lease = root
        .join("resident-client-leases.v1")
        .join("client-foreign.lease");
    fs::write(
        &foreign_lease,
        format!("{pid}\n{marker}\n{foreign_digest}\n"),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&foreign_lease, fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[cfg(windows)]
    crate::resident_state::protect_windows_private_path(&foreign_lease, false, &root).unwrap();
    assert!(!is_orphaned_foreign_resident(
        &root,
        &state(&foreign_digest, u32::MAX, "dead"),
        &digest
    ));
    drop(current_lease);
    fs::remove_dir_all(root).unwrap();
}
