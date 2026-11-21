use super::parent_liveness_pipe_open;
use std::fs::File;
use std::io::Write;

#[test]
fn already_closed_supervisor_is_observed_without_a_watcher_thread() {
    let (reader, writer) = nix::unistd::pipe().unwrap();
    let reader = File::from(reader);
    drop(writer);
    assert!(!parent_liveness_pipe_open(&reader).unwrap());
}

#[test]
fn live_supervisor_is_nonblocking_and_protocol_data_means_death() {
    let (reader, writer) = nix::unistd::pipe().unwrap();
    let reader = File::from(reader);
    let mut writer = File::from(writer);
    assert!(parent_liveness_pipe_open(&reader).unwrap());
    writer.write_all(b"closed").unwrap();
    assert!(!parent_liveness_pipe_open(&reader).unwrap());
}
