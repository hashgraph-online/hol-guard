use super::safe_start_arguments;

#[test]
fn starting_named_existing_containers_is_admitted() {
    for words in [
        vec!["start", "app-test-pg"],
        vec!["start", "web", "db_1", "cache.local"],
        vec!["start", "4f3c2b1a9d8e"],
        vec!["container", "start", "web"],
    ] {
        assert!(safe_start_arguments(&words), "{words:?}");
    }
}

#[test]
fn options_unusual_operands_and_other_subcommands_stay_reviewed() {
    for words in [
        vec![],
        vec!["start"],
        vec!["container"],
        vec!["container", "start"],
        vec!["start", "-a", "web"],
        vec!["start", "--attach", "web"],
        vec!["start", "-ai", "web"],
        vec!["start", "-i", "web"],
        vec!["start", "--checkpoint", "cp1", "web"],
        vec!["start", "--checkpoint-dir=/tmp/cp", "web"],
        vec!["start", "--detach-keys", "ctrl-x", "web"],
        vec!["start", "--", "web"],
        vec!["start", "-web"],
        vec!["start", "../web"],
        vec!["start", "web/db"],
        vec!["start", "web*"],
        vec!["start", "web?"],
        vec!["start", "_web"],
        vec!["start", "web:latest"],
        vec!["start", "~web"],
        vec!["stop", "web"],
        vec!["restart", "web"],
        vec!["container", "stop", "web"],
        vec!["container", "restart", "web"],
        vec!["kill", "web"],
        vec!["rm", "-f", "web"],
        vec!["pause", "web"],
        vec!["update", "--privileged", "web"],
        vec!["exec", "web", "env"],
        vec!["run", "-v", "/:/host", "alpine"],
        vec!["create", "alpine"],
        vec!["container", "kill", "web"],
        vec!["-H", "tcp://build.example.com:2376", "start", "web"],
        vec!["--context", "production", "start", "web"],
    ] {
        assert!(!safe_start_arguments(&words), "{words:?}");
    }
}
