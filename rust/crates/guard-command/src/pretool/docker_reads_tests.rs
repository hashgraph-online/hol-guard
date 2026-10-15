use super::safe_docker_arguments;

fn arguments(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| (*word).to_owned()).collect()
}

#[test]
fn container_and_image_listings_are_admitted() {
    for words in [
        vec!["ps"],
        vec!["ps", "-a"],
        vec!["ps", "-aq"],
        vec!["ps", "--all", "--no-trunc"],
        vec!["ps", "--format", "{{.Names}} {{.Ports}}"],
        vec!["ps", "--format={{json .}}"],
        vec!["ps", "--format", "table {{.Names}}\t{{.Status}}"],
        vec!["ps", "-f", "name=web", "-n", "5"],
        vec!["ps", "--filter=status=running", "--last", "3"],
        vec!["ps", "-s", "-l"],
        vec!["container", "ls", "-a"],
        vec!["container", "list"],
        vec!["images"],
        vec!["images", "-a", "--digests"],
        vec!["images", "node:20-alpine"],
        vec!["images", "--format", "{{.Repository}}:{{.Tag}}"],
        vec!["image", "ls", "-q"],
    ] {
        assert!(safe_docker_arguments(&arguments(&words)), "{words:?}");
    }
}

#[test]
fn remote_daemons_secrets_and_other_subcommands_stay_reviewed() {
    for words in [
        vec![],
        vec!["-H", "tcp://build.example.com:2376", "ps"],
        vec!["--host=ssh://ops@example.com", "ps"],
        vec!["--context", "production", "ps"],
        vec!["-c", "production", "images"],
        vec!["--config", "/tmp/docker-config", "ps"],
        vec!["--tlsverify", "ps"],
        vec!["-D", "ps"],
        vec!["inspect", "web"],
        vec!["container", "inspect", "web"],
        vec!["compose", "ps"],
        vec!["logs", "web", "--tail", "50"],
        vec!["exec", "web", "env"],
        vec!["run", "--rm", "alpine", "env"],
        vec!["compose", "up", "-d"],
        vec!["pull", "alpine"],
        vec!["system", "prune", "-af"],
        vec!["rm", "-f", "web"],
        vec!["stats", "--no-stream"],
        vec!["scan", "alpine"],
        vec!["ps", "web"],
        vec!["ps", "-x"],
        vec!["ps", "-n5"],
        vec!["ps", "-n", "five"],
        vec!["ps", "-f"],
        vec!["ps", "-f", "running"],
        vec!["ps", "--format"],
        vec!["ps", "--format", "{{.Names}} $HOME"],
        vec!["ps", "--format", "`id`"],
        vec!["ps", "--", "-a"],
        vec!["images", "--digests", "a", "b"],
        vec!["images", "-s"],
        vec!["images", "../secrets"],
        vec!["image", "inspect", "alpine"],
        vec!["image", "history", "alpine"],
        vec!["container", "top", "web"],
    ] {
        assert!(!safe_docker_arguments(&arguments(&words)), "{words:?}");
    }
}
