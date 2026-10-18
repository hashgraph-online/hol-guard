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
        vec!["version"],
        vec!["compose", "version"],
        vec!["compose", "version", "--short"],
        vec!["buildx", "version"],
        vec!["buildx", "ls"],
        vec!["buildx", "ls", "--no-trunc"],
        vec!["compose", "ls"],
        vec!["compose", "list"],
        vec!["compose", "ls", "-a", "-q"],
        vec!["compose", "ls", "--filter=name=portal", "--format", "json"],
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
        // Only the banner itself; a format string or a project file is not it.
        vec!["version", "--format", "{{json .}}"],
        vec!["compose", "version", "--format", "json"],
        vec!["compose", "-f", "compose.yaml", "version"],
        vec!["-H", "ssh://ops@example.com", "version"],
        // A builder listing prints names; starting, changing or removing one
        // does not, and neither does a project the listing has to resolve.
        vec!["buildx", "inspect"],
        vec!["buildx", "inspect", "--bootstrap", "default"],
        // `--format json` prints each builder's nodes, proxy configuration
        // included, and `-f` on a project listing names a compose file.
        vec!["buildx", "ls", "--format", "json"],
        vec!["buildx", "ls", "--format", "{{.Name}}"],
        vec!["compose", "ls", "-f", "name=portal"],
        vec!["compose", "ls", "-f", "/srv/other=1/compose.yaml"],
        vec!["buildx", "ls", "default"],
        vec!["buildx", "ls", "--builder", "remote"],
        vec!["buildx", "create", "--use"],
        vec!["buildx", "rm", "old-builder"],
        vec!["buildx", "prune", "-af"],
        vec!["buildx", "build", "."],
        vec!["compose", "ls", "--project-directory", "/srv/app"],
        vec!["compose", "-f", "compose.yaml", "ls"],
        vec!["compose", "ls", "portal"],
        vec!["-H", "ssh://ops@example.com", "buildx", "ls"],
    ] {
        assert!(!safe_docker_arguments(&arguments(&words)), "{words:?}");
    }
}
