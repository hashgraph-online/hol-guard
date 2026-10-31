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
        vec!["context", "ls"],
        vec!["context", "list"],
        vec!["context", "ls", "-q"],
        vec!["context", "ls", "--quiet"],
        vec!["context", "ls", "--format", "json"],
        vec!["context", "ls", "--format={{.Name}}"],
        vec![
            "context",
            "ls",
            "--format",
            "table {{.Name}}\t{{.DockerEndpoint}}",
        ],
        vec!["context", "show"],
    ] {
        assert!(safe_docker_arguments(&arguments(&words)), "{words:?}");
    }
}

#[test]
fn registry_manifest_queries_are_admitted() {
    for words in [
        vec![
            "buildx",
            "imagetools",
            "inspect",
            "registry.example.com/acme/acme-app:1a2b3c4",
        ],
        vec![
            "buildx",
            "imagetools",
            "inspect",
            "registry.example.com/acme/acme-app:1a2b3c4",
            "--format",
            "{{.Manifest.Digest}}",
        ],
        vec![
            "buildx",
            "imagetools",
            "inspect",
            "--format={{json .Manifest}}",
            "registry.example.com/acme/acme-app:1a2b3c4",
        ],
        vec!["buildx", "imagetools", "inspect", "--raw", "alpine:3.20"],
        vec![
            "buildx",
            "imagetools",
            "inspect",
            "--format",
            "{{ json .Index }} {{.Name}}",
            "alpine:3.20",
        ],
        vec![
            "buildx",
            "imagetools",
            "inspect",
            "registry.example.com/acme/acme-app@sha256:0123456789abcdef",
        ],
    ] {
        assert!(safe_docker_arguments(&arguments(&words)), "{words:?}");
    }
}

#[test]
fn registry_manifest_templates_cannot_print_the_image_configuration() {
    for template in [
        "{{json .Image}}",
        "{{.Image.Config.Env}}",
        "{{ .Provenance }}",
        "{{json .}}",
        "{{range .Image}}{{.}}{{end}}",
        "{{printf \"%v\" .Image}}",
        "{{.Manifest.Digest",
        "}}{{.Name}}",
        "{{.Manifest..Digest}}",
        "{{.Manifest.Digest;}}",
        "{{.ManifestX}}",
    ] {
        let format = format!("--format={template}");
        let words = [
            "buildx",
            "imagetools",
            "inspect",
            format.as_str(),
            "alpine:3.20",
        ];
        assert!(!safe_docker_arguments(&arguments(&words)), "{template}");
    }
}

#[test]
fn registry_manifest_changes_and_redirected_queries_stay_reviewed() {
    for words in [
        // `create` pushes a new manifest list; every other verb is not a query.
        vec![
            "buildx",
            "imagetools",
            "create",
            "-t",
            "registry.example.com/acme/acme-app:latest",
            "registry.example.com/acme/acme-app:1a2b3c4",
        ],
        vec!["buildx", "imagetools"],
        vec!["buildx", "imagetools", "help"],
        vec!["buildx", "imagetools", "inspect"],
        vec!["buildx", "imagetools", "inspect", "--raw"],
        vec![
            "buildx",
            "imagetools",
            "inspect",
            "registry.example.com/acme/acme-app:1",
            "registry.example.com/acme/acme-app:2",
        ],
        // Another builder carries another registry configuration and endpoint.
        vec![
            "buildx",
            "imagetools",
            "inspect",
            "--builder",
            "remote",
            "alpine:3.20",
        ],
        vec![
            "buildx",
            "imagetools",
            "inspect",
            "--builder=remote",
            "alpine:3.20",
        ],
        vec!["buildx", "imagetools", "inspect", "--format", "alpine:3.20"],
        vec!["buildx", "imagetools", "inspect", "-x", "alpine:3.20"],
        vec!["buildx", "imagetools", "inspect", "../local-file"],
        vec!["buildx", "imagetools", "inspect", "-", "alpine:3.20"],
        vec![
            "buildx",
            "imagetools",
            "inspect",
            "--format",
            "{{.Manifest.Digest}} $HOME",
            "alpine:3.20",
        ],
        vec![
            "buildx",
            "imagetools",
            "inspect",
            "--format",
            "`id`",
            "alpine:3.20",
        ],
        vec![
            "-H",
            "ssh://ops@example.com",
            "buildx",
            "imagetools",
            "inspect",
            "alpine:3.20",
        ],
        vec![
            "--config",
            "/tmp/docker-config",
            "buildx",
            "imagetools",
            "inspect",
            "alpine:3.20",
        ],
        vec![
            "buildx",
            "--builder",
            "remote",
            "imagetools",
            "inspect",
            "alpine:3.20",
        ],
    ] {
        assert!(!safe_docker_arguments(&arguments(&words)), "{words:?}");
    }
}

/// Reading back what one container already printed is a read: nothing starts,
/// nothing is pulled, no project file is resolved.
#[test]
fn bounded_container_logs_are_admitted() {
    for words in [
        vec!["logs", "web"],
        vec!["logs", "web", "--tail", "50"],
        vec!["logs", "--tail=100", "api-1"],
        vec!["logs", "-n", "200", "web"],
        vec!["logs", "--tail", "all", "web"],
        vec!["logs", "--since", "10m", "web"],
        vec![
            "logs",
            "--since=2026-10-22T09:00:00Z",
            "--until",
            "1h",
            "web",
        ],
        vec!["logs", "-t", "web"],
        vec!["logs", "--timestamps", "--tail", "20", "db_1"],
        vec!["container", "logs", "web"],
    ] {
        assert!(safe_docker_arguments(&arguments(&words)), "{words:?}");
    }
}

/// A log read that never ends, one that reaches another daemon, one that
/// prints the driver's own attributes, and a Compose log read, which resolves
/// the project first, are not that read.
#[test]
fn followed_remote_and_project_backed_logs_stay_reviewed() {
    for words in [
        vec!["logs"],
        vec!["logs", "-f", "web"],
        vec!["logs", "--follow", "web"],
        vec!["logs", "--details", "web"],
        vec!["logs", "web", "api"],
        vec!["logs", "--tail"],
        vec!["logs", "--tail", "many", "web"],
        vec!["logs", "--since", "-1h", "web"],
        vec!["logs", "--tail", "50", "../web"],
        vec!["-H", "tcp://build.example.com:2376", "logs", "web"],
        vec!["--context", "production", "logs", "web"],
        vec!["compose", "logs"],
        vec!["compose", "logs", "api"],
        vec!["compose", "logs", "--tail=50", "api", "worker"],
        vec!["compose", "logs", "--no-color", "--no-log-prefix", "api"],
        vec!["compose", "-f", "compose.prod.yaml", "logs"],
        vec!["compose", "logs", "-f"],
        vec!["compose", "logs", "--follow", "api"],
    ] {
        assert!(!safe_docker_arguments(&arguments(&words)), "{words:?}");
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
        vec!["exec", "web", "env"],
        vec!["run", "--rm", "alpine", "env"],
        vec!["compose", "up", "-d"],
        vec!["pull", "alpine"],
        vec!["system", "prune", "-af"],
        vec!["rm", "-f", "web"],
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
        // Switching, creating, copying or removing a context changes the
        // store, and `inspect` prints each endpoint's full metadata.
        vec!["context", "use", "staging"],
        vec![
            "context",
            "create",
            "remote",
            "--docker",
            "host=ssh://ops@example.com",
        ],
        vec!["context", "update", "remote", "--description", "ops"],
        vec!["context", "rm", "remote"],
        vec!["context", "export", "prod"],
        vec!["context", "import", "prod", "prod.dockercontext"],
        vec!["context", "inspect"],
        vec!["context", "inspect", "default"],
        vec!["context", "ls", "staging"],
        vec!["context", "ls", "--format"],
        vec!["context", "ls", "--format", "{{.Name}} $HOME"],
        vec!["context", "ls", "-f", "name=prod"],
        vec!["context", "ls", "-a"],
        vec!["context", "ls", "--all"],
        vec!["context", "ls", "--no-trunc"],
        vec!["context", "ls", "-aq"],
        vec!["context", "show", "--format", "{{.Name}}"],
        vec!["context", "show", "staging"],
        vec!["--context", "production", "context", "ls"],
        vec!["-H", "ssh://ops@example.com", "context", "ls"],
        vec!["context"],
    ] {
        assert!(!safe_docker_arguments(&arguments(&words)), "{words:?}");
    }
}

#[test]
fn daemon_summaries_that_resolve_no_project_are_admitted() {
    for words in [
        vec!["volume", "ls"],
        vec!["volume", "list"],
        vec!["volume", "ls", "-q"],
        vec!["volume", "ls", "--filter=dangling=true"],
        vec!["volume", "ls", "-f", "driver=local"],
        vec!["network", "ls"],
        vec!["network", "list"],
        vec!["network", "ls", "-q", "--no-trunc"],
        vec!["network", "ls", "--filter=driver=bridge"],
        vec!["network", "ls", "--format", "{{.Name}} {{.Driver}}"],
        vec!["network", "ls", "--format={{json .ID}}"],
        vec!["system", "df"],
        vec!["system", "df", "-v"],
        vec!["system", "df", "--verbose"],
        vec![
            "system",
            "df",
            "--format",
            "{{.Type}} {{.Size}} {{.Reclaimable}}",
        ],
        vec!["stats", "--no-stream"],
        vec!["stats", "--no-stream", "--all"],
        vec!["stats", "--no-stream", "web", "api"],
        vec!["stats", "--no-stream", "--format", "{{.Name}} {{.CPUPerc}}"],
    ] {
        assert!(
            safe_docker_arguments(&arguments(&words)),
            "{}",
            words.join(" ")
        );
    }
}

#[test]
fn summaries_that_stream_name_a_secret_or_query_a_registry_stay_reviewed() {
    for words in [
        // Without `--no-stream` the command redraws until it is interrupted.
        vec!["stats"],
        vec!["stats", "web"],
        vec!["stats", "--all"],
        // `--format` takes the next word as its template, so the word that was
        // supposed to bound the stream is consumed by it and the command
        // redraws exactly as a bare `docker stats` does.
        vec!["stats", "--format", "--no-stream"],
        vec!["stats", "--format=--no-stream"],
        // A network row carries the labels it was created with, and a verbose
        // disk row reaches the volumes and the options they were created with.
        vec!["network", "ls", "--format", "{{.Labels}}"],
        vec!["network", "ls", "--format", "{{json .}}"],
        vec!["network", "ls", "--format", "json"],
        vec!["network", "ls", "--format=json"],
        vec!["network", "ls", "--format", "{{.IPAM.Config}}"],
        vec!["system", "df", "--format", "{{json .}}"],
        vec!["system", "df", "--format", "json"],
        vec![
            "system",
            "df",
            "-v",
            "--format",
            "{{range .Volumes}}{{.Labels}}{{end}}",
        ],
        // `--format json` on a volume listing serializes the `--opt` values a
        // CIFS or NFS volume was created with, credentials among them.
        vec!["volume", "ls", "--format", "{{json .}}"],
        vec!["volume", "ls", "--format=json"],
        // A volume listing has no `--all` or `--no-trunc` of its own, and a
        // disk summary has no filter.
        vec!["volume", "ls", "-a"],
        vec!["volume", "ls", "--no-trunc"],
        vec!["system", "df", "--filter=type=image"],
        // `info` names the proxy the daemon was configured with, and a proxy
        // URL is written with its credentials in it.
        vec!["info"],
        vec!["info", "--format", "{{.ServerVersion}}"],
        // A process listing prints command lines and an image history the
        // commands it was built from; both routinely hold a secret.
        vec!["top", "web"],
        vec!["history", "nginx:latest"],
        vec!["diff", "web"],
        // These reach a registry rather than the local daemon.
        vec!["search", "nginx"],
        vec!["manifest", "inspect", "nginx:latest"],
        vec!["trust", "inspect", "nginx"],
        // Removal and pruning are not summaries.
        vec!["volume", "prune"],
        vec!["volume", "rm", "data"],
        vec!["network", "prune"],
        vec!["network", "rm", "web"],
        vec!["system", "prune", "-a"],
        // A streaming event feed never returns either.
        vec!["system", "events"],
    ] {
        assert!(
            !safe_docker_arguments(&arguments(&words)),
            "{}",
            words.join(" ")
        );
    }
}
