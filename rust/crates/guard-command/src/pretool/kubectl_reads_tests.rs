use super::{safe_export_segment, safe_kubectl_segment};
use crate::pretool::PathContext;

fn model(command: &str) -> crate::CanonicalCommandV1 {
    crate::parse_command(&crate::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })
    .unwrap()
}

fn proven_with(command: &str, cwd: &str) -> bool {
    let model = model(command);
    let context = PathContext {
        cwd: Some(cwd),
        ..PathContext::default()
    };
    model.confidence == "exact"
        && model
            .segments
            .first()
            .is_some_and(|segment| match segment.executable.as_deref() {
                Some("kubectl") => safe_kubectl_segment(&model, segment, context),
                Some("export") => safe_export_segment(&model, segment, context),
                _ => false,
            })
}

fn proven(command: &str) -> bool {
    proven_with(command, "/")
}

#[test]
fn read_verbs_are_proven() {
    for command in [
        "kubectl get pods",
        "kubectl get pods -l app=frontend -o wide",
        "kubectl get deployments -A -o wide",
        "kubectl get deploy,svc --namespace=web -o=jsonpath='{.items[*].metadata.name}'",
        "kubectl -n web get pods --selector=tier=api --sort-by=.metadata.name",
        "kubectl --context prod get nodes --show-labels",
        "kubectl describe pod web-0 -n web",
        "kubectl top pods -A",
        "kubectl top node",
        "kubectl api-resources",
        "kubectl api-versions",
        "kubectl explain deployment.spec --recursive",
        "kubectl cluster-info",
        "kubectl config get-contexts",
        "kubectl config current-context",
        "kubectl version",
        "kubectl version --client -o json",
        "kubectl get configmaps -A",
        "kubectl get cm app-settings -o wide",
        "kubectl get configmap app-settings -o name",
        "kubectl logs web-0",
        "kubectl logs deploy/web --tail 100",
        "kubectl --context staging -n web logs deploy/web --since-time=2026-10-08T00:00:00Z --tail=300",
        "kubectl logs web-0 app --since=15m --timestamps",
        "kubectl logs -p web-0 -c app --limit-bytes 65536",
        "kubectl logs statefulset/db --all-containers --prefix",
        "kubectl logs -l app=web --max-log-requests 5 --tail=50",
    ] {
        assert!(proven(command), "{command}");
    }
}

#[test]
fn secrets_mutations_and_server_overrides_stay_reviewed() {
    for command in [
        "kubectl get secrets",
        "kubectl get secret app-token -o yaml",
        "kubectl get pods,secrets",
        "kubectl describe secret/app-token",
        "kubectl get secrets.v1 -A",
        "kubectl get --raw /api/v1/namespaces/web/secrets",
        "kubectl get pods -o go-template-file=t.tmpl",
        "kubectl get pods -o jsonpath-file=q.txt",
        "kubectl get pods --template={{.items}}",
        "kubectl get pods -f pods.yaml",
        "kubectl get pods -w",
        "kubectl get pods -v=9",
        "kubectl get pods --server https://10.0.0.1",
        "kubectl get pods -s https://10.0.0.1",
        "kubectl get pods --token abc",
        "kubectl get pods --as admin",
        "kubectl get pods --as-group system:masters",
        "kubectl get pods --user admin",
        "kubectl get pods --insecure-skip-tls-verify",
        "kubectl get pods --cache-dir /tmp/kube",
        "kubectl get pods -n $NS",
        "kubectl get",
        "kubectl version --short=x",
        "kubectl logs -f web-0",
        "kubectl logs --follow deploy/web",
        "kubectl logs web-0 --tail=-1",
        "kubectl logs web-0 --since-time=$(date)",
        "kubectl logs secret/app-token",
        "kubectl logs configmap/app-settings",
        "kubectl logs node/node-1",
        "kubectl logs web-0 app extra",
        "kubectl logs web-0 -o yaml",
        "kubectl logs web-0 -c ../app",
        "kubectl logs web-0 --as admin",
        "kubectl logs web-0 --server https://10.0.0.1",
        "kubectl logs web-0 -v=9",
        "kubectl get pods --tail 10",
        "kubectl get pods -c app",
        "kubectl describe pod web-0 --previous",
        "kubectl get configmap app-settings -o yaml",
        "kubectl get cm app-settings -o jsonpath='{.data}'",
        "kubectl get pods,configmaps -o json",
        "kubectl describe configmap app-settings",
        "kubectl describe cm",
        "kubectl get sealedsecrets -A",
        "kubectl exec web-0 -- env",
        "kubectl cp web-0:/etc/app ./app",
        "kubectl port-forward web-0 8080",
        "kubectl proxy",
        "kubectl attach web-0",
        "kubectl run shell --image=busybox",
        "kubectl apply -f deploy.yaml",
        "kubectl create token web",
        "kubectl delete pod web-0",
        "kubectl edit deploy web",
        "kubectl patch deploy web -p {}",
        "kubectl scale deploy web --replicas=0",
        "kubectl rollout restart deploy/web",
        "kubectl label pod web-0 a=b",
        "kubectl annotate pod web-0 a=b",
        "kubectl drain node-1",
        "kubectl cordon node-1",
        "kubectl auth can-i get pods --as admin",
        "kubectl config view --raw",
        "kubectl config view",
        "kubectl config use-context prod",
        "kubectl cluster-info dump",
        "kubectl top secret",
        "kubectl debug web-0",
        "kubectl foo",
    ] {
        assert!(!proven(command), "{command}");
    }
}

/// Kubeconfig files on disk. The proof is POSIX-only and rejects `:` paths.
#[cfg(unix)]
mod files {
    use super::{proven, proven_with};
    use std::path::PathBuf;

    struct Directory(PathBuf);

    impl Directory {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("guard-kubeconfig-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path.canonicalize().unwrap())
        }

        fn write(&self, name: &str, text: &str) -> String {
            let path = self.0.join(name);
            std::fs::write(&path, text).unwrap();
            path.to_str().unwrap().to_owned()
        }
    }

    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const INERT: &str = "apiVersion: v1\nkind: Config\nclusters:\n- name: a\n  cluster:\n    server: https://k8s.example.com\ncontexts:\n- name: a\n  context:\n    cluster: a\n    user: a\ncurrent-context: a\nusers:\n- name: a\n  user: {}\n";

    const PLUGIN: &str = "apiVersion: v1\nkind: Config\nusers:\n- name: a\n  user:\n    exec:\n      apiVersion: client.authentication.k8s.io/v1\n      command: ./refresh.sh\n";

    const TOKEN_FILE: &str =
        "apiVersion: v1\nkind: Config\nusers:\n- name: a\n  user:\n    tokenFile: /home/a/.ssh/id_ed25519\n";

    #[test]
    fn inert_kubeconfig_is_accepted_anywhere() {
        let directory = Directory::new("inert");
        let path = directory.write("kubeconfig.yaml", INERT);
        assert!(proven(&format!("kubectl --kubeconfig {path} get pods")));
        assert!(proven(&format!(
            "kubectl --kubeconfig={path} get pods -o wide"
        )));
        assert!(proven(&format!("export KUBECONFIG={path}")));
    }

    #[test]
    fn active_kubeconfig_from_agent_trees_stays_reviewed() {
        let directory = Directory::new("active");
        for (name, text) in [("plugin.yaml", PLUGIN), ("token.yaml", TOKEN_FILE)] {
            let path = directory.write(name, text);
            assert!(
                !proven(&format!("kubectl --kubeconfig {path} get pods")),
                "{name}"
            );
            assert!(!proven(&format!("export KUBECONFIG={path}")), "{name}");
        }
        // Relative to the working directory, inside the agent's own tree.
        directory.write("kc.yaml", PLUGIN);
        let cwd = directory.0.to_str().unwrap();
        assert!(!proven_with("kubectl --kubeconfig kc.yaml get pods", cwd));
    }

    #[test]
    fn malformed_or_other_exports_stay_reviewed() {
        let directory = Directory::new("export");
        let path = directory.write("kubeconfig.yaml", INERT);
        for command in [
            "export KUBECONFIG=/missing/kubeconfig.yaml".to_owned(),
            format!("export KUBECONFIG={path}:{path}"),
            format!("export KUBECONFIG={path} GIT_SSH_COMMAND=x"),
            "export GIT_SSH_COMMAND=x".to_owned(),
            "export KUBECONFIG=$HOME/kubeconfig.yaml".to_owned(),
            "export -p".to_owned(),
            "export".to_owned(),
            format!(
                "kubectl --kubeconfig {}/missing.yaml get pods",
                directory.0.display()
            ),
            format!("kubectl --kubeconfig {} get pods", directory.0.display()),
        ] {
            assert!(!proven(&command), "{command}");
        }
    }
}
