"""Record parity vectors for the Kubernetes command checks.

Usage: ``sfrs_kubernetes_cases.py FIXTURE_DIR``. Every function reachable from
``kubernetes_commands`` (and its two support modules) is called over a fixed
corpus of commands, token lists, paths and scripts; the inputs and results are
stored in ``kubernetes.json.gz`` for the Rust port to replay. This script
depends on the Python implementation and is retired with it.
"""

from __future__ import annotations

import gzip
import json
import shlex
import sys
from pathlib import Path

from codex_plugin_scanner.guard.runtime import kubernetes_command_support as support
from codex_plugin_scanner.guard.runtime import kubernetes_commands as kc
from codex_plugin_scanner.guard.runtime import kubernetes_heredoc_support as hd

SECRET_SCRIPTS = [
    "cat /var/run/secrets/kubernetes.io/serviceaccount/token",
    "cat /etc/secrets/db",
    "cat < /run/secrets/key",
    "cat </mnt/secrets-store/x",
    "echo $API_KEY",
    "echo ${DB_PASSWORD:-x}",
    "echo \\$API_KEY",
    "echo $HOME",
    "echo hello",
    "printenv",
    "printenv HOME",
    "printenv API_KEY | head",
    "env",
    "env FOO=1",
    "env | sort",
    "cat /proc/self/environ",
    "cat /proc/1/environ",
    "cat /proc/\u0661/environ",
    "tee /etc/secrets/out",
    "echo x > /etc/secrets/out",
    "cp /etc/secrets/a /tmp/b",
    "cp /tmp/a /etc/secrets/b",
    "cp -t /tmp /etc/secrets/a",
    "cp --target-directory=/tmp /etc/secrets/a",
    "cp --target-directory /tmp /etc/secrets/a",
    "ls /var/run/secrets-store/",
    "ls --dir=/etc/secret",
    "ls -la",
    "sh -c 'cat /etc/secrets/x'",
    "bash -lc 'echo $TOKEN'",
    'sh -c "echo $(cat /run/secrets/x)"',
    "sh -- -c 'cat /etc/secrets/x'",
    "python -c \"import os; print(os.environ['API_KEY'])\"",
    "python3 -c 'import os; print(os.environ)'",
    "python -c 'import os; print(os.environ.get(\"SECRET_X\"))'",
    "python -c 'import os; os.environ.copy()'",
    "python -c 'import os; os.environ . items ()'",
    "python -c 'import os; print(os.getenv(\"PASSWORD\"))'",
    "python -c 'import os; os.environ[key]'",
    'python -c \'import os; os.environ.setdefault("a", "b")\'',
    "node -e 'console.log(process.env.AUTH_TOKEN)'",
    "node -e 'console.log(process.env)'",
    "node -e 'process.env[k]'",
    "node -e 'process.env[\"HOME\"]'",
    "node -e 'process.env . SECRET'",
    "ruby -e 'puts ENV[\"API_KEY\"]'",
    "ruby -e 'puts ENV[\"PATH\"]'",
    "java -e 'System.getenv(\"TOKEN\")'",
    "perl -e 'print $ENV{TOKEN}'",
    "php -r 'echo getenv(\"TOKEN\");'",
    "echo $PRIVATE_KEY $PATH",
    "echo ${PRIVATE-KEY}",
    "echo $KEYBOARD",
    "echo $my_key_",
    "echo $_key",
    "echo $\u00e9",
    "",
    "   ",
    "echo `cat /etc/secrets/x`",
    "echo $(cat /etc/secrets/x)",
    "x=$(printenv TOKEN)",
]

PATHS = [
    "",
    " ",
    "/etc/secrets",
    "/etc/secrets/",
    "/etc/secrets/x",
    "/etc/secretsx",
    "/etc/secret/x",
    "/ETC/SECRETS/x",
    "'/etc/secrets/x'",
    '"/run/secrets/x"',
    "  /run/secrets/x  ",
    "/run/secrets",
    "/run/secrets-store/a",
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/var/run/secrets/kubernetes.io/serviceaccount",
    "/run/secrets/kubernetes.io/serviceaccount/ca.crt",
    "--path=/etc/secrets/x",
    "--path=",
    "=/etc/secrets/x",
    "a=b",
    "a='/etc/secrets/x'",
    "a= /etc/secrets/x ",
    "/mnt/secrets-store/x",
    "/mnt/secrets",
    "/proc/self/environ",
    "/proc/1/environ",
    "/proc/123/environ",
    "/proc/\u0661\u0662/environ",
    "/proc/x/environ",
    "/proc/self/environ/",
    "/proc/self/environ\n",
    "PROC=/proc/self/environ",
    "/PROC/SELF/ENVIRON",
    "/tmp/x",
    "relative/path",
    "\u00c9tc/secrets",
    "\u0130/etc/secrets",
    "C:\\run\\secrets",
]

RAW_PATHS = [
    "/api/v1/secrets",
    "/api/v1/secrets/",
    "/api/v1/secrets/name",
    "/api/v1/namespaces/ns/secrets",
    "/api/v1/namespaces/ns/secrets/name",
    "/api/v1/watch/namespaces/ns/secrets",
    "/api/v1/watch/secrets",
    "/apis/g/v1/namespaces/ns/secret",
    "/apis/g/v1/secrets/x?watch=true",
    "/apis/g/v1/secrets/x#frag",
    "'/API/V1/SECRETS'",
    '"/api/v1/secrets"',
    "  /api/v1/secrets  ",
    "/api/v1/pods",
    "/api/v1/namespaces/ns/pods",
    "/api/v1/secretsx",
    "/api/v1/secrets/a/b",
    "/api/secrets",
    "api/v1/secrets",
    "",
    "/apis/g/secrets",
    "/api/v1/namespaces/a/b/secrets",
    "/api/v1/secrets\n",
    "/api/v1/secrets?x=1#y",
]

REMOTE_CP = [
    "pod:/etc/secrets/x",
    "ns/pod:/etc/secrets/x",
    ":/x",
    "pod:",
    "pod",
    "",
    "http://x/y",
    "a:b:c",
    "pod:/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/etc/secrets/x",
    "C:/x",
]

RESOURCE_TOKENS = [
    "secret",
    "secrets",
    "Secret",
    "SECRETS",
    "secret/name",
    "secrets.v1",
    "secrets.v1/name",
    "pods,secrets",
    "pods,Secret/x",
    "pods",
    "pod/secret",
    "secretx",
    "",
    "secret,",
    ",",
    "configmap",
    "sec",
    "secrets,pods",
    "svc.secrets",
    "po/secrets",
    "secret.v1.",
    "\u0130secret",
]

INLINE_ARGS = [
    ["-c", "import os"],
    ["-e", "x"],
    ["-cprint(1)"],
    ["-eputs 1"],
    ["-c"],
    ["-e"],
    [],
    ["-"],
    ["-", "<<EOF"],
    ["<<EOF", "-"],
    ["-", "<<EOF", "os.environ"],
    ["x.py"],
    ["-c", ""],
    ["--", "-c", "x"],
    ["-m", "x", "-c", "y"],
    ["-c", "a", "-e", "b"],
    ["-c1", "-e2"],
]

COMMAND_NAMES = [
    "python",
    "python3",
    "python3.12",
    "pythonw",
    "node",
    "nodejs",
    "perl",
    "php",
    "ruby",
    "bash",
    "sh",
    "kubectl",
    "oc",
    "",
    "Python",
    "py",
    "pythonx",
    "NODE",
    "java",
]

OPTION_TOKENS = [
    "-n",
    "-nfoo",
    "-n=foo",
    "--namespace",
    "--namespace=foo",
    "--namespacex",
    "--as",
    "--as=x",
    "--as-group",
    "-A",
    "--all-namespaces",
    "--all-namespaces=true",
    "-A=1",
    "-i",
    "-t",
    "-it",
    "-ti",
    "-itq",
    "-itx",
    "-q",
    "-T",
    "--tty",
    "--stdin",
    "--quiet",
    "--quiet=true",
    "-c",
    "-cfoo",
    "-c=foo",
    "--container=foo",
    "--container",
    "-o",
    "-ojson",
    "--output=json",
    "-l",
    "-lapp=x",
    "-f",
    "-f-",
    "-",
    "--",
    "--retries",
    "--retries=3",
    "--no-preserve",
    "--no-preserve=true",
    "--ignore-not-found",
    "--show-labels",
    "--raw",
    "--request-timeout=5s",
    "--kubeconfig",
    "--kubeconfig=/x",
    "--context",
    "--context=prod",
    "-x",
    "--x",
    "",
    "foo",
    "secret",
    "-n-",
    "--shell",
    "--shell=/bin/sh",
    "--pod-running-timeout=1s",
    "--token=abc",
]

GET_SAMPLES = [
    "kubectl get pods",
    "kubectl get pods -o wide",
    "kubectl get pods -o name",
    "kubectl get pod/web -o name",
    "kubectl get pods -oname",
    "kubectl get pods --output=wide",
    "kubectl get pods --output wide",
    "kubectl get pods -o yaml",
    "kubectl get pods -o json",
    "kubectl get pods -o custom-columns=A:.x",
    "kubectl get pods -o jsonpath='{.items[0].metadata.name}'",
    "kubectl get pods -o jsonpath={.metadata.uid}",
    "kubectl get pods -o jsonpath-as-json='{.status.phase}'",
    "kubectl get pods -o jsonpath='{.spec}'",
    "kubectl get pods -o jsonpath='{.items[*].metadata.namespace}'",
    "kubectl get pods -o 'JSONPATH={.Status.Phase}'",
    "kubectl get pods -o jsonpath",
    "kubectl get pods -o jsonpath=",
    "kubectl get pods -o",
    "kubectl get pods --raw /api/v1/secrets",
    "kubectl get --raw=/api/v1/pods",
    "kubectl get --raw",
    "kubectl get pods,secrets",
    "kubectl get secrets",
    "kubectl get pods secrets",
    "kubectl get pods secret/x",
    "kubectl get pods pod/x svc/y",
    "kubectl get pods pod/x cm/y",
    "kubectl get pods po/a,secret/b",
    "kubectl get pods.v1 -n kube-system",
    "kubectl -n kube-system get pods",
    "kubectl --context prod get nodes",
    "kubectl --kubeconfig=/x get nodes -A",
    "kubectl get nodes --no-headers --show-labels --show-kind",
    "kubectl get nodes --ignore-not-found --use-openapi-print-columns",
    "kubectl get -- pods",
    "kubectl get pods -l app=x",
    "kubectl get pods --selector app=x --field-selector=a=b",
    "kubectl get pods -w",
    "kubectl get",
    "kubectl",
    "kubectl describe pods",
    "oc get pods",
    "OC get Pods",
    "kubectl get Pods -O wide",
    "kubectl get pods -Owide",
    "kubectl get events --sort-by=.x",
    "kubectl get deploy.apps",
    "kubectl get ing",
    "kubectl get cm",
    "kubectl get PODS",
    "kubectl get pods -ojsonpath=name",
    "kubectl get --output=jsonpath={.metadata.name} pods",
    "kubectl get pods -o name -o yaml",
    "kubectl get -n x",
    "kubectl get -f x.yaml",
]

KUBE_COMMANDS = [
    "kubectl get secret",
    "kubectl get secrets",
    "kubectl get secret db -o yaml",
    "kubectl get secret db -o jsonpath='{.data.password}'",
    "kubectl get secrets -A",
    "kubectl get secret/db -n prod",
    "kubectl get pods,secrets",
    "kubectl get Secret",
    "kubectl get SECRETS.v1",
    "kubectl -n prod get secret db",
    "kubectl --namespace=prod get secret",
    "kubectl --context=c get secret",
    "kubectl --context c --kubeconfig /k -n ns get secret",
    "kubectl --kubeconfig=/k get secrets",
    "kubectl -A get secrets",
    "kubectl --all-namespaces get secrets",
    "kubectl --token=x get secret",
    "kubectl describe secret db",
    "kubectl describe secrets",
    "kubectl describe pod x",
    "kubectl edit secret db",
    "kubectl edit cm x",
    "kubectl logs pod",
    "kubectl logs deploy/x -c app",
    "kubectl apply -f x.yaml",
    "kubectl apply -f -",
    "kubectl delete secret db",
    "kubectl delete pod x",
    "kubectl create secret generic db --from-literal=password=hunter2",
    "kubectl create secret generic db --from-file=./key.pem",
    "kubectl create secret tls t --cert=a --key=b",
    "kubectl create token sa",
    "kubectl create token sa -n x",
    "kubectl create -n x token sa",
    "kubectl --context c create token default --duration=1h",
    "kubectl create deployment x --image=y",
    "kubectl create",
    "kubectl create -n",
    "kubectl get --raw /api/v1/namespaces/x/secrets",
    "kubectl get --raw=/api/v1/secrets/x",
    "kubectl get --raw /api/v1/pods",
    "kubectl get --raw",
    "kubectl get --raw=/apis/x/v1/namespaces/n/secrets?watch=1 ",
    "kubectl get -o yaml --raw /api/v1/secrets",
    "oc extract secret/db",
    "oc extract secrets/db --to=-",
    "oc extract cm/x",
    "oc -n x extract secret/y",
    "kubectl extract secret/db",
    "oc get secret db",
    "oc describe secret",
    "oc rsh pod cat /etc/secrets/x",
    "oc rsh pod printenv",
    "kubectl rsh pod env",
    "kubectl exec pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/token",
    "kubectl exec pod -- cat /etc/secrets/db",
    "kubectl exec -it pod -- cat /etc/secrets/db",
    "kubectl exec -n x pod -c c -- cat /run/secrets/x",
    "kubectl exec pod cat /etc/secrets/x",
    "kubectl exec pod --container c -- printenv",
    "kubectl exec pod -- printenv API_KEY",
    "kubectl exec pod -- printenv HOME",
    "kubectl exec pod -- env",
    "kubectl exec pod -- env FOO=1",
    "kubectl exec pod -- env FOO=1 cat /etc/secrets/x",
    "kubectl exec pod -- sh -c 'echo $API_KEY'",
    "kubectl exec pod -- sh -c 'cat /etc/secrets/x'",
    "kubectl exec pod -- bash -c 'echo hi'",
    "kubectl exec pod -- sh -c 'sh -c \"cat /etc/secrets/x\"'",
    'kubectl exec pod -- sh -c \'sh -c "sh -c \\"sh -c \\\\\\"cat /etc/secrets/x\\\\\\"\\""\'',
    "kubectl exec pod -- sh -c 'echo $(printenv TOKEN)'",
    "kubectl exec pod -- sh -c 'echo `printenv TOKEN`'",
    "kubectl exec pod -- sudo cat /etc/secrets/x",
    "kubectl exec pod -- sudo -u root printenv",
    "kubectl exec pod -- nice -n 5 cat /etc/secrets/x",
    "kubectl exec pod -- command -v cat /etc/secrets/x",
    "kubectl exec pod -- time cat /run/secrets/x",
    "kubectl exec pod -- nohup cat /run/secrets/x",
    "kubectl exec pod -- stdbuf -oL cat /run/secrets/x",
    "kubectl exec pod -- env -i cat /etc/secrets/x",
    "kubectl exec pod -- env -S 'cat /etc/secrets/x'",
    "kubectl exec pod -- env -u X printenv",
    "kubectl exec pod -- env -S 'printenv' ",
    "kubectl exec pod -- X=1 cat /etc/secrets/x",
    "kubectl exec pod -- /bin/cat /etc/secrets/x",
    "kubectl exec pod -- /usr/bin/printenv TOKEN",
    "kubectl exec pod -- CAT /etc/secrets/x",
    "kubectl exec pod -- cat < /etc/secrets/x",
    "kubectl exec pod -- cat </etc/secrets/x",
    "kubectl exec pod -- cat --file=/etc/secrets/x",
    "kubectl exec pod -- cat -n /etc/secrets/x",
    "kubectl exec pod -- ls /etc/secrets",
    "kubectl exec pod -- ls -la /etc",
    "kubectl exec pod -- echo /etc/secrets/x",
    "kubectl exec pod -- rm /etc/secrets/x",
    "kubectl exec pod -- tee /etc/secrets/x",
    "kubectl exec pod -- touch /run/secrets/x",
    "kubectl exec pod -- cp /etc/secrets/a /tmp/b",
    "kubectl exec pod -- cp /tmp/a /etc/secrets/b",
    "kubectl exec pod -- cp -t /tmp /etc/secrets/a",
    "kubectl exec pod -- cp --target-directory=/tmp /etc/secrets/a",
    "kubectl exec pod -- cp -t",
    "kubectl exec pod -- cp /a",
    "kubectl exec pod -- cp -r /etc/secrets /tmp",
    "kubectl exec pod -- cat /proc/self/environ",
    "kubectl exec pod -- strings /proc/1/environ",
    "kubectl exec pod -- echo /proc/self/environ",
    "kubectl exec pod -- python -c 'import os; print(os.environ)'",
    "kubectl exec pod -- python3 -c \"import os; os.getenv('TOKEN')\"",
    "kubectl exec pod -- node -e 'process.env.KEY'",
    "kubectl exec pod -- ruby -e 'ENV[\"SECRET\"]'",
    "kubectl exec pod -- perl -e 'print 1'",
    "kubectl exec pod -- python -c 'print(1)'",
    "kubectl exec pod -- python",
    "kubectl exec pod --",
    "kubectl exec pod",
    "kubectl exec",
    "kubectl exec -it",
    "kubectl exec -- cat /etc/secrets/x",
    "kubectl exec pod -n",
    "kubectl exec -n x -- cat /etc/secrets/x",
    "kubectl exec -itn x pod -- printenv",
    "kubectl exec -i -t -q pod -- printenv",
    "kubectl exec pod -- printenv | sort",
    "kubectl exec pod -- env | grep X",
    "kubectl exec pod -- printenv -0",
    "kubectl exec pod -- sh",
    "kubectl exec -i pod -- sh",
    "kubectl cp pod:/etc/secrets/x ./x",
    "kubectl cp ns/pod:/var/run/secrets/kubernetes.io/serviceaccount/token ./t",
    "kubectl cp -c c pod:/etc/secrets/x ./x",
    "kubectl cp -n x pod:/etc/secrets/x ./x",
    "kubectl cp --retries=3 pod:/run/secrets/x .",
    "kubectl cp --no-preserve pod:/etc/secrets/x .",
    "kubectl cp ./x pod:/etc/secrets/x",
    "kubectl cp pod:/tmp/x ./x",
    "kubectl cp pod:/etc/secrets/x",
    "kubectl cp",
    "kubectl cp -n",
    "kubectl cp http://x/etc/secrets/x ./y",
    "kubectl cp --container=c pod:/mnt/secrets-store/s ./s",
    "kubectl cp -x pod:/etc/secrets/x ./x",
    "FOO=1 kubectl get secrets",
    "FOO=1 BAR=2 kubectl describe secret x",
    "env kubectl get secrets",
    "env FOO=1 kubectl get secrets",
    "env -i kubectl get secrets",
    "env -u X kubectl get secrets",
    "env -S 'kubectl get secrets'",
    "env -S 'kubectl get secrets' x",
    "env -C /tmp kubectl get secrets",
    "env --chdir=/tmp kubectl get secrets",
    "env -- kubectl get secrets",
    "env",
    "env -i",
    "env -u",
    "env FOO=1",
    "env kubectl",
    "env && kubectl get secrets",
    "env ; kubectl get secrets",
    "env | kubectl get secrets",
    "env -S",
    "env -S ''",
    "env -S ' '",
    "env -X kubectl get secrets",
    "sudo kubectl get secrets",
    "sudo -u root kubectl get secrets",
    "sudo -E kubectl get secrets",
    "sudo --user=root kubectl get secrets",
    "sudo --user root kubectl get secrets",
    "sudo -n kubectl get secrets",
    "sudo -- kubectl get secrets",
    "sudo FOO=1 kubectl get secrets",
    "sudo -E -u root -n kubectl get secrets",
    "sudo -ni kubectl get secrets",
    "sudo -g wheel kubectl get secrets",
    "sudo --group=wheel kubectl get secrets",
    "sudo",
    "sudo -u",
    "sudo -u root",
    "sudo env kubectl get secrets",
    "sudo env FOO=1 sudo kubectl get secrets",
    "nice kubectl get secrets",
    "nice -n 5 kubectl get secrets",
    "nice --adjustment=5 kubectl get secrets",
    "nohup kubectl get secrets",
    "nohup sudo kubectl get secrets",
    "time kubectl get secrets",
    "time -p kubectl get secrets",
    "time -f %e kubectl get secrets",
    "time --format=%e kubectl get secrets",
    "stdbuf -oL kubectl get secrets",
    "stdbuf -o L kubectl get secrets",
    "stdbuf --output=L kubectl get secrets",
    "command kubectl get secrets",
    "command -v kubectl",
    "command -p kubectl get secrets",
    "/usr/local/bin/kubectl get secrets",
    "./kubectl get secrets",
    "../bin/oc get secrets",
    "KUBECTL get secrets",
    "kubectl/ get secrets",
    "kubectl. get secrets",
    "./ get secrets",
    "/ get secrets",
    "bin//kubectl get secrets",
    "~/bin/kubectl get secrets",
    "kubectl.exe get secrets",
    "kubectl-foo get secrets",
    "echo ok && kubectl get secrets",
    "echo ok; kubectl get secrets",
    "echo ok | kubectl get secrets",
    "echo ok || kubectl get secrets",
    "echo ok & kubectl get secrets",
    "echo ok\nkubectl get secrets",
    "kubectl get pods && kubectl get secrets",
    "kubectl get pods; kubectl describe secret x",
    "(kubectl get secrets)",
    "{ kubectl get secrets; }",
    "! kubectl get secrets",
    "if true; then kubectl get secrets; fi",
    "echo $(kubectl get secrets)",
    "echo `kubectl get secrets`",
    'echo "$(kubectl get secrets)"',
    "echo '$(kubectl get secrets)'",
    "x=$(kubectl get secrets -o yaml)",
    "echo $(echo $(kubectl get secrets))",
    "echo $(echo $(echo $(echo $(echo $(kubectl get secrets)))))",
    "bash -c 'kubectl get secrets'",
    'sh -c "kubectl describe secret x"',
    "bash -lc 'kubectl get secrets'",
    "bash -c \"bash -c 'kubectl get secrets'\"",
    "zsh -c 'kubectl get pods'",
    "dash -c 'echo hi'",
    "sudo bash -c 'kubectl get secrets'",
    "env bash -c 'kubectl get secrets'",
    "/bin/sh -c 'kubectl get secrets'",
    "kubectl get secrets > out.txt",
    "kubectl get secrets 2>/dev/null",
    "kubectl get secrets | base64 -d",
    "kubectl get secret db -o jsonpath='{.data}' | base64 -d",
    "kubectl get 'secrets'",
    'kubectl get "secret"',
    "kubectl get 'secret db'",
    "kubectl 'get' secrets",
    'kubectl "get" "secrets"',
    "k\\ubectl get secrets",
    "kubectl get secr\\ets",
    "kubectl get $SECRET",
    "kubectl get $(echo secrets)",
    "kubectl get `echo secrets`",
    "kubectl get ${R}",
    "kubectl $VERB secrets",
    "$KUBECTL get secrets",
    '"$KUBECTL" get secrets',
    "kubectl get \u0441ecrets",
    "kubectl get secr\u00e9ts",
    "kubectl g\u00e9t secrets",
    "kubectl get \u0131ecret",
    "kubectl get s\u0435crets",
    "kubectl\u00a0get secrets",
    "kubectl\u3000get secrets",
    "kubectl\tget\tsecrets",
    "kubectl  get   secrets",
    "kubectl get\n secrets",
    "kubectl\\\nget secrets",
    "kubectl get secrets #c",
    "# kubectl get secrets",
    "echo # kubectl get secrets",
    "kubectl get secrets \\",
    "kubectl get 'secrets",
    'kubectl get "secrets',
    "kubectl get secrets'",
    "echo 'it's",
    "kubectl get secret 'a b",
    "",
    " ",
    "\n",
    "kubectl",
    "oc",
    "kubectl ",
    "kubectl -n",
    "kubectl --",
    "kubectl -- get secrets",
    "kubectl -n x --",
    "kubectl -n x -- get secrets",
    "kubectl --context",
    "kubectl -x get secrets",
    "kubectl -nx get secrets",
    "kubectl -n=x get secrets",
    "kubectl --namespacex get secrets",
    "kubectl --server=https://x get secrets",
    "kubectl --token abc get secrets",
    "kubectl --as=u get secrets",
    "kubectl --as u --as-group g get secrets",
    "kubectl --cache-dir=/c get secrets",
    "kubectl --request-timeout=5s get secrets",
    "kubectl -o yaml get secrets",
    "kubectl -f x get secrets",
    "kubectl --filename=x get secrets",
    "kubectl --field-manager=m get secrets",
    "kubectl --profile=cpu --profile-output=/tmp/p get secrets",
    "kubectl --user=u --username=n --password=p get secrets",
    "kubectl --client-key k --client-certificate c get secrets",
    "kubectl --certificate-authority=c --cluster=x get secrets",
    "kubectl --chunk-size=0 get secrets",
    "kubectl --sort-by=.x get secrets",
    "kubectl --subresource=status get secrets",
    "kubectl --template=x get secrets",
    "kubectl --label-selector=a=b get secrets",
    "kubectl --selector a=b get secrets",
    "kubectl -l a=b get secrets",
    "kubectl --as-uid=1 get secrets",
    "kubectl --all-namespaces=true get secrets",
    "kubectl -A=1 get secrets",
    "kubectl -itq get secrets",
    "kubectl -it get secrets",
    "kubectl -i get secrets",
    "kubectl -z get secrets",
    "kubectl - get secrets",
    "kubectl --verbose get secrets",
    "kubectl get secrets --from-literal=a=b",
    "kubectl create secret generic x --from-literal=k=v -o yaml",
    "kubectl run x --image=y -- sh -c 'cat /etc/secrets/x'",
    "kubectl port-forward pod 8080",
    "kubectl config view",
    "kubectl config view --raw",
    "kubectl config get-contexts",
    "kubectl auth can-i get secrets",
    "kubectl top pods",
    "kubectl rollout status deploy/x",
    "kubectl version",
    "kubectl api-resources",
]

HEREDOC_COMMANDS = [
    "kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x\nEOF",
    "kubectl exec -i pod -- sh <<'EOF'\ncat /etc/secrets/x\nEOF",
    'kubectl exec -i pod -- sh <<"EOF"\ncat /etc/secrets/x\nEOF',
    "kubectl exec -i pod -- sh <<-EOF\n\techo $API_KEY\n\tEOF",
    "kubectl exec -i pod -- sh <<EOF\necho $API_KEY\nEOF",
    "kubectl exec -i pod -- sh <<EOF\necho hello\nEOF",
    "kubectl exec -i pod -- sh <<EOF\nprintenv\nEOF",
    "kubectl exec -i pod -- sh <<EOF\ncat < /run/secrets/x\nEOF",
    "kubectl exec -i pod -- sh <<EOF\nsh -c 'cat /etc/secrets/x'\nEOF",
    "kubectl exec -i pod -- sh <<EOF\necho $(cat /etc/secrets/x)\nEOF",
    "kubectl exec -i pod -- sh <<EOF\necho `cat /etc/secrets/x`\nEOF",
    "kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x > /tmp/y\nEOF",
    "kubectl exec -i pod -- sh <<EOF\necho /etc/secrets/x\nEOF",
    "kubectl exec -i pod -- sh <<EOF\ncp /tmp/a /etc/secrets/b\nEOF",
    "kubectl exec -i pod -- sh <<EOF\ncat -- /etc/secrets/x\nEOF",
    "kubectl exec -i pod -- sh <<EOF\ncat --f=/etc/secrets/x\nEOF",
    "kubectl exec -i pod -- sh <<EOF\ncat >/etc/secrets/x\nEOF",
    "kubectl exec -i pod -- sh <<EOF\ncat > /etc/secrets/x\nEOF",
    "kubectl exec -i pod -- sh <<EOF\nbash -c 'echo hi'\nEOF",
    "kubectl exec -i pod -- sh -s <<EOF\ncat /etc/secrets/x\nEOF",
    "kubectl exec -i pod -- sh - <<EOF\ncat /etc/secrets/x\nEOF",
    "kubectl exec -i pod -- sh -c <<EOF\ncat /etc/secrets/x\nEOF",
    "kubectl exec -i pod -- sh -x <<EOF\ncat /etc/secrets/x\nEOF",
    "kubectl exec -i pod -- sh script.sh <<EOF\ncat /etc/secrets/x\nEOF",
    "kubectl exec -i pod -- bash -- <<EOF\ncat /etc/secrets/x\nEOF",
    "kubectl exec -i pod -- python - <<EOF\nimport os\nprint(os.environ['API_KEY'])\nEOF",
    "kubectl exec -i pod -- python3 <<EOF\nimport os\nprint(os.environ['API_KEY'])\nEOF",
    "kubectl exec -i pod -- python - <<EOF\nprint(1)\nEOF",
    "kubectl exec -i pod -- python -c 'x' <<EOF\nos.environ\nEOF",
    "kubectl exec -i pod -- python -- - <<EOF\nos.environ\nEOF",
    "kubectl exec -i pod -- python -u - <<EOF\nos.environ\nEOF",
    "kubectl exec -i pod -- python x.py <<EOF\nos.environ\nEOF",
    "kubectl exec -i pod -- node - <<EOF\nconsole.log(process.env)\nEOF",
    "kubectl exec -i pod -- node -e 'x' <<EOF\nprocess.env\nEOF",
    'kubectl exec -i pod -- ruby - <<EOF\nputs ENV["TOKEN"]\nEOF',
    "kubectl exec -i pod -- cat <<EOF\n/etc/secrets/x\nEOF",
    "kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x\n",
    "kubectl exec -i pod -- sh <<EOF",
    "kubectl exec -i pod -- sh <<",
    "kubectl exec -i pod -- sh <<\n",
    "kubectl exec -i pod -- sh <<\nEOF\n",
    "kubectl exec -i pod -- sh <<'EOF\ncat /etc/secrets/x\nEOF",
    "kubectl exec -i pod -- sh <<'' \nx\n",
    "kubectl exec -i pod -- sh << EOF\ncat /etc/secrets/x\nEOF",
    "kubectl exec -i pod -- sh <<\tEOF\ncat /etc/secrets/x\nEOF",
    "kubectl exec -i pod -- sh <<EOF\r\ncat /etc/secrets/x\r\nEOF\r\n",
    "kubectl exec -i pod -- sh <<EOF  \ncat /etc/secrets/x\nEOF  \n",
    "kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x\n  EOF\n",
    "kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x\nEOFX\nEOF\n",
    "kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x\nXEOF\n",
    "kubectl exec -i pod -- sh <<' E'\ncat /etc/secrets/x\n E\n",
    "kubectl exec -i pod -- sh <<' E'\ncat /etc/secrets/x\n\t E\n",
    "kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x\nEOF\necho more",
    "kubectl exec -i pod -- sh <<EOF1\necho hi\nEOF1\nkubectl exec -i pod -- sh <<EOF2\ncat /etc/secrets/x\nEOF2",
    "echo a <<A\nx\nA\nkubectl exec -i pod -- sh <<B\necho $API_KEY\nB",
    "cat <<EOF | kubectl exec -i pod -- sh\ncat /etc/secrets/x\nEOF",
    "cat <<EOF | kubectl exec -i pod -- sh -s\necho $API_KEY\nEOF",
    "cat <<EOF | kubectl exec -i pod -- python -\nos.environ\nEOF",
    "cat <<EOF | kubectl exec -i pod -- sh | tee out\ncat /etc/secrets/x\nEOF",
    "cat <<EOF | tee x | kubectl exec -i pod -- sh\ncat /etc/secrets/x\nEOF",
    "cat <<EOF |kubectl exec -i pod -- sh\ncat /etc/secrets/x\nEOF",
    "cat <<EOF >out | kubectl exec -i pod -- sh\ncat /etc/secrets/x\nEOF",
    "cat <<EOF || kubectl exec -i pod -- sh\ncat /etc/secrets/x\nEOF",
    "cat <<EOF ; kubectl exec -i pod -- sh\ncat /etc/secrets/x\nEOF",
    "cat <<EOF | echo x\ncat /etc/secrets/x\nEOF",
    "cat <<EOF | | kubectl exec pod -- sh\ncat /etc/secrets/x\nEOF",
    "cat <<EOF |\ncat /etc/secrets/x\nEOF",
    "cat <<EOF| kubectl exec -i pod -- sh\ncat /etc/secrets/x\nEOF",
    "env kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x\nEOF",
    "env FOO=1 kubectl exec -i pod -- env bash <<EOF\ncat /etc/secrets/x\nEOF",
    "env -S 'kubectl exec -i pod -- sh' <<EOF\ncat /etc/secrets/x\nEOF",
    "env -S 'kubectl exec -i pod -- sh' x <<EOF\ncat /etc/secrets/x\nEOF",
    "env -i <<EOF\ncat /etc/secrets/x\nEOF",
    "env && kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x\nEOF",
    "sudo -u root kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x\nEOF",
    "sudo kubectl exec -i pod -- sudo sh <<EOF\ncat /etc/secrets/x\nEOF",
    "nice -n 5 kubectl exec -i pod -- nice sh <<EOF\ncat /etc/secrets/x\nEOF",
    "nohup kubectl exec -i pod -- nohup sh <<EOF\ncat /etc/secrets/x\nEOF",
    "time kubectl exec -i pod -- time -p sh <<EOF\ncat /etc/secrets/x\nEOF",
    "stdbuf -oL kubectl exec -i pod -- stdbuf -o L sh <<EOF\ncat /etc/secrets/x\nEOF",
    "command kubectl exec -i pod -- command sh <<EOF\ncat /etc/secrets/x\nEOF",
    "FOO=1 kubectl exec -i pod -- BAR=2 sh <<EOF\ncat /etc/secrets/x\nEOF",
    "oc rsh pod sh <<EOF\ncat /etc/secrets/x\nEOF",
    "oc rsh -c c pod sh <<EOF\ncat /etc/secrets/x\nEOF",
    "kubectl -n x exec -i pod -- sh <<EOF\ncat /etc/secrets/x\nEOF",
    "kubectl --context c exec -i pod -- sh <<EOF\ncat /etc/secrets/x\nEOF",
    "kubectl --kubeconfig=/k exec -i pod -c c -- sh <<EOF\ncat /etc/secrets/x\nEOF",
    "kubectl get pods <<EOF\ncat /etc/secrets/x\nEOF",
    "kubectl exec -i pod <<EOF\ncat /etc/secrets/x\nEOF",
    "kubectl exec -i pod -- <<EOF\ncat /etc/secrets/x\nEOF",
    "kubectl exec <<EOF\ncat /etc/secrets/x\nEOF",
    "kubectl <<EOF\ncat /etc/secrets/x\nEOF",
    "<<EOF\ncat /etc/secrets/x\nEOF",
    "echo hi <<<'cat /etc/secrets/x'",
    "kubectl exec -i pod -- sh <<<'cat /etc/secrets/x'",
    'kubectl exec -i pod -- sh <<< "echo $API_KEY"',
    "kubectl exec -i pod -- sh <<EOF <<<x\ncat /etc/secrets/x\nEOF",
    "kubectl exec -i pod -- sh <<EOF && echo done\ncat /etc/secrets/x\nEOF",
    "kubectl exec -i pod -- sh <<EOF | cat\ncat /etc/secrets/x\nEOF",
    "kubectl exec -i pod -- sh <<EOF > out\ncat /etc/secrets/x\nEOF",
    "kubectl exec -i pod -- sh <<EOF; echo done\ncat /etc/secrets/x\nEOF",
    "kubectl exec -i pod -- sh <<EOF & echo done\ncat /etc/secrets/x\nEOF",
    "kubectl exec -i pod -- sh <<EOF 2>&1\ncat /etc/secrets/x\nEOF",
    "echo x && kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x\nEOF",
    "echo x || kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x\nEOF",
    "echo x; kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x\nEOF",
    "echo x & kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x\nEOF",
    "echo x &>/dev/null; kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x\nEOF",
    "echo x >&2 & kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x\nEOF",
    "echo $(kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x\nEOF\n)",
    "echo $( kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x\nEOF\n); echo done",
    "(kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x\nEOF\n)",
    "echo $((1+2)) && kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x\nEOF",
    "echo '<<EOF' ; kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x\nEOF",
    'echo "<<EOF"; kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x\nEOF',
    "echo \\<<EOF; kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x\nEOF",
    "echo `x <<EOF\ncat /etc/secrets/x\nEOF\n`",
    "echo 'it'\"s\"; kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x\nEOF",
    'echo "a\'b"; kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x\nEOF',
    "echo 'a\"b'; kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x\nEOF",
    'echo "$(echo x)"; kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x\nEOF',
    "echo $(echo (x)); kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x\nEOF",
    "x=(1 2); kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x\nEOF",
    "kubectl exec -i pod -- sh <<EOF\n$(cat /etc/secrets/x)\nEOF",
    "kubectl exec -i pod -- sh <<'EOF'\n$(cat /etc/secrets/x)\nEOF",
    "kubectl exec -i pod -- sh <<EOF\n\\$(cat /etc/secrets/x)\nEOF",
    "kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x\nEOF\n\n",
    "kubectl exec -i pod -- sh <<\u00e9\ncat /etc/secrets/x\n\u00e9\n",
    "kubectl exec -i pod -- sh <<\u0661\ncat /etc/secrets/x\n\u0661\n",
    "\u00e9 kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x\nEOF",
    "kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/\u00e9\nEOF",
    "kubectl exec -i pod -- sh <<EOF\n\u3000cat /etc/secrets/x\nEOF",
    "kubectl exec -i pod -- sh <<EOF\ncat\u3000/etc/secrets/x\nEOF",
    "kubectl exec -i pod -- sh <<EOF\ncat '/etc/secrets/x'\nEOF",
    'kubectl exec -i pod -- sh <<EOF\ncat "/etc/secrets/x"\nEOF',
    "kubectl exec -i pod -- sh <<EOF\ncat 'unterminated\nEOF",
    "kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x; cat /tmp/y\nEOF",
    "kubectl exec -i pod -- sh <<EOF\necho hi\ncat /etc/secrets/x\nEOF",
    "kubectl exec -i pod -- sh <<EOF\n# cat /etc/secrets/x\nEOF",
    "kubectl exec -i pod -- sh <<EOF\nls /etc/secrets\nEOF",
    "kubectl exec -i pod -- sh <<EOF\ncd /etc/secrets && cat x\nEOF",
    "kubectl exec -i pod -- sh <<EOF\nbash <<'INNER'\ncat /etc/secrets/x\nINNER\nEOF",
    "kubectl apply -f - <<EOF\napiVersion: v1\nkind: Secret\nmetadata:\n  name: x\nstringData:\n  k: v\nEOF",
    "kubectl apply -f - <<'EOF'\napiVersion: v1\nkind: Secret\nEOF",
    "kubectl create -f - <<EOF\napiVersion: v1\nkind: Secret\nEOF",
    "cat <<EOF | kubectl apply -f -\napiVersion: v1\nkind: Secret\nEOF",
    "kubectl apply -f manifest.yaml",
    "kubectl delete -f - <<EOF\nkind: Secret\nEOF",
    "kubectl get secret x -o yaml <<EOF\nx\nEOF",
    "kubectl create secret generic x --from-file=k=/dev/stdin <<EOF\nv\nEOF",
    "kubectl exec pod -- sh -c 'cat <<EOF\n/etc/secrets/x\nEOF'",
    "kubectl exec pod -- sh -c 'cat /etc/secrets/x <<EOF\nx\nEOF'",
    "sh -c 'kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x\nEOF'",
    'bash -c "kubectl exec -i pod -- sh <<EOF\ncat /etc/secrets/x\nEOF"',
    "echo $(kubectl exec -i pod -- sh <<EOF\necho $API_KEY\nEOF\n)",
    "kubectl exec -i pod -- sh <<EOF\nkubectl exec -i pod -- sh <<INNER\necho $API_KEY\nINNER\nEOF",
]

TOKEN_LISTS = [
    [],
    [""],
    ["kubectl"],
    ["oc"],
    ["kubectl", ""],
    ["", "kubectl"],
    ["  ", "kubectl"],
    ["env"],
    ["env", "-i"],
    ["env", "-S", "kubectl get secrets"],
    ["env", "-S", "kubectl get secrets", "x"],
    ["env", "--"],
    ["env", "-u"],
    ["env", "FOO=1"],
    ["env", "FOO=1", "kubectl", "get", "secrets"],
    ["env", "&&", "kubectl", "get", "secrets"],
    ["env", "|", "x"],
    ["env", ";"],
    ["env", "&"],
    ["sudo", "-u"],
    ["sudo", "-u", "root", "env", "-i", "kubectl", "get", "secrets"],
    ["sudo", "--", "-u", "x"],
    ["sudo", "-"],
    ["sudo", "-u=root", "kubectl", "get", "secrets"],
    ["sudo", "--user=root", "-n", "env", "-S", "kubectl get secrets"],
    ["time", "-f", "%e", "kubectl", "get", "secrets"],
    ["time", "-f"],
    ["time", "--format=x", "oc", "get", "secrets"],
    ["nice", "-n", "5", "nice", "-n", "5", "kubectl", "get", "secrets"],
    ["nice", "-5", "kubectl", "get", "secrets"],
    ["stdbuf", "-i", "L", "-o", "L", "-e", "0", "kubectl", "get", "secrets"],
    ["stdbuf", "--error=0", "kubectl"],
    ["command", "-v", "kubectl"],
    ["command", "--", "kubectl", "get", "secrets"],
    ["command", "A=1", "kubectl"],
    ["nohup", "nohup", "nohup", "kubectl", "get", "secrets"],
    ["A=1", "B=2"],
    ["A=1", "kubectl"],
    ["=1", "kubectl"],
    ["1A=1", "kubectl"],
    ["A=", "kubectl", "get", "secrets"],
    ["A", "kubectl"],
    ["/usr/bin/env", "kubectl"],
    ["./sudo", "kubectl"],
    ["SUDO", "kubectl", "get", "secrets"],
    ["kubectl", "get", "secrets"],
    ["kubectl", "-n", "x", "get", "-n", "y", "secret"],
    ["kubectl", "get", "--raw"],
    ["kubectl", "get", "--raw", ""],
    ["kubectl", "get", "--raw=/api/v1/secrets"],
    ["kubectl", "get", "--raw", "/api/v1/secrets", "--raw", "/x"],
    ["kubectl", "get", "--raw=/api/v1/pods", "--raw=/api/v1/secrets"],
    ["kubectl", "exec", "pod", "--", "printenv", "|", "sort"],
    ["kubectl", "exec", "pod", "--", "env", "|"],
    ["kubectl", "exec", "pod", "--", "printenv", "-x", "TOKEN"],
    ["kubectl", "exec", "pod", "--", "printenv", "-x", "HOME"],
    ["kubectl", "exec", "pod", "--", "printenv", "HOME", "|", "grep", "TOKEN"],
    ["kubectl", "exec", "pod", "--", "printenv", "|", "TOKEN"],
    ["kubectl", "exec", "pod", "--", "env", "A=1", "|"],
    ["kubectl", "exec", "pod", "--", "env", "A=1"],
    ["kubectl", "exec", "pod", "--", "env", "-i", "A=1"],
    ["kubectl", "exec", "pod", "--", "env", "X"],
    ["kubectl", "exec", "pod", "--", "sh", "-c", "env"],
    ["kubectl", "exec", "pod", "--", "sh", "-c", "env | grep X"],
    ["kubectl", "exec", "pod", "--", "sh", "-c", ""],
    ["kubectl", "exec", "pod", "--", "sh", "-c"],
    ["kubectl", "exec", "pod", "--", "sh", "-xc", "cat /etc/secrets/x"],
    ["kubectl", "exec", "pod", "--", "sh", "-ce", "cat /etc/secrets/x"],
    ["kubectl", "exec", "pod", "--", "sh", "-c", "cat", "/etc/secrets/x"],
    ["kubectl", "exec", "pod", "--", "sh", "--", "-c", "cat /etc/secrets/x"],
    ["kubectl", "exec", "pod", "--", "sh", "<<EOF", "cat /etc/secrets/x", "EOF"],
    ["kubectl", "exec", "pod", "--", "sh", "<<EOF", "echo $API_KEY", "EOF"],
    ["kubectl", "exec", "pod", "--", "sh", "<<EOF", "EOF"],
    ["kubectl", "exec", "pod", "--", "sh", "<<EOF"],
    ["kubectl", "exec", "pod", "--", "bash", "<<EOF", "env", "EOF"],
    ["kubectl", "exec", "pod", "--", "bash", "<<EOF", "x y", "EOF"],
    ["kubectl", "exec", "pod", "--", "sh", "<<EOF", "'unterminated", "EOF"],
    ["kubectl", "exec", "pod", "--", "sh", "<<EOF", "   ", "EOF"],
    ["kubectl", "exec", "pod", "--", "python", "-", "<<EOF", "os.environ", "EOF"],
    ["kubectl", "exec", "pod", "--", "python", "-c", "x", "<<EOF"],
    ["kubectl", "exec", "pod", "--", "node", "-e", "process.env.TOKEN"],
    ["kubectl", "exec", "pod", "--", "php", "-r", "x"],
    ["kubectl", "exec", "pod", "--", "perl", "-eprint $ENV{X}"],
    ["kubectl", "exec", "pod", "--", "python3.11", "-cimport os; os.environ"],
    ["kubectl", "exec", "pod", "--", "pypy", "-c", "os.environ"],
    ["kubectl", "exec", "pod", "--", "cat", ">", "/etc/secrets/x"],
    ["kubectl", "exec", "pod", "--", "cat", ">/etc/secrets/x"],
    ["kubectl", "exec", "pod", "--", "cat", "2>", "/etc/secrets/x"],
    ["kubectl", "exec", "pod", "--", "cat", "<", "/etc/secrets/x"],
    ["kubectl", "exec", "pod", "--", "cat", "<", "/tmp/x", ">", "/etc/secrets/y"],
    ["kubectl", "exec", "pod", "--", "cat", "--file=/etc/secrets/x"],
    ["kubectl", "exec", "pod", "--", "cat", "--file="],
    ["kubectl", "exec", "pod", "--", "cat", "-"],
    ["kubectl", "exec", "pod", "--", "cat", "-x", "/etc/secrets/x"],
    ["kubectl", "exec", "pod", "--", "cp"],
    ["kubectl", "exec", "pod", "--", "cp", "/etc/secrets/x"],
    ["kubectl", "exec", "pod", "--", "cp", "/etc/secrets/x", "/etc/secrets/y"],
    ["kubectl", "exec", "pod", "--", "cp", "-t", "/etc/secrets", "x"],
    ["kubectl", "exec", "pod", "--", "cp", "--target-directory", "/etc/secrets", "x"],
    ["kubectl", "exec", "pod", "--", "cp", "-t"],
    ["kubectl", "exec", "pod", "--", "cp", "--target-directory=", "/etc/secrets/x"],
    ["kubectl", "exec", "pod", "--", "cp", "x", ">/etc/secrets/y"],
    ["kubectl", "exec", "pod", "--", "cp", "-r", "-t", "/tmp", "/etc/secrets/x", "/etc/secrets/y"],
    ["kubectl", "cp", "-n", "x", "-c", "y", "--retries", "1", "--no-preserve", "pod:/etc/secrets/x", "out"],
    ["kubectl", "cp", "--retries=1", "pod:/etc/secrets/x"],
    ["kubectl", "cp", "pod:/etc/secrets/x", "-"],
    ["kubectl", "cp", "-itq", "pod:/etc/secrets/x", "y"],
    ["kubectl", "cp", "-A", "pod:/etc/secrets/x", "y"],
    ["kubectl", "cp", "-z", "pod:/etc/secrets/x", "y"],
    ["kubectl", "cp", "--", "pod:/etc/secrets/x", "y"],
    ["kubectl", "cp", "pod:", "y"],
    ["kubectl", "cp", ":/etc/secrets/x", "y"],
    ["kubectl", "cp", "pod:/etc/secrets/x:y", "z"],
    ["kubectl", "cp", "file:///etc/secrets/x", "y"],
    ["kubectl", "cp", "PoD:/ETC/SECRETS/x", "y"],
    ["oc", "extract", "secret/x"],
    ["oc", "extract", "-n", "x", "secrets"],
    ["oc", "extract", "-n"],
    ["oc", "extract"],
    ["oc", "extract", "--to=-", "secret/x"],
    ["oc", "extract", "cm/x"],
    ["kubectl", "extract", "secret/x"],
    ["kubectl", "create", "token"],
    ["kubectl", "create", "-n", "x", "token", "sa"],
    ["kubectl", "create", "TOKEN", "sa"],
    ["kubectl", "create", "secret", "token"],
    ["kubectl", "create", "--", "token"],
    ["kubectl", "create", "-f", "token"],
    ["kubectl", "describe", "secret"],
    ["kubectl", "describe", "-n", "x", "secrets/x"],
    ["kubectl", "edit", "-n"],
    ["kubectl", "get", "-n", "x", "-o", "yaml", "secret"],
    ["kubectl", "get", "-f", "secret"],
    ["kubectl", "get", "--", "secret"],
    ["kubectl", "get", "-A", "-n", "x", "-lapp=x", "secrets"],
    ["kubectl", "get", "secrets", "--ignore-not-found"],
    ["kubectl", "GET", "SECRETS"],
    ["kubectl", "Describe", "Secret"],
    ["kubectl", "EXEC", "pod", "--", "cat", "/etc/secrets/x"],
    ["kubectl", "RSH", "pod", "cat", "/etc/secrets/x"],
    ["oc", "RSH", "pod", "printenv"],
    ["kubectl", "CP", "pod:/etc/secrets/x", "y"],
    ["kubectl", "-o"],
    ["kubectl", "-n", "x"],
    ["kubectl", "--"],
    ["kubectl", "--", "--"],
    ["kubectl", "-n", "--", "get", "secrets"],
]

for _command in HEREDOC_COMMANDS + KUBE_COMMANDS + GET_SAMPLES + SECRET_SCRIPTS:
    pass

PIPE_TEXTS = [
    "",
    " ",
    "a",
    "a | b",
    "a|b",
    "a || b",
    "a |& b",
    " a | b | c ",
    "'a|b' | c",
    '"a|b" | c',
    "a \\| b",
    "$(a | b) | c",
    "(a | b) | c",
    "`a | b` | c",
    "a | | b",
    "|",
    "||",
    "a |",
    "| a",
    "a | b && c | d",
    "a ; b | c",
    "a\n| b",
    "kubectl exec pod -- sh | tee",
    "sudo -u x kubectl exec pod -- env | sort",
    "a |\u00a0b",
]

AFTER_TEXTS = [
    "",
    "| kubectl exec -i pod -- sh",
    " | kubectl exec -i pod -- sh -s",
    "|",
    "| a | kubectl exec pod -- sh",
    "> out",
    "| echo x",
    "  \t| kubectl exec -i pod -- python -",
    "|| kubectl exec -i pod -- sh",
    "x | kubectl exec -i pod -- sh",
    "|kubectl exec -i pod -- python3 -",
    " | kubectl exec -i pod -- sh | cat",
]

BEFORE_TEXTS = [
    "",
    "kubectl exec -i pod -- sh",
    "cat x | kubectl exec -i pod -- sh",
    "kubectl exec -i pod -- sh | cat",
    "env kubectl exec -i pod -- bash",
    "echo hi",
    "kubectl exec -i pod -- python -",
    "kubectl exec -i pod -- node",
    "x | y | kubectl exec -i pod -- sh -s",
    "kubectl exec -i pod -- sh -c x",
    "kubectl exec -it pod -- ash -",
    "kubectl exec -i pod -- sh x",
    "kubectl exec -i pod -- ksh -s",
    "kubectl exec -i pod -- zsh -x -s",
    "kubectl exec -i pod -- bash --",
    "kubectl exec -i pod -- bash -- -s",
]

TAGS = ["EOF", "E", " E", "E ", "a.b", "a+b", "(x)", "[x]", "$x", "", "\u00e9", "EOF\t"]
WRAPPER_TOKENS = [
    "-n",
    "-n=5",
    "--adjustment",
    "--adjustment=5",
    "-u",
    "--user=root",
    "--user",
    "-x",
    "--",
    "-",
    "-i",
    "--input",
    "--output=x",
    "-f",
    "--format",
    "--format=x",
    "-C",
    "-h",
    "--host",
    "--host=x",
    "-E",
]
WRAPPER_NAMES = ["nice", "stdbuf", "sudo", "time", "command", "nohup", "env", "other", ""]
INTERPRETER_NAMES = COMMAND_NAMES


def _shlex(text: str) -> list[str] | None:
    try:
        return shlex.split(text)
    except ValueError:
        return None


def _tails(tokens: list[str]) -> list[list[str]]:
    seen: list[list[str]] = []
    for start in range(min(len(tokens) + 1, 5)):
        tail = tokens[start:]
        if tail not in seen:
            seen.append(tail)
    return seen


def _dedupe(items: list[list[str]]) -> list[list[str]]:
    seen: list[list[str]] = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return seen


def _enc(value: object) -> object:
    if isinstance(value, tuple):
        return [_enc(item) for item in value]
    if isinstance(value, list):
        return [_enc(item) for item in value]
    if isinstance(value, frozenset):
        return sorted(value)
    return value


class Recorder:
    def __init__(self) -> None:
        self.cases: list[dict[str, object]] = []

    def add(self, name: str, args: list[object], result: object) -> None:
        self.cases.append({"fn": name, "args": args, "result": _enc(result)})


def _variant_sets(name: str) -> dict[str, object]:
    base = {
        "base_value_flags": support.KUBECTL_OPTIONS_WITH_VALUES,
        "base_boolean_flags": support.KUBECTL_BOOLEAN_OPTIONS,
        "base_boolean_short_cluster": support.EXEC_BOOLEAN_SHORT_CLUSTER,
    }
    if name == "exec":
        base.update(
            value_flags=support.EXEC_OPTIONS_WITH_VALUES,
            boolean_flags=support.EXEC_BOOLEAN_OPTIONS,
            boolean_short_cluster=support.EXEC_BOOLEAN_SHORT_CLUSTER,
        )
    elif name == "cp":
        base.update(value_flags=kc._CP_OPTIONS_WITH_VALUES, boolean_flags=kc._CP_BOOLEAN_OPTIONS)
    elif name == "get":
        base["base_boolean_flags"] = support.KUBECTL_BOOLEAN_OPTIONS | kc._READ_ONLY_GET_BOOLEAN_OPTIONS
    return base


def _record_support(rec: Recorder, token_lists: list[list[str]]) -> None:
    for script in [*SECRET_SCRIPTS, "", "os.environ", "os.environ\n", "$A", "${A}", "$ A"]:
        rec.add("s_dumps_env", [script], support.script_dumps_process_environment(script))
        rec.add("s_reads_env", [script], support.script_reads_sensitive_env(script))
    for name in [
        "",
        "API_KEY",
        "api-key",
        "apikey",
        "KEY",
        "MY_KEY_X",
        "AUTH",
        "authz",
        "x_auth_y",
        "PASSWORD ",
        " TOKEN",
        "TOKENS",
        "TOKEN\n",
        "SECRET",
        "secret-x",
        "PRIVATE_KEY",
        "private-key",
        "privatekey",
        "CREDENTIALS",
        "credential",
        "HOME",
        "KEYBOARD",
        "monkey",
        "_key",
        "key_",
        "a_b_secret_c",
        "\u0130KEY",
        "API__KEY",
        "DB_PASSWORD",
    ]:
        rec.add("s_sensitive_name", [name], support.is_sensitive_env_name(name))
    for path in PATHS:
        rec.add("s_proc_environ", [path], support.is_proc_environ_path(path))
        rec.add("s_secret_volume", [path], support.is_secret_volume_path(path))
        rec.add("s_path_candidates", [path], support._path_candidates(path))
        rec.add("s_volume_arg", [path], support.secret_volume_argument_value(path))
        rec.add("s_strip_redirect", [path], support.strip_redirect_prefix(path))
    for token in [
        ">",
        ">>",
        "1>",
        "2>",
        "1>>",
        "2>>",
        "<",
        "0<",
        ">x",
        "<x",
        "0<x",
        "1>>x",
        "2>x",
        ">>x",
        "--a=b",
        "--a=>x",
        "-a=<x",
        "x",
        "",
    ]:
        rec.add("s_volume_arg", [token], support.secret_volume_argument_value(token))
        rec.add("s_strip_redirect", [token], support.strip_redirect_prefix(token))
        for previous in [None, ">", "2>>", "x", "<", ""]:
            rec.add(
                "s_redirect_target",
                [token, previous],
                support.is_output_redirect_target(token, previous_token=previous),
            )
    for path in RAW_PATHS:
        rec.add("s_raw_secret", [path], support.raw_secret_api_path(path))
    for value in REMOTE_CP:
        rec.add("s_remote_cp_path", [value], support.remote_cp_path(value))
    for token in RESOURCE_TOKENS:
        rec.add("s_resource_secret", [token], support.resource_token_includes_secret(token))
    for name in COMMAND_NAMES:
        rec.add("s_inline_interp", [name], support._is_inline_interpreter_command(name))
        for args in INLINE_ARGS:
            rec.add("s_interp_env", [name, args], support.interpreter_reads_sensitive_env(name, tuple(args)))
    for args in (
        INLINE_ARGS
        + [["-c", script] for script in SECRET_SCRIPTS]
        + [["-e", script] for script in SECRET_SCRIPTS[28:50]]
    ):
        rec.add("s_inline_script", [args], support._interpreter_inline_script(tuple(args)))
    for tokens in token_lists:
        rec.add("s_exec_remote", [tokens], support.exec_remote_tokens_after_resource(tuple(tokens)))
        rec.add("s_shell_script", [tokens], support.shell_command_script(tuple(tokens)))
        rec.add(
            "s_matching",
            ["proc", tokens],
            support.matching_source_arguments(tuple(tokens), support.is_proc_environ_path),
        )
        rec.add(
            "s_matching",
            ["volume", tokens],
            support.matching_source_arguments(tuple(tokens), support.is_secret_volume_path),
        )
        for index in range(len(tokens) + 2):
            rec.add(
                "s_skip_options",
                [tokens, index],
                support.skip_kubectl_options(
                    tuple(tokens),
                    index,
                    value_flags=support.KUBECTL_OPTIONS_WITH_VALUES,
                    boolean_flags=support.KUBECTL_BOOLEAN_OPTIONS,
                    boolean_short_cluster=support.EXEC_BOOLEAN_SHORT_CLUSTER,
                ),
            )
        for variant in ("kubectl", "exec", "cp", "get"):
            for index in range(len(tokens)):
                rec.add(
                    "s_option_consumed",
                    [variant, tokens, index],
                    support.kubernetes_option_tokens_consumed(tuple(tokens), index, **_variant_sets(variant)),
                )
    for variant in ("kubectl", "exec", "cp", "get"):
        for token in OPTION_TOKENS:
            for tokens in ([token], [token, "x"], ["x", token]):
                for index in range(len(tokens)):
                    rec.add(
                        "s_option_consumed",
                        [variant, tokens, index],
                        support.kubernetes_option_tokens_consumed(tuple(tokens), index, **_variant_sets(variant)),
                    )
    for tokens in ([t] for t in OPTION_TOKENS):
        for index in (0, 1):
            rec.add(
                "s_skip_options",
                [tokens, index],
                support.skip_kubectl_options(
                    tuple(tokens),
                    index,
                    value_flags=support.KUBECTL_OPTIONS_WITH_VALUES,
                    boolean_flags=support.KUBECTL_BOOLEAN_OPTIONS,
                    boolean_short_cluster=support.EXEC_BOOLEAN_SHORT_CLUSTER,
                ),
            )


def _record_heredoc(rec: Recorder, token_lists: list[list[str]]) -> None:
    texts = HEREDOC_COMMANDS + KUBE_COMMANDS[:60] + SECRET_SCRIPTS
    for command in texts:
        rec.add("h_secret_source", [command], hd.kubernetes_heredoc_secret_source(command))
        rec.add("h_iter", [command], hd._iter_kubernetes_heredocs(command))
        rec.add("h_shell_tokens", [command], hd._shell_tokens(command))
        rec.add("h_remote_kind_cmd", [command], hd._kubernetes_remote_kind_from_command(command))
        rec.add("h_body_volume", [command], hd._script_body_reads_secret_volume(command))
        rec.add("h_last_pipe", [command], hd._last_pipe_segment(command))
        rec.add("h_pipe_segments", [command], hd._pipe_segments(command))
    for command in HEREDOC_COMMANDS:
        for index in range(0, len(command) + 1):
            if command.startswith(("<<", "&", "|", " ", "\n"), index) or index in (0, len(command)):
                rec.add(
                    "h_background",
                    [command, index],
                    hd._is_background_separator(command, index) if index < len(command) else None,
                )
                rec.add("h_looks_heredoc", [command, index], hd._looks_like_heredoc_operator(command, index))
                rec.add("h_starts_sep", [command, index], hd._starts_command_separator(command, index))
                rec.add("h_skip_ws", [command, index], hd._skip_command_whitespace(command, index))
                rec.add("h_parse", [command, index], hd._parse_heredoc(command, index))
        for tag in ["EOF", "E", " E", "EOF1", "EOF2", "A", "B", "INNER", "\u00e9", "\u0661", ""]:
            for start in sorted({0, command.find("\n") + 1, max(command.rfind("\n"), 0)}):
                if tag:
                    rec.add(
                        "h_body_end",
                        [command, tag, start],
                        list(hd._heredoc_body_and_end(command, tag=tag, start=start)),
                    )
    for text in [
        "a&b",
        "a&&b",
        "&",
        "a&",
        "&a",
        ">&",
        "a>&b",
        "a&>b",
        "a|&b",
        "<&",
        "a<&b",
        "a &",
        "a & b",
        "a\u00e9&b",
        "x&",
    ]:
        for index in range(len(text)):
            rec.add("h_background", [text, index], hd._is_background_separator(text, index))
    for text in ["<<", "<<<", "a<<b", "a<<<b", "<", "<<-", "x<<<<y", "", "<<\u00e9"]:
        for index in range(len(text) + 1):
            rec.add("h_looks_heredoc", [text, index], hd._looks_like_heredoc_operator(text, index))
    for text in ["&&", "||", "&|", "|&", "a&&", "&&&", "&", "|", "", "x||y"]:
        for index in range(len(text) + 1):
            rec.add("h_starts_sep", [text, index], hd._starts_command_separator(text, index))
    for text in ["", " ", "  a", "\t\n a", "a", "\u3000x", "\u00a0 x", "\x1cx", "x  "]:
        for index in range(len(text) + 2):
            rec.add("h_skip_ws", [text, index], hd._skip_command_whitespace(text, index))
    parse_texts = [
        "<<EOF\n",
        "<<-EOF\n",
        "<< EOF\n",
        "<<\tEOF\n",
        "<<'EOF'\n",
        '<<"EOF"\n',
        "<<'EOF\n",
        "<<EOF",
        "<<",
        "<<-",
        "<< ",
        "<<'E F'\n",
        "<<E;F\n",
        "<<E`F\n",
        "<<E'F\n",
        "<<EOF\r\n",
        "<<EOF  \r\n",
        "<<EOF \n",
        "<<''\n",
        '<<""\n',
        "<<\u00e9\n",
        "<<-'EOF' \n",
        '<<-"E"x\n',
        "<<E>x\n",
        "<<E<x\n",
        "<<E|x\n",
        "<<E&x\n",
        "x <<E\nbody\nE\n",
        "<<\r\n",
        "<<E\r",
        "<<'E'\r\n",
    ]
    for text in parse_texts:
        for index in range(len(text) + 1):
            if text.startswith("<<", index) or index in (0, len(text)):
                rec.add("h_parse", [text, index], hd._parse_heredoc(text, index))
    for before in BEFORE_TEXTS:
        for after in AFTER_TEXTS:
            rec.add("h_remote_kind", [before, after], hd._kubernetes_heredoc_remote_kind(before, after))
    for text in PIPE_TEXTS:
        rec.add("h_last_pipe", [text], hd._last_pipe_segment(text))
        rec.add("h_pipe_segments", [text], hd._pipe_segments(text))
    for args in [
        *INLINE_ARGS,
        ["-s"],
        ["-"],
        ["-c", "x"],
        ["-xc", "x"],
        ["-x"],
        ["x"],
        ["--"],
        ["--", "-s"],
        ["--", "-"],
        ["--", "x"],
        ["-x", "-s"],
        ["-x", "-"],
        ["-x", "y"],
        ["-s", "-c"],
        ["-e", "x"],
        ["-ce"],
        ["-C"],
        ["--c"],
        ["--", "--"],
    ]:
        rec.add("h_interp_stdin", [args], hd._interpreter_reads_stdin(tuple(args)))
        rec.add("h_shell_stdin", [args], hd._shell_reads_stdin(tuple(args)))
    for body in SECRET_SCRIPTS + HEREDOC_COMMANDS:
        rec.add("h_body_volume", [body], hd._script_body_reads_secret_volume(body))
    for tokens in token_lists:
        rec.add("h_segment_volume", [tokens], hd._segment_reads_secret_volume(tuple(tokens)))
        rec.add("h_exec_remote", [tokens], hd._kubernetes_exec_remote_tokens(tuple(tokens)))
        rec.add("h_unwrap", [tokens], hd._unwrap_heredoc_remote_command(tuple(tokens)))
    for name in WRAPPER_NAMES:
        for token in WRAPPER_TOKENS:
            rec.add("h_wrapper_option", [name, token], hd._wrapper_option_tokens_consumed(name, token))
            rec.add("k_option_consumed", [name, token], kc._option_tokens_consumed(name, token))


def _record_commands(rec: Recorder, token_lists: list[list[str]]) -> None:
    commands = KUBE_COMMANDS + HEREDOC_COMMANDS + GET_SAMPLES + SECRET_SCRIPTS
    for command in commands:
        rec.add("k_secret_read_source", [command], kc.kubernetes_secret_read_source(command))
        rec.add("k_command_candidates", [command], kc._command_candidates(command))
        rec.add("k_shell_tokens", [command], kc._shell_tokens(command))
        rec.add("k_candidate_source", [command], kc._kubernetes_secret_read_source_for_candidate(command))
    for depth in (3, 4):
        for command in KUBE_COMMANDS[:40]:
            rec.add("k_command_candidates_depth", [command, depth], kc._command_candidates(command, depth=depth))
    rec.add("k_secret_read_source", [None], kc.kubernetes_secret_read_source(None))
    for command in GET_SAMPLES:
        tokens = _shlex(command)
        if tokens is None:
            continue
        for name in ("kubectl", "oc", "KUBECTL", "OC", "helm", "", "kubectl.exe"):
            rec.add("k_inventory_args", [name, tokens[1:]], kc.kubernetes_read_only_inventory_args(name, tokens[1:]))
        rec.add("k_get_resource_output", [tokens[2:]], kc._read_only_get_resource_and_output(tuple(tokens[2:])))
    for tokens in token_lists:
        rec.add("k_inventory_args", ["kubectl", tokens], kc.kubernetes_read_only_inventory_args("kubectl", tokens))
        rec.add("k_get_resource_output", [tokens], kc._read_only_get_resource_and_output(tuple(tokens)))
        rec.add("k_source_from_tokens", [tokens], kc._kubectl_secret_read_source_from_tokens(tuple(tokens)))
        rec.add("k_unwrap_start", [tokens], kc._unwrap_command_start(tuple(tokens)))
        rec.add("k_exec_secret_source", [tokens], kc._kubectl_exec_secret_source(tuple(tokens)))
        rec.add("k_exec_remote_tokens", [tokens], kc._kubectl_exec_remote_tokens(tuple(tokens)))
        for depth in (0, 2, 3, 4):
            rec.add("k_pod_env", [tokens, depth], kc._remote_command_reads_pod_environment(tuple(tokens), depth=depth))
            rec.add(
                "k_secret_volume", [tokens, depth], kc._remote_command_reads_secret_volume(tuple(tokens), depth=depth)
            )
        rec.add("k_cp_reads", [tokens], kc._kubectl_cp_reads_secret_volume(tuple(tokens)))
        rec.add("k_cp_operands", [tokens], kc._kubectl_cp_operands(tuple(tokens)))
        rec.add("k_remote_copy", [tokens], kc._remote_copy_source_reads_secret_volume(tuple(tokens)))
        rec.add("k_volume_source_args", [tokens], kc._secret_volume_source_arguments(tuple(tokens)))
        rec.add("k_remote_cp_operands", [tokens], kc._remote_cp_operands(tuple(tokens)))
        rec.add("k_shell_stdin_source", [tokens], kc._shell_stdin_secret_source(tuple(tokens)))
        for index in range(len(tokens) + 2):
            rec.add("k_resource_is_secret", [tokens, index], kc._kubectl_resource_is_secret(tuple(tokens), index))
            rec.add("k_get_raw_path", [tokens, index], kc._kubectl_get_raw_secret_path(tuple(tokens), index))
            rec.add("k_create_token", [tokens, index], kc._kubectl_create_token(tuple(tokens), index))
    for token in [*RESOURCE_TOKENS, "pods/x", "Pod.v1/x", "", "a/b/c", "a.b/c.d", "SVC.x"]:
        rec.add("k_inventory_resource_name", [token], kc._inventory_resource_name(token))


def build() -> list[dict[str, object]]:
    rec = Recorder()
    token_lists: list[list[str]] = [list(tokens) for tokens in TOKEN_LISTS]
    for command in KUBE_COMMANDS + GET_SAMPLES + SECRET_SCRIPTS + HEREDOC_COMMANDS[:60]:
        tokens = _shlex(command)
        if tokens:
            token_lists.extend(_tails(tokens))
    token_lists.extend(["sh", "-c", script] for script in SECRET_SCRIPTS)
    token_lists.extend(
        [name, "-c", script] for name in ("python", "node", "bash", "env", "printenv") for script in SECRET_SCRIPTS[:20]
    )
    token_lists.extend(
        [name, *shlex.split(script)]
        for name in ("cat", "cp", "tee", "ls", "echo")
        for script in SECRET_SCRIPTS[:8]
        if _shlex(script)
    )
    token_lists = _dedupe(token_lists)
    _record_support(rec, token_lists)
    _record_heredoc(rec, token_lists)
    _record_commands(rec, token_lists)
    return rec.cases


def main() -> None:
    fixture_dir = Path(sys.argv[1])
    cases = build()
    seen: set[str] = set()
    unique: list[dict[str, object]] = []
    for case in cases:
        key = json.dumps([case["fn"], case["args"]], sort_keys=True)
        if key not in seen:
            seen.add(key)
            unique.append(case)
    document = {"schema": "sfrs-kubernetes.v1", "cases": unique}
    out = fixture_dir / "kubernetes.json.gz"
    out.write_bytes(gzip.compress(json.dumps(document, sort_keys=True).encode("utf-8"), mtime=0))
    counts: dict[str, int] = {}
    for case in unique:
        counts[str(case["fn"])] = counts.get(str(case["fn"]), 0) + 1
    print(f"{len(unique)} cases -> {out}")
    print(json.dumps(counts, sort_keys=True))


if __name__ == "__main__":
    main()
