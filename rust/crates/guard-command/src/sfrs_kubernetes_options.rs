//! Kubernetes option tables shared by the command walkers
//! (`runtime/kubernetes_command_support.py`).

#![allow(dead_code)]

pub(crate) const KUBECTL_OPTIONS_WITH_VALUES: &[&str] = &[
    "--as",
    "--as-group",
    "--as-uid",
    "--cache-dir",
    "--certificate-authority",
    "--chunk-size",
    "--client-certificate",
    "--client-key",
    "--cluster",
    "--context",
    "--field-manager",
    "--field-selector",
    "--filename",
    "--kubeconfig",
    "--label-selector",
    "--namespace",
    "--output",
    "--password",
    "--profile",
    "--profile-output",
    "--request-timeout",
    "--selector",
    "--server",
    "--sort-by",
    "--subresource",
    "--template",
    "--token",
    "--user",
    "--username",
    "-c",
    "-f",
    "-l",
    "-n",
    "-o",
];
pub(crate) const KUBECTL_BOOLEAN_OPTIONS: &[&str] = &["-A", "--all-namespaces"];
pub(crate) const EXEC_OPTIONS_WITH_VALUES: &[&str] = &[
    "--container",
    "--namespace",
    "--pod-running-timeout",
    "--profile",
    "--profile-output",
    "--request-timeout",
    "--shell",
    "-c",
    "-n",
];
pub(crate) const EXEC_BOOLEAN_OPTIONS: &[&str] =
    &["--quiet", "--stdin", "--tty", "-T", "-i", "-q", "-t"];
pub(crate) const EXEC_BOOLEAN_SHORT_CLUSTER: &[char] = &['i', 'q', 't'];
pub(crate) const SHELL_EXECUTABLES: &[&str] = &["ash", "bash", "dash", "ksh", "sh", "zsh"];
