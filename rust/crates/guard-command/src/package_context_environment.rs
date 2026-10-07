//! Policy-relevant package environment selection; raw values never enter evidence.
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const GENERIC: &[&str] = &[
    "ALL_PROXY",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "all_proxy",
    "http_proxy",
    "https_proxy",
    "no_proxy",
];
const JS: &[&str] = &[
    "BUN_CONFIG_REGISTRY",
    "NODE_AUTH_TOKEN",
    "NPM_CONFIG_CAFILE",
    "NPM_CONFIG_HTTPS_PROXY",
    "NPM_CONFIG_PROXY",
    "NPM_CONFIG_REGISTRY",
    "NPM_CONFIG_STRICT_SSL",
    "NPM_CONFIG_USERCONFIG",
    "NPM_TOKEN",
    "YARN_ENABLE_NETWORK",
    "YARN_ENABLE_SCRIPTS",
    "YARN_HTTP_PROXY",
    "YARN_HTTPS_PROXY",
    "YARN_NPM_AUTH_TOKEN",
    "YARN_NPM_REGISTRY_SERVER",
    "YARN_RC_FILENAME",
];
const PYTHON: &[&str] = &[
    "PIP_CERT",
    "PIP_CLIENT_CERT",
    "PIP_CONFIG_FILE",
    "PIP_EXTRA_INDEX_URL",
    "PIP_FIND_LINKS",
    "PIP_INDEX_URL",
    "PIP_NO_INDEX",
    "PIP_TRUSTED_HOST",
    "UV_DEFAULT_INDEX",
    "UV_EXTRA_INDEX_URL",
    "UV_INDEX",
    "UV_INDEX_URL",
    "UV_NO_INDEX",
];
const GO: &[&str] = &["GONOPROXY", "GONOSUMDB", "GOPRIVATE", "GOPROXY", "GOSUMDB"];
const JVM: &[&str] = &["GRADLE_OPTS", "MAVEN_ARGS", "MAVEN_OPTS"];
const PHP: &[&str] = &["COMPOSER_AUTH", "COMPOSER_HOME", "COMPOSER_REPO_PACKAGIST"];

pub fn environment_policy_values(
    manager: &str,
    environment: &BTreeMap<String, String>,
    referenced_names: &[String],
) -> BTreeMap<String, Option<String>> {
    let family = match manager {
        "bun" | "bunx" | "npm" | "npx" | "pnpm" | "yarn" => JS,
        "pip" | "pip3" | "pipenv" | "pipx" | "poetry" | "uv" | "uvx" => PYTHON,
        "go" => GO,
        "gradle" | "gradlew" | "mvn" | "mvnw" => JVM,
        "composer" => PHP,
        _ => &[],
    };
    let mut names: BTreeSet<String> = GENERIC.iter().map(|name| (*name).to_owned()).collect();
    for name in family {
        names.insert((*name).to_owned());
        names.insert(name.to_ascii_lowercase());
    }
    names.extend(referenced_names.iter().cloned());
    names
        .into_iter()
        .map(|name| {
            let digest = environment
                .get(&name)
                .map(|value| hex::encode(Sha256::digest(value.as_bytes())));
            (name, digest)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manager_selection_and_configuration_references_are_independent() {
        let environment = BTreeMap::from([
            ("NPM_TOKEN".into(), "npm-secret".into()),
            ("pip_index_url".into(), "https://python.invalid".into()),
            ("PROJECT_TOKEN".into(), "project-secret".into()),
            ("UNRELATED_SECRET".into(), "ignored".into()),
        ]);
        let names = vec!["PROJECT_TOKEN".into(), "PROJECT_TOKEN".into()];
        let npm = environment_policy_values("npm", &environment, &names);
        assert!(npm["NPM_TOKEN"].is_some());
        assert!(!npm.contains_key("pip_index_url"));
        assert!(npm["PROJECT_TOKEN"].is_some());
        assert!(!npm.contains_key("UNRELATED_SECRET"));
        let pip = environment_policy_values("pip", &environment, &names);
        assert!(pip["pip_index_url"].is_some());
        assert!(!pip.contains_key("NPM_TOKEN"));
        assert_eq!(npm["PROJECT_TOKEN"], pip["PROJECT_TOKEN"]);
    }

    #[test]
    fn absent_empty_and_case_distinct_values_do_not_share_an_identity() {
        let mut environment = BTreeMap::from([("HTTP_PROXY".into(), String::new())]);
        let before = environment_policy_values("unknown", &environment, &[]);
        assert_eq!(before["http_proxy"], None);
        assert_eq!(
            before["HTTP_PROXY"].as_deref(),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        environment.insert("http_proxy".into(), "https://proxy.invalid".into());
        let after = environment_policy_values("unknown", &environment, &[]);
        assert_ne!(after["HTTP_PROXY"], after["http_proxy"]);
        assert_eq!(before["HTTP_PROXY"], after["HTTP_PROXY"]);
    }
}
