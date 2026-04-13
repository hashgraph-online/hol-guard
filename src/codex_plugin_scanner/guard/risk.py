"""Risk heuristics for local Guard artifacts."""

from __future__ import annotations

from pathlib import PurePath

from .models import GuardArtifact


def artifact_risk_signals(artifact: GuardArtifact) -> tuple[str, ...]:
    signals: list[str] = []
    signals.extend(_metadata_signals(artifact))
    combined = " ".join(_artifact_terms(artifact)).lower()
    command_name = PurePath(artifact.command or "").name.lower()
    env_keys = _env_keys(artifact)

    if artifact.url is not None and artifact.url.startswith(("http://", "https://")):
        signals.append("connects to a remote server")

    if any(token in combined for token in ("http://", "https://", "curl ", "wget ", "fetch(", "axios.", "requests.")):
        signals.append("can send or receive network traffic")

    if env_keys:
        signals.append("receives environment variables that may contain secrets")

    if any(token in combined for token in (".env", "dotenv", "printenv", "process.env", "os.environ", "getenv(")):
        signals.append("can read local environment secrets")

    if any(token in combined for token in (".ssh", "id_rsa", "credentials", ".npmrc", ".pypirc", ".gitconfig")):
        signals.append("mentions sensitive local files")

    if command_name in {"bash", "sh", "zsh", "powershell", "cmd"} or _has_shell_wrapper(artifact):
        signals.append("runs through a shell wrapper")

    if _has_inline_code(artifact):
        signals.append("executes inline code at launch")

    return tuple(_dedupe(signals))


def artifact_risk_summary(artifact: GuardArtifact) -> str:
    metadata_summary = _metadata_summary(artifact)
    if metadata_summary is not None:
        return metadata_summary
    signals = artifact_risk_signals(artifact)
    if len(signals) == 0:
        return "No obvious secret-access or network signal was detected in the launch definition."
    if len(signals) == 1:
        return signals[0].capitalize() + "."
    return f"{signals[0].capitalize()}, and it also {signals[1]}."


def _artifact_terms(artifact: GuardArtifact) -> list[str]:
    parts = [artifact.name, artifact.command or "", artifact.url or "", *artifact.args]
    parts.extend(_env_keys(artifact))
    return [part for part in parts if part]


def _env_keys(artifact: GuardArtifact) -> list[str]:
    env_keys = artifact.metadata.get("env_keys")
    if not isinstance(env_keys, list):
        return []
    return [str(value) for value in env_keys if isinstance(value, str) and value]


def _metadata_signals(artifact: GuardArtifact) -> list[str]:
    signals: list[str] = []
    for key in ("runtime_request_signals", "prompt_signals"):
        value = artifact.metadata.get(key)
        if not isinstance(value, list):
            continue
        signals.extend(str(item) for item in value if isinstance(item, str) and item)
    return signals


def _metadata_summary(artifact: GuardArtifact) -> str | None:
    for key in ("runtime_request_summary", "prompt_summary"):
        value = artifact.metadata.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _has_shell_wrapper(artifact: GuardArtifact) -> bool:
    return any(value in {"-c", "-lc", "/c"} for value in artifact.args)


def _has_inline_code(artifact: GuardArtifact) -> bool:
    if artifact.command is None:
        return False
    command_name = PurePath(artifact.command).name.lower()
    if command_name in {"python", "python3", "node", "ruby", "perl"}:
        return any(value in {"-c", "-e"} for value in artifact.args)
    return False


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered
