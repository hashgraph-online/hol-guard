"""Validated platform-managed policy loading and monotonic composition."""

from __future__ import annotations

import base64
import binascii
import importlib
import json
import os
import platform
import plistlib
import stat
import urllib.parse
from collections.abc import Mapping
from pathlib import Path
from typing import Literal, cast

from ..action_lattice import is_guard_action, most_restrictive_guard_action, normalize_guard_action
from .contracts import (
    MDM_POLICY_SCHEMA_VERSION,
    InstallOwner,
    ManagedIntegrityTrust,
    ManagedNetworkPolicy,
    ManagedPolicy,
    ManagedPolicyState,
    ManagedUpdatePolicy,
    ProxyMode,
    canonical_payload_hash,
    default_machine_paths,
)

_MAX_POLICY_BYTES = 1024 * 1024
_MODE_STRENGTH = {"observe": 0, "prompt": 1, "enforce": 2}
_TOP_LEVEL_KEYS = {
    "schemaVersion",
    "settings",
    "lockedSettings",
    "requiredHarnesses",
    "policyBundleKeyring",
    "network",
    "update",
    "daemonStartup",
    "integrityTrust",
}


class ManagedPolicyError(ValueError):
    """A managed policy failed strict validation."""


def _expect_mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ManagedPolicyError(f"{name} must be an object")
    return cast(Mapping[str, object], value)


def _optional_string(value: object, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ManagedPolicyError(f"{name} must be a non-empty string or null")
    return value


def _optional_https_url(value: object, name: str) -> str | None:
    url = _optional_string(value, name)
    if url is None:
        return None
    if url != url.strip() or any(character.isspace() for character in url):
        raise ManagedPolicyError(f"{name} must be an absolute HTTPS URL")
    try:
        parsed = urllib.parse.urlsplit(url)
        # Accessing port performs urllib's numeric/range validation.
        _ = parsed.port
    except ValueError as exc:
        raise ManagedPolicyError(f"{name} must be an absolute HTTPS URL") from exc
    if parsed.scheme.lower() != "https" or not parsed.netloc or parsed.hostname is None:
        raise ManagedPolicyError(f"{name} must be an absolute HTTPS URL")
    if parsed.username is not None or parsed.password is not None:
        raise ManagedPolicyError(f"{name} credentials are forbidden in managed policy")
    if "?" in url or "#" in url:
        raise ManagedPolicyError(f"{name} must not contain a query or fragment")
    return url


def _validate_settings(value: object) -> dict[str, object]:
    settings = dict(_expect_mapping(value, "settings"))
    try:
        json.dumps(settings, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ManagedPolicyError("settings must contain only JSON values") from exc
    return settings


def _parse_integrity_trust(value: object) -> ManagedIntegrityTrust:
    raw = _expect_mapping(value, "integrityTrust")
    unknown = set(raw) - {"releasePublicKeys", "macosTeamId", "windowsSignerThumbprints"}
    if unknown:
        raise ManagedPolicyError(f"unknown integrityTrust keys: {', '.join(sorted(unknown))}")
    keys_raw = _expect_mapping(raw.get("releasePublicKeys", {}), "integrityTrust.releasePublicKeys")
    release_keys: dict[str, bytes] = {}
    for key_id, encoded in keys_raw.items():
        if not key_id or not isinstance(encoded, str):
            raise ManagedPolicyError("release public keys must map non-empty ids to base64 strings")
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ManagedPolicyError("release public key is not valid base64") from exc
        if len(decoded) != 32:
            raise ManagedPolicyError("release public keys must be 32-byte Ed25519 keys")
        release_keys[key_id] = decoded
    thumbprints_raw = raw.get("windowsSignerThumbprints", [])
    if not isinstance(thumbprints_raw, list) or not all(isinstance(item, str) and item for item in thumbprints_raw):
        raise ManagedPolicyError("integrityTrust.windowsSignerThumbprints must be an array of strings")
    thumbprints_raw = cast(list[str], thumbprints_raw)
    thumbprints = tuple(sorted({item.replace(" ", "").upper() for item in thumbprints_raw}))
    if any(len(item) != 40 or any(character not in "0123456789ABCDEF" for character in item) for item in thumbprints):
        raise ManagedPolicyError("Windows signer thumbprints must be SHA-1 certificate thumbprints")
    return ManagedIntegrityTrust(
        release_public_keys=release_keys,
        macos_team_id=_optional_string(raw.get("macosTeamId"), "integrityTrust.macosTeamId"),
        windows_signer_thumbprints=thumbprints,
    )


def _validate_policy_bundle_keyring(value: object) -> dict[str, object]:
    trusted_keys = importlib.import_module("..policy_bundle_trusted_keys", __package__)
    try:
        keys = trusted_keys.load_policy_bundle_verification_keys(
            value,
            require_keyring_contract=True,
        )
    except ValueError as exc:
        raise ManagedPolicyError("policyBundleKeyring is invalid") from exc
    if not isinstance(value, dict):  # strict loader guarantees this; retained for type narrowing
        raise ManagedPolicyError("policyBundleKeyring is invalid")
    workspace_id = value.get("workspaceId")
    if not isinstance(workspace_id, str) or not workspace_id.strip():
        raise ManagedPolicyError("policyBundleKeyring is invalid")
    return trusted_keys.policy_bundle_keyring_payload(keys, workspace_id=workspace_id.strip())


def parse_managed_policy(payload: object) -> ManagedPolicy:
    """Parse a policy object using the stable v1 contract."""

    root = _expect_mapping(payload, "policy")
    unknown = set(root) - _TOP_LEVEL_KEYS
    if unknown:
        raise ManagedPolicyError(f"unknown policy keys: {', '.join(sorted(unknown))}")
    if root.get("schemaVersion") != MDM_POLICY_SCHEMA_VERSION:
        raise ManagedPolicyError("unsupported managed policy schema")

    settings = _validate_settings(root.get("settings", {}))
    policy_bundle_keyring = (
        _validate_policy_bundle_keyring(root["policyBundleKeyring"]) if "policyBundleKeyring" in root else None
    )
    locked_raw = root.get("lockedSettings", [])
    if not isinstance(locked_raw, list) or not all(isinstance(item, str) and item for item in locked_raw):
        raise ManagedPolicyError("lockedSettings must be an array of setting paths")
    locked = frozenset(cast(list[str], locked_raw))
    for setting_path in locked:
        if _get_path(settings, setting_path) is _MISSING:
            raise ManagedPolicyError(f"locked setting has no managed value: {setting_path}")

    harnesses_raw = root.get("requiredHarnesses", [])
    if not isinstance(harnesses_raw, list) or not all(isinstance(item, str) and item for item in harnesses_raw):
        raise ManagedPolicyError("requiredHarnesses must be an array of names")

    network_raw = _expect_mapping(root.get("network", {}), "network")
    proxy_mode = network_raw.get("proxyMode", "system")
    if proxy_mode not in {"system", "explicit", "none"}:
        raise ManagedPolicyError("network.proxyMode is invalid")
    proxy_mode = cast(ProxyMode, proxy_mode)
    proxy_url = _optional_string(network_raw.get("proxyUrl"), "network.proxyUrl")
    if proxy_mode == "explicit" and proxy_url is None:
        raise ManagedPolicyError("network.proxyUrl is required for explicit proxy mode")
    if proxy_url is not None:
        parsed_proxy = urllib.parse.urlsplit(proxy_url)
        if parsed_proxy.username is not None or parsed_proxy.password is not None:
            raise ManagedPolicyError("proxy credentials are forbidden in managed policy")
    allow_registries = network_raw.get("allowPublicRegistries", True)
    if not isinstance(allow_registries, bool):
        raise ManagedPolicyError("network.allowPublicRegistries must be boolean")
    network = ManagedNetworkPolicy(
        proxy_mode=proxy_mode,
        proxy_url=proxy_url,
        ca_bundle_path=_optional_string(network_raw.get("caBundlePath"), "network.caBundlePath"),
        allow_public_registries=allow_registries,
    )

    update_raw = _expect_mapping(root.get("update", {}), "update")
    owner = update_raw.get("owner", "user")
    if owner not in {"user", "mdm"}:
        raise ManagedPolicyError("update.owner is invalid")
    owner = cast(InstallOwner, owner)
    channel = update_raw.get("channel", "stable")
    if not isinstance(channel, str) or not channel:
        raise ManagedPolicyError("update.channel must be a non-empty string")
    allow_downgrade = update_raw.get("allowDowngrade", False)
    if not isinstance(allow_downgrade, bool):
        raise ManagedPolicyError("update.allowDowngrade must be boolean")
    update = ManagedUpdatePolicy(
        owner=owner,
        channel=channel,
        minimum_version=_optional_string(update_raw.get("minimumVersion"), "update.minimumVersion"),
        maximum_version=_optional_string(update_raw.get("maximumVersion"), "update.maximumVersion"),
        allow_downgrade=allow_downgrade,
        index_url=_optional_https_url(update_raw.get("indexUrl"), "update.indexUrl"),
    )
    daemon_startup = root.get("daemonStartup", "on-demand")
    if daemon_startup not in {"on-demand", "login"}:
        raise ManagedPolicyError("daemonStartup is invalid")
    daemon_startup = cast(Literal["on-demand", "login"], daemon_startup)
    integrity_trust = _parse_integrity_trust(root.get("integrityTrust", {}))

    canonical = dict(root)
    return ManagedPolicy(
        schema_version=MDM_POLICY_SCHEMA_VERSION,
        settings=settings,
        locked_settings=locked,
        policy_bundle_keyring=policy_bundle_keyring,
        required_harnesses=tuple(sorted(set(cast(list[str], harnesses_raw)))),
        network=network,
        update=update,
        integrity_trust=integrity_trust,
        daemon_startup=daemon_startup,
        content_hash=canonical_payload_hash(canonical),
    )


def _read_policy_file(path: Path) -> object:
    size = path.stat().st_size
    if size > _MAX_POLICY_BYTES:
        raise ManagedPolicyError("managed policy exceeds size limit")
    data = path.read_bytes()
    if path.suffix.lower() == ".plist":
        return plistlib.loads(data)
    return json.loads(data)


def _machine_policy_source_is_trusted(path: Path, system_name: str) -> bool:
    """Require the native Unix policy and its path to remain machine-owned."""

    if system_name == "Windows":
        # Windows policy authority is read from HKLM. ProgramData cache paths
        # are not authority until their owner and DACL can be verified through
        # native security APIs; POSIX mode bits are not meaningful there.
        return False
    if not path.is_absolute():
        return False
    current = path
    while True:
        try:
            metadata = current.lstat()
        except OSError:
            return False
        if stat.S_ISLNK(metadata.st_mode):
            return False
        if current == path:
            if not stat.S_ISREG(metadata.st_mode):
                return False
        elif not stat.S_ISDIR(metadata.st_mode):
            return False
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            return False
        if current.parent == current:
            return True
        current = current.parent


def _read_windows_policy() -> tuple[object | None, str]:
    try:
        import winreg
    except ImportError:
        return None, r"HKLM\Software\Policies\HOL\Guard"
    source = r"HKLM\Software\Policies\HOL\Guard"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"Software\Policies\HOL\Guard") as key:
            payload, value_type = winreg.QueryValueEx(key, "PolicyJson")
    except FileNotFoundError:
        return None, source
    if value_type not in {winreg.REG_SZ, winreg.REG_EXPAND_SZ} or not isinstance(payload, str):
        raise ManagedPolicyError("PolicyJson registry value must be a string")
    if len(payload.encode("utf-8")) > _MAX_POLICY_BYTES:
        raise ManagedPolicyError("managed policy exceeds size limit")
    return json.loads(payload), source


def _cache_path(system_name: str) -> Path:
    return default_machine_paths(system_name=system_name).state_root / "managed-policy-cache.json"


def _administrator_context(system_name: str) -> bool:
    if system_name != "Windows":
        return os.geteuid() == 0
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _write_policy_cache(payload: object, system_name: str) -> None:
    if not _administrator_context(system_name) or not isinstance(payload, dict):
        return
    path = _cache_path(system_name)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    temporary.replace(path)


def _cache_owner_is_trusted(path: Path, system_name: str) -> bool:
    if system_name == "Windows":
        return False
    metadata = path.stat()
    return metadata.st_uid == 0 and not metadata.st_mode & 0o022


def _load_policy_cache(system_name: str) -> ManagedPolicyState | None:
    path = _cache_path(system_name)
    if not os.path.lexists(path):
        return None
    if system_name == "Windows":
        # Never promote an unverifiable ProgramData file into policy-signing
        # authority. Its presence still records a fail-closed managed state.
        return ManagedPolicyState("tampered", str(path), reason_code="managed_policy_cache_tampered")
    if not _machine_policy_source_is_trusted(path, system_name):
        return ManagedPolicyState("tampered", str(path), reason_code="managed_policy_cache_tampered")
    try:
        metadata = path.stat()
        if metadata.st_size > _MAX_POLICY_BYTES:
            raise ManagedPolicyError("managed policy cache exceeds size limit")
        if not _cache_owner_is_trusted(path, system_name):
            return ManagedPolicyState("tampered", str(path), reason_code="managed_policy_cache_tampered")
        policy = parse_managed_policy(json.loads(path.read_bytes()))
        return ManagedPolicyState(
            "active", str(path), policy=policy, reason_code="managed_policy_profile_removed_cached"
        )
    except (OSError, json.JSONDecodeError, ManagedPolicyError) as exc:
        return ManagedPolicyState(
            "invalid", str(path), reason_code="managed_policy_cache_invalid", detail=str(exc)[:256]
        )


def load_managed_policy(
    *,
    policy_path: Path | None = None,
    system_name: str | None = None,
    write_cache: bool = True,
) -> ManagedPolicyState:
    """Load machine authority only from an explicit test path or native machine source."""

    resolved_system = system_name or platform.system()
    source = str(policy_path) if policy_path is not None else ""
    try:
        if policy_path is not None:
            if not policy_path.exists():
                return ManagedPolicyState("absent", source, reason_code="managed_policy_absent")
            payload = _read_policy_file(policy_path)
        elif resolved_system == "Windows":
            payload, source = _read_windows_policy()
            if payload is None:
                cached = _load_policy_cache(resolved_system)
                return cached or ManagedPolicyState("absent", source, reason_code="managed_policy_absent")
        else:
            native_path = default_machine_paths(system_name=resolved_system).policy_path
            if native_path is None:
                return ManagedPolicyState("absent", "native", reason_code="managed_policy_absent")
            source = str(native_path)
            if not os.path.lexists(native_path):
                cached = _load_policy_cache(resolved_system)
                return cached or ManagedPolicyState("absent", source, reason_code="managed_policy_absent")
            if not _machine_policy_source_is_trusted(native_path, resolved_system):
                return ManagedPolicyState(
                    "tampered",
                    source,
                    reason_code="managed_policy_source_tampered",
                )
            payload = _read_policy_file(native_path)
        policy = parse_managed_policy(payload)
        if policy_path is None and write_cache:
            _write_policy_cache(payload, resolved_system)
        return ManagedPolicyState("active", source, policy=policy)
    except PermissionError:
        return ManagedPolicyState("inaccessible", source, reason_code="managed_policy_inaccessible")
    except (ManagedPolicyError, json.JSONDecodeError, plistlib.InvalidFileException, OSError) as exc:
        return ManagedPolicyState("invalid", source, reason_code="managed_policy_invalid", detail=str(exc)[:256])


class _Missing:
    pass


_MISSING = _Missing()


def _get_path(payload: Mapping[str, object], path: str) -> object:
    current: object = payload
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return _MISSING
        current = current[part]
    return current


def _set_path(payload: dict[str, object], path: str, value: object) -> None:
    parts = path.split(".")
    current = payload
    for part in parts[:-1]:
        child = current.get(part)
        if not isinstance(child, dict):
            child = {}
            current[part] = child
        current = cast(dict[str, object], child)
    current[parts[-1]] = value


def _merge_strongest_actions(local: object, managed: object) -> object:
    if isinstance(managed, dict):
        merged = dict(local) if isinstance(local, dict) else {}
        for key, value in managed.items():
            merged[key] = _merge_strongest_actions(merged.get(key), value)
        return merged
    if local is None:
        return normalize_guard_action(managed, unknown_action="block")
    if managed is None:
        return normalize_guard_action(local, unknown_action="block")
    return most_restrictive_guard_action(local, managed, unknown_action="block")


def _strongest_security_value(local: object, managed: object) -> object:
    if isinstance(local, str) and isinstance(managed, str):
        if is_guard_action(local) or is_guard_action(managed):
            return most_restrictive_guard_action(local, managed, unknown_action="block")
        if local in _MODE_STRENGTH and managed in _MODE_STRENGTH:
            return max((local, managed), key=_MODE_STRENGTH.__getitem__)
    return managed


def _is_action_setting_path(path: str) -> bool:
    parts = tuple(path.split("."))
    return any(part == "actions" or part.endswith(("_actions", "Actions")) for part in parts) or parts[-1].endswith(
        ("_action", "Action")
    )


def _compose_managed_value(local: object, managed: object) -> object:
    if isinstance(local, dict) and isinstance(managed, dict):
        composed = dict(local)
        for key, managed_value in managed.items():
            composed[key] = _compose_managed_value(composed.get(key), managed_value)
        return composed
    return _strongest_security_value(local, managed)


def apply_managed_policy(local_payload: Mapping[str, object], policy: ManagedPolicy) -> dict[str, object]:
    """Compose local configuration without allowing a managed requirement to weaken."""

    composed = dict(local_payload)
    for key, managed_value in policy.settings.items():
        local_value = composed.get(key)
        if _is_action_setting_path(key):
            composed[key] = _merge_strongest_actions(local_value, managed_value)
        elif key in composed:
            composed[key] = _compose_managed_value(local_value, managed_value)
        else:
            composed[key] = managed_value
    for setting_path in policy.locked_settings:
        managed_value = _get_path(policy.settings, setting_path)
        if managed_value is not _MISSING:
            local_value = _get_path(composed, setting_path)
            strongest_value = (
                _merge_strongest_actions(local_value, managed_value)
                if _is_action_setting_path(setting_path)
                else _strongest_security_value(local_value, managed_value)
            )
            _set_path(composed, setting_path, strongest_value)
    return composed


def fail_closed_managed_policy() -> ManagedPolicy:
    """Return the non-weaker floor used when configured machine authority is unreadable."""

    settings: dict[str, object] = {
        "mode": "enforce",
        "security_level": "paranoid",
        "default_action": "block",
        "unknown_publisher_action": "block",
        "changed_hash_action": "block",
        "new_network_domain_action": "block",
        "subprocess_action": "block",
        "sync": False,
    }
    return ManagedPolicy(
        schema_version=MDM_POLICY_SCHEMA_VERSION,
        settings=settings,
        locked_settings=frozenset(settings),
        update=ManagedUpdatePolicy(owner="mdm", allow_downgrade=False),
        content_hash=canonical_payload_hash(
            {"schemaVersion": MDM_POLICY_SCHEMA_VERSION, "settings": settings, "failClosed": True}
        ),
    )


__all__ = [
    "ManagedPolicyError",
    "apply_managed_policy",
    "fail_closed_managed_policy",
    "load_managed_policy",
    "parse_managed_policy",
]
